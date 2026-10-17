"""One configurable compression session for Responses and Chat Completions."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import threading
import time
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Callable

from codexscope.compression_boundary import reference_text, task_from_body, transform_data
from codexscope.context_compression import chat_text_slots
from codexscope.deferred_tools import DeferredToolRegistry
from codexscope.input_compression import _text_slots, compress_prose, oversized_text
from codexscope.proxy_usage import default_token_counter
from codexscope.reference_selection import SourceStore, extract_source
from codexscope.structural_compression import StructuralCompressor, dumps, loads

from .backends import BackendUnavailable, make_backend, protected_rewrite, rewrite_material
from .history import shorten_tags, trim_history
from .methods import canonical_method


@dataclass(frozen=True)
class CompressionConfig:
    method: str = "structure"
    model: str = "gpt-4o"
    rate: float = 0.6
    model_path: str | None = None
    device: str = "cpu"
    reference_path: str | None = None
    spacy_model: str = "en_core_web_sm"
    mlm_model_path: str | None = None
    language: str = "en"
    stable_prefix: bool = False
    adaptive: bool = False
    history_max_tokens: int | None = None
    history_keep_turns: int = 2
    max_backend_calls: int = 4
    cache_entries: int = 128
    failure_backoff_s: float = 300

    def __post_init__(self):
        object.__setattr__(self, "method", canonical_method(self.method))
        if not 0 < self.rate < 1:
            raise ValueError("rate must be between zero and one")
        for name in ("history_keep_turns", "max_backend_calls", "cache_entries"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.history_max_tokens is not None and (type(self.history_max_tokens) is not int or self.history_max_tokens < 1):
            raise ValueError("history_max_tokens must be a positive integer")
        if self.method == "off" and (self.history_max_tokens or self.stable_prefix):
            raise ValueError("off is an unchanged baseline; remove history/prefix options")
        if type(self.failure_backoff_s) not in (float, int) or not math.isfinite(self.failure_backoff_s) or self.failure_backoff_s < 0:
            raise ValueError("failure_backoff_s must be finite and nonnegative")


@dataclass
class CompressionResult:
    body: dict
    method: str
    status: str
    tokens_before: int
    tokens_after: int
    tokenizer: str
    elapsed_ms: float
    stages: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    lossy: bool = False
    prefix_messages_reused: int = 0
    cache_hits: int = 0
    backend_attempts: int = 0
    changed_fields: int = 0
    changed_roles: list[str] = field(default_factory=list)

    @property
    def tokens_saved(self):
        return self.tokens_before - self.tokens_after

    def to_dict(self):
        return {**asdict(self), "body": json.loads(dumps(self.body)), "tokens_saved": self.tokens_saved,
                "savings_percent": round(100 * self.tokens_saved / self.tokens_before, 3) if self.tokens_before else 0,
                "measurement": "local serialized-request token estimate; not provider usage or cost"}


class TokenCompressor:
    """Use one instance per session/tenant. Sources remain until the host disposes it.

    ``backend`` optionally injects a selector, rewriter, or Headroom ContentRouter.
    It is useful for alternative clients and deterministic contract tests.
    """
    def __init__(self, config: CompressionConfig | None = None, *, source_store: SourceStore | None = None,
                 token_counter: Callable[[str], int] | None = None, backend=None):
        self.config = config or CompressionConfig()
        self.sources = source_store if source_store is not None else SourceStore()
        self.count, self.tokenizer = ((token_counter, "custom") if token_counter else default_token_counter(self.config.model))
        self._backend = backend
        self._injected = backend is not None
        self._lock = threading.RLock()
        self._cache = OrderedDict()
        self._failures = OrderedDict()
        self._prefix = None
        self._feedback = {}
        self._source_tools = {}
        self._read = set()

    def read_source(self, source_id, start_line=1, end_line=None):
        with self._lock:
            result = self.sources.read(source_id, start_line, end_line)
            if source_id in self._source_tools and source_id not in self._read:
                self._read.add(source_id)
                self._feedback[self._source_tools[source_id]]["rereads"] += 1
            return result

    def feedback(self):
        with self._lock:
            return copy.deepcopy(self._feedback)

    def reset_prefix(self):
        with self._lock:
            self._prefix = None

    def prepare_tools(self, definitions, *, resident=(), supports_tool_search=False):
        """Explicit host capability gate; original schemas are returned when unsupported."""
        registry = DeferredToolRegistry(definitions)
        if len(set(resident)) != len(resident) or any(n not in {t["name"] for t in definitions} for n in resident):
            raise ValueError("resident tools must be unique known names")
        if not supports_tool_search:
            return copy.deepcopy(definitions), registry
        selected = [copy.deepcopy(t) for t in definitions if t["name"] in resident]
        deferred = [t for t in definitions if t["name"] not in resident]
        registry = DeferredToolRegistry(deferred)
        return (registry.responses_tools(selected) if deferred else selected), registry

    def compress_text(self, text: str, *, task: str = "") -> CompressionResult:
        return self.compress_request({"model": self.config.model, "input": task + "\n" + reference_text(text)})

    def compress_bytes(self, raw: bytes) -> tuple[bytes, CompressionResult | None]:
        """Byte-preserving fail-open transport adapter for invalid/unsupported JSON."""
        if not raw:
            return raw, None
        try:
            body = loads(raw)
            if not isinstance(body, dict) or oversized_text(raw, body):
                return raw, None
            result = self.compress_request(body)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            return raw, None
        return (dumps(result.body).encode() if result.body != body else raw), result

    def compress_request(self, body: dict) -> CompressionResult:
        if not isinstance(body, dict):
            raise TypeError("request must be a dict")
        with self._lock:
            return self._compress(body)

    def _compress(self, original):
        started = time.monotonic()
        body = copy.deepcopy(original)
        before = self.count(dumps(body))
        result = CompressionResult(body, self.config.method, "unchanged", before, before, self.tokenizer, 0)
        def finish():
            result.tokens_after = self.count(dumps(result.body))
            result.status = "compressed" if result.body != original else "unchanged"
            result.elapsed_ms = round((time.monotonic() - started) * 1000, 3)
            result.issues = list(dict.fromkeys(result.issues))
            result.source_ids = list(dict.fromkeys(result.source_ids))
            return result
        if self.config.method == "off":
            return finish()
        if any(body.get(k) is not None for k in ("previous_response_id", "conversation", "prompt")):
            result.issues.append("server_managed_context")
            return finish()
        if oversized_text(dumps(body).encode(), body):
            result.issues.append("body_size")
            return finish()
        key = "messages" if "messages" in body else "input"
        items = body.get(key)
        if not isinstance(items, (str, list)) or isinstance(items, list) and any(not isinstance(x, dict) for x in items):
            result.issues.append("unsupported_input")
            return finish()
        stable = dumps({k: v for k, v in body.items() if k != key})
        reused = 0
        if self.config.stable_prefix and isinstance(items, list) and self._prefix:
            old_stable, old_raw, old_sent = self._prefix
            if stable == old_stable and items[:len(old_raw)] == old_raw and len(items) >= len(old_raw):
                reused = len(old_raw)
                body[key][:reused] = copy.deepcopy(old_sent)
                result.prefix_messages_reused = reused
        # Only new messages enter compressors. Existing forwarded bytes remain stable.
        work = {**body, key: body[key][reused:]} if reused else body
        slots = list(chat_text_slots(work) if key == "messages" else _text_slots(work))
        task = task_from_body(original)
        codec = StructuralCompressor(self.count)
        families, names = {}, {}
        for item in items if isinstance(items, list) else []:
            if item.get("type") in {"function_call", "custom_tool_call"}:
                call_id = item.get("call_id")
                names[call_id] = item.get("name", "tool")
                families[call_id] = dumps([names[call_id], item.get("arguments", item.get("input"))])
            for call in item.get("tool_calls", []) if isinstance(item.get("tool_calls"), list) else []:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function", {})
                names[call.get("id")] = fn.get("name", "tool")
                families[call.get("id")] = dumps(fn)
        all_slots = chat_text_slots(original) if key == "messages" else _text_slots(original)
        ids = Counter(c.get("call_id", c.get("tool_call_id")) for c, _, role in all_slots if role == "tool_output")
        backend_attempts = 0
        for container, field_name, role in slots:
            text = container[field_name]
            call_id = container.get("call_id", container.get("tool_call_id"))
            if not isinstance(call_id, str) or ids[call_id] != 1:
                call_id = None
            tool = names.get(call_id, "reference" if role == "user" else "tool")
            field_sources, field_lossy = [], False

            def transform(source):
                nonlocal backend_attempts, field_lossy
                method = self.config.method
                structured = codec.compress(source, call_id=call_id, family=families.get(call_id, ""))
                if method == "structure":
                    return structured
                if source.lstrip().startswith(("{", "[")):
                    try:
                        parsed = loads(source)
                        if isinstance(parsed, dict) and "$lingmou" in parsed:
                            return structured
                    except (ValueError, RecursionError):
                        return structured
                if method != "headroom" and (source.lstrip().startswith(("{", "[")) or "$lingmou" in structured):
                    return structured
                feedback = self._feedback.get(tool, {"compressions": 0, "rereads": 0})
                if (self.config.adaptive or method == "auto") and feedback["compressions"] >= 5 and feedback["rereads"] / feedback["compressions"] > 0.5:
                    result.issues.append("reread_feedback_structure_only")
                    return structured
                cache_key = hashlib.sha256(dumps([method, task, source]).encode()).hexdigest()
                if self._failures.get(cache_key, 0) > time.monotonic():
                    result.issues.append("backend_backoff")
                    result.cache_hits += 1
                    return structured
                if cache_key in self._cache:
                    selected, source_id = self._cache[cache_key]
                    try:
                        self.sources.get(source_id)
                    except (ValueError, OSError):
                        result.issues.append("source_unavailable")
                        return structured
                    self._cache.move_to_end(cache_key)
                    result.cache_hits += 1
                    field_lossy = True
                    field_sources.append(source_id)
                    return selected
                if backend_attempts >= self.config.max_backend_calls or len(source) > 100_000:
                    result.issues.append("backend_budget_or_size_limit")
                    return structured
                try:
                    # Recoverability checked before any paid/model work.
                    source_id = self.sources.put(source)
                    if not self._injected and method == "jev" and not os.environ.get("TYPESAFE_API_KEY"):
                        raise BackendUnavailable("TYPESAFE_API_KEY is not configured")
                    if not self._injected and method in {"kimi", "llm_rewrite", "caveman_llm"} and not any(os.environ.get(k) for k in ("KIMI_API_KEY", "MOONSHOT_API_KEY", "KIMI_API_KEY_FILE")):
                        raise BackendUnavailable("Kimi credentials are not configured")
                    if self._backend is None:
                        self._backend = make_backend(self.config)
                    backend_attempts += 1
                    if method in {"extract", "auto", "jev", "kimi"}:
                        selected, calls = extract_source(source, task, self._backend, self.sources)
                        result.calls.extend(calls)
                        if any(c.get("status") != "completed" for c in calls):
                            result.issues.append("backend_failed")
                            self._remember_failure(cache_key)
                    else:
                        if method == "caveman":
                            candidate = protected_rewrite(source, compress_prose)
                        elif method == "generic_agent":
                            candidate = shorten_tags(source)
                        else:
                            try:
                                candidate = rewrite_material(method, self._backend, source, task)
                            finally:
                                records = getattr(self._backend, "records", None)
                                if isinstance(records, list):
                                    result.calls.extend(records)
                                    records.clear()
                        if not isinstance(candidate, str) or not candidate.strip() or candidate == source:
                            return structured
                        selected = dumps({"$lingmou": "lossy/v1", "source_id": source_id,
                            "read_more": "lingmou_source_read(source_id,start_line,end_line)", "text": candidate})
                    if selected != source and len(selected) < len(structured) and self.count(selected) < self.count(structured):
                        self._cache[cache_key] = (selected, source_id)
                        while len(self._cache) > self.config.cache_entries or sum(len(v[0]) for v in self._cache.values()) > 2_000_000:
                            self._cache.popitem(last=False)
                        field_sources.append(source_id)
                        field_lossy = True
                        self._source_tools[source_id] = tool
                        stats = self._feedback.setdefault(tool, {"compressions": 0, "rereads": 0})
                        stats["compressions"] += 1
                        return selected
                except Exception as exc:
                    # Exception strings from external adapters may include source text/secrets.
                    result.issues.append("backend_unavailable" if isinstance(exc, (BackendUnavailable, ImportError)) else "backend_failed")
                    self._remember_failure(cache_key)
                return structured

            candidate = transform_data(text, role, transform)
            if candidate != text and self.count(candidate) < self.count(text):
                container[field_name] = candidate
                result.changed_fields += 1
                if role not in result.changed_roles:
                    result.changed_roles.append(role)
                result.lossy |= field_lossy
                result.source_ids.extend(field_sources)
                if field_lossy and call_id:
                    # A later delta must not depend on evidence removed by a selector.
                    codec.bases.pop(call_id, None)
                    codec.latest = {k: v for k, v in codec.latest.items() if v != call_id}
                    codec.duplicates = {k: v for k, v in codec.duplicates.items() if v != call_id}
        if reused:
            body[key] = body[key][:reused] + work[key]
        material_after = self.count(dumps(body))
        result.stages.append({"name": "material", "tokens_before": before, "tokens_after": material_after})
        if self.config.history_max_tokens:
            try:
                body, archive = trim_history(body, original_body=original, budget=self.config.history_max_tokens,
                    keep_turns=self.config.history_keep_turns, count=self.count, store=self.sources)
                if archive:
                    result.lossy = True
                    result.source_ids.append(archive["source_id"])
                    result.stages.append({"name": "history", "tokens_before": material_after,
                                          "tokens_after": self.count(dumps(body)), **archive})
            except (ValueError, OSError):
                result.issues.append("history_source_unavailable")
        if self.count(dumps(body)) > before:
            body = copy.deepcopy(original)
            result.lossy, result.source_ids = False, []
            result.changed_fields, result.changed_roles = 0, []
            result.issues.append("no_full_request_savings")
        result.body = body
        result.backend_attempts = backend_attempts
        if self.config.stable_prefix and isinstance(items, list) and len(body.get(key, [])) == len(items):
            self._prefix = (stable, copy.deepcopy(original[key]), copy.deepcopy(body[key]))
        else:
            self._prefix = None
        return finish()

    def _remember_failure(self, key):
        self._failures[key] = time.monotonic() + self.config.failure_backoff_s
        self._failures.move_to_end(key)
        while len(self._failures) > self.config.cache_entries:
            self._failures.popitem(last=False)
