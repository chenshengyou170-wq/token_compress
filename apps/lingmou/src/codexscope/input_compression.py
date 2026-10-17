"""Opt-in, local Caveman-style prose compression at the Responses boundary.

This is a rule-based adaptation, not the upstream spaCy/LLM implementation.
It never summarizes or truncates history, and never calls a model. Structured
protocol data and recognized code/literals are excluded. Rewriting prose is
still lossy; tokenizer checks establish size, not semantic equivalence.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterator

from .proxy_usage import TokenCounter, default_token_counter
from .compression_boundary import transform_data


_MAX_BODY_BYTES = 8 * 1024 * 1024
_MAX_TEXT_CHARS = 256_000
_INLINE = re.compile(
    r"`+"
    r'|"(?:\\.|[^"\\])*"'
    r"|(?<!\w)'(?:\\.|[^'\\\n])*'(?!\w)"
    r"|\[[^\]\n]*\]\([^\)\n]*\)"
    r"|https?://[^\s<>]+"
    r"|(?<!\w)(?:\.{0,2}/|~/|[A-Za-z]:\\)[^\s<>]+"
    r"|<[^>\n]+>",
)
_CODE_LINE = re.compile(
    r"^(?:[ \t]{4}|\t|\s*\||\s*[$>] |\s*```|\s*~~~)"
    r"|^\s*(?:def|class|import|from|return|const|let|var|function|if|else|elif|for|while)\b"
    r"|^\s*(?:sudo|curl|wget|echo|printf|cat|sed|awk|rm|cp|mv|git|rg|find|python3?|node|npm|bash|sh)\s"
    r"|^\s*[\w.]+\s*=(?!=)"
    r"|^\s*\d{4}-\d\d-\d\d[T ]"
)
# Only lowercase articles before ordinary lowercase words. A/The in names,
# quoted literals, and common references to a variable named 'a' stay intact.
_ARTICLES = re.compile(
    r"\b(?:the|an|a) +(?!(?:is|are|was|were|to|and|or|denotes|means|equals|becomes)\b)"
    r"(?=[a-z]{2,}\b)"
)
_COPULA = re.compile(r"(?<!\b[A-Za-z] )\b(?:is|are) +(?!not\b|no\b|never\b|only\b)")
_PHRASES = (
    (re.compile(r"\bin order to\b", re.I), "to"),
    (re.compile(r"\bdue to the fact that\b", re.I), "because"),
    (re.compile(r"\bin the event that\b", re.I), "if"),
    (re.compile(r"\bat this point in time\b", re.I), "now"),
    (re.compile(r"\bfor the purpose of\b", re.I), "for"),
    (re.compile(r"\bwith the exception of\b", re.I), "except"),
    (re.compile(r"(?<!\w)(?:Please|please|Kindly|kindly) +"), ""),
    (re.compile(r"进行(?:一下)?(?=检查|核对|分析|验证|比较|测试)"), ""),
    (re.compile(r"(?:请你|麻烦你|烦请)(?=[\u3400-\u9fff])"), ""),
)


def _prose(text: str) -> str:
    for pattern, replacement in _PHRASES:
        text = pattern.sub(replacement, text)
    return _COPULA.sub("", _ARTICLES.sub("", text))


def compress_prose(text: str) -> str:
    """Shorten ordinary prose; copy fenced/indented code and literals exactly."""
    if not text or len(text) > _MAX_TEXT_CHARS:
        return text
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        pass
    else:
        return text  # Tool JSON is data, not natural-language prose.
    result: list[str] = []
    fence: tuple[str, int] | None = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence is not None:
            result.append(line)
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= fence[1]:
                fence = None
            continue
        if marker:
            fence = (marker[1][0], len(marker[1]))
            result.append(line)
            continue
        if _CODE_LINE.search(line):
            result.append(line)
            continue
        offset = 0
        while (match := _INLINE.search(line, offset)) is not None:
            result.append(_prose(line[offset:match.start()]))
            end = match.end()
            if match[0].startswith('`'):
                # A direct search avoids regex backtracking on long/unclosed
                # backtick runs supplied in untrusted tool output.
                closing = line.find(match[0], end)
                end = len(line) if closing < 0 else closing + len(match[0])
            result.append(line[match.start():end])
            offset = end
        result.append(_prose(line[offset:]))
    return "".join(result)


def _text_slots(body: dict) -> Iterator[tuple[dict, str, str]]:
    """Explicit Responses allowlist: never recurse through arbitrary values."""
    if isinstance(body.get("instructions"), str):
        yield body, "instructions", "instructions"
    inputs = body.get("input")
    if isinstance(inputs, str):
        yield body, "input", "user"
        return
    if not isinstance(inputs, list):
        return
    for item in inputs:
        if not isinstance(item, dict):
            continue
        # Reasoning, tool calls, additional_tools, item references, images and
        # unknown future item types are copied without inspecting their values.
        if item.get("type") in {"function_call_output", "custom_tool_call_output"}:
            if isinstance(item.get("output"), str):
                yield item, "output", "tool_output"
            elif isinstance(item.get('output'), list):
                for part in item['output']:
                    if isinstance(part, dict) and part.get('type') in {'input_text', 'text'} and isinstance(part.get('text'), str):
                        yield part, 'text', 'tool_output'
            continue
        if item.get("type", "message") != "message":
            continue
        role = item.get("role")
        if role not in {"system", "developer", "user", "assistant"}:
            continue
        content = item.get("content")
        if isinstance(content, str):
            yield item, "content", role
        elif isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") in {"input_text", "output_text"}
                    and isinstance(part.get("text"), str)
                ):
                    yield part, "text", role


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


@dataclass(frozen=True)
class CompressionObservation:
    status: str
    reason: str
    text_tokens_before_estimate: int = 0
    text_tokens_after_estimate: int = 0
    changed_fields: int = 0
    changed_roles: tuple[str, ...] = ()
    tokenizer_source: str = "not_counted"
    latency_ms: float = 0.0
    compression_model_calls: int = 0
    cache_hits: int = 0
    rejected_fields: int = 0
    full_request_tokens_before_estimate: int = 0
    full_request_tokens_after_estimate: int = 0
    compression_calls: tuple[dict, ...] = ()
    local_model_calls: int = 0
    lossy_fields: int = 0
    method_observations: tuple[dict, ...] = ()


class ResponsesInputCompressor:
    """Thread-safe numeric telemetry; request text is never cached or logged."""

    def __init__(
        self,
        *,
        token_counter: TokenCounter | None = None,
        on_observation: Callable[[CompressionObservation], None] | None = None,
    ) -> None:
        self.token_counter = token_counter
        self.on_observation = on_observation
        self._lock = threading.Lock()
        self._stats = {
            "mode": "caveman", "requests": 0, "compressed_requests": 0,
            "skipped_requests": 0, "error_requests": 0, "changed_fields": 0,
            "text_tokens_before_estimate": 0, "text_tokens_after_estimate": 0,
            "compression_model_calls": 0,
            "cache_hits": 0, "rejected_fields": 0,
            "local_model_calls": 0, "lossy_fields": 0,
            "full_request_tokens_before_estimate": 0, "full_request_tokens_after_estimate": 0,
        }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def compress(self, raw: bytes) -> bytes:
        return self.compress_observed(raw)[0]

    def compress_observed(self, raw: bytes) -> tuple[bytes, CompressionObservation]:
        started = time.monotonic()
        try:
            output, observation = self._compress(raw)
        except Exception:
            output = raw
            observation = CompressionObservation("error", "compression_failed")
        observation = CompressionObservation(
            **{**asdict(observation), "latency_ms": round(1000 * (time.monotonic() - started), 3)}
        )
        with self._lock:
            self._stats["requests"] += 1
            self._stats[{"compressed": "compressed_requests", "skipped": "skipped_requests", "error": "error_requests"}[observation.status]] += 1
            for key in ("changed_fields", "text_tokens_before_estimate", "text_tokens_after_estimate",
                        "compression_model_calls", "cache_hits", "rejected_fields", "local_model_calls", "lossy_fields",
                        "full_request_tokens_before_estimate", "full_request_tokens_after_estimate"):
                self._stats[key] += getattr(observation, key)
        if self.on_observation is not None:
            try:
                self.on_observation(observation)
            except Exception:
                pass  # Telemetry cannot prevent an otherwise valid request.
        return output, observation

    def _compress(self, raw: bytes) -> tuple[bytes, CompressionObservation]:
        from .structural_compression import loads, dumps
        def skip(reason: str) -> tuple[bytes, CompressionObservation]:
            return raw, CompressionObservation("skipped", reason)

        if not raw or len(raw) > _MAX_BODY_BYTES:
            return skip("body_size")
        try:
            body = loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return skip("invalid_json")
        if not isinstance(body, dict) or not isinstance(body.get("input"), (str, list)):
            return skip("unsupported_input")
        if any(body.get(key) is not None for key in ("previous_response_id", "conversation", "prompt")):
            return skip("server_managed_context")
        if self.token_counter is None:
            count, source = default_token_counter(str(body.get("model", "")))
        else:
            count, source = self.token_counter, "custom-tokenizer-est"
        full_before = count(dumps(body))
        before = after = changed = 0
        roles: set[str] = set()
        for container, key, role in _text_slots(body):
            text = container[key]
            candidate = transform_data(text, role, compress_prose)
            original_tokens = count(text)
            candidate_tokens = count(candidate) if candidate != text else original_tokens
            before += original_tokens
            # Small fields and candidates that grow or empty the input stay raw.
            if candidate.strip() and len(candidate) < len(text) and candidate_tokens < original_tokens:
                container[key] = candidate
                changed += 1
                roles.add(role)
                after += candidate_tokens
            else:
                after += original_tokens
        full_after = count(dumps(body)) if changed else full_before
        if full_after >= full_before:
            return raw, CompressionObservation('skipped', 'no_savings', before, before,
                tokenizer_source=source, full_request_tokens_before_estimate=full_before,
                full_request_tokens_after_estimate=full_before)
        observation = CompressionObservation(
            "compressed" if changed else "skipped", "shorter_text" if changed else "no_savings",
            before, after, changed, tuple(sorted(roles)), source,
            full_request_tokens_before_estimate=full_before, full_request_tokens_after_estimate=full_after,
        )
        if not changed:
            return raw, observation
        return dumps(body).encode("utf-8"), observation
