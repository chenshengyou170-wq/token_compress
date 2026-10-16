from __future__ import annotations

import json
import os
import re
import stat
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from .redaction import redact_text
from .storage import append_jsonl_locked
from .util import now_iso


OTEL_TRACE_SCHEMA = "codexscope.otel.trace.v1"
_LOOPBACK_HOST = "127.0.0.1"
_TRACE_PATH = "/v1/traces"
_DEFAULT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024

# Codex deliberately emits a separate trace-safe telemetry stream.  Retain
# only count, identity, policy, timing, and outcome fields from that stream.
# In particular, unknown fields and free-form error text are not persisted.
_SAFE_ATTRIBUTE = re.compile(
    r"^(?:"
    r"event\.(?:name|kind|timestamp)|"
    r"conversation\.id|app\.version|auth_mode|originator|terminal\.type|"
    r"model|slug|provider_name|reasoning_effort|reasoning_summary|"
    r"context_window|auto_compact_token_limit|approval_policy|sandbox_policy|"
    r"mcp_server_count|tool_name|call_id|outcome|success|"
    r"duration_ms|initial_duration_ms|escalated_duration_ms|ttft_ms|"
    r"arguments_length|output_length|output_line_count|tool_origin|mcp_tool|"
    r"prompt_length|text_input_count|image_input_count|local_image_input_count|"
    r"input_token_count|output_token_count|cached_token_count|"
    r"cache_write_token_count|reasoning_token_count|tool_token_count|"
    r"service_tier|model_reasoning_effort|http\.response\.status_code|attempt|"
    r"startup\.(?:phase|status)|plugin_install\.(?:tool_type|response_action|user_confirmed|completed)|"
    r"auth\.(?:header_attached|retry_after_unauthorized|connection_reused|"
    r"env_openai_api_key_present|env_codex_api_key_present|"
    r"env_codex_api_key_enabled|env_provider_key_present|"
    r"env_refresh_token_url_override_present)|"
    r"gen_ai\.[A-Za-z0-9_.]*tokens|codex\.usage\.[A-Za-z0-9_.]*tokens|"
    r"rpc\.(?:system|method)|otel\.(?:name|kind)|from|phase|status"
    r")$"
)
_SAFE_RESOURCE_ATTRIBUTE = re.compile(
    r"^(?:service\.(?:name|version)|deployment\.environment\.name|"
    r"telemetry\.sdk\.(?:name|language|version))$"
)


def _bounded_text(value: object, *, limit: int = 1024) -> str:
    text = redact_text(str(value))
    if len(text) <= limit:
        return text
    return f"{text[:limit]}[TRUNCATED:{len(text)} chars]"


def _integer(value: object) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _any_value(value: object, *, depth: int = 0) -> object:
    """Decode one OTLP/JSON AnyValue without retaining opaque byte strings."""

    if depth > 4 or not isinstance(value, Mapping):
        return None
    if "stringValue" in value:
        return _bounded_text(value["stringValue"])
    if "boolValue" in value and type(value["boolValue"]) is bool:
        return value["boolValue"]
    if "intValue" in value:
        return _integer(value["intValue"])
    if "doubleValue" in value and type(value["doubleValue"]) in {int, float}:
        return float(value["doubleValue"])
    if "bytesValue" in value:
        encoded = str(value["bytesValue"])
        return {"bytes_omitted": True, "encoded_length": len(encoded)}
    array = value.get("arrayValue")
    if isinstance(array, Mapping) and isinstance(array.get("values"), list):
        return [
            _any_value(item, depth=depth + 1)
            for item in array["values"][:64]
        ]
    kvlist = value.get("kvlistValue")
    if isinstance(kvlist, Mapping):
        return _attributes(kvlist.get("values"), allow=_SAFE_ATTRIBUTE, depth=depth + 1)[0]
    return None


def _attributes(
    value: object,
    *,
    allow: re.Pattern[str],
    depth: int = 0,
) -> tuple[dict[str, object], int]:
    if depth > 4 or not isinstance(value, list):
        return {}, 0
    result: dict[str, object] = {}
    omitted = 0
    for item in value[:512]:
        if not isinstance(item, Mapping):
            omitted += 1
            continue
        key = str(item.get("key") or "")
        if not key or allow.fullmatch(key) is None:
            omitted += 1
            continue
        decoded = _any_value(item.get("value"), depth=depth + 1)
        if decoded is None:
            omitted += 1
            continue
        result[_bounded_text(key, limit=256)] = decoded
    if len(value) > 512:
        omitted += len(value) - 512
    return result, omitted


def _scope(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, object] = {}
    for key in ("name", "version"):
        candidate = value.get(key)
        if candidate is not None:
            result[key] = _bounded_text(candidate, limit=256)
    return result


def _status(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    # OTLP status.message is free-form and can echo provider or tool content.
    # Persist its presence only, never the body.
    result: dict[str, object] = {}
    code = value.get("code")
    if code is not None:
        result["code"] = _bounded_text(code, limit=64)
    message = value.get("message")
    if message:
        result["message_omitted"] = True
        result["message_length"] = len(str(message))
    return result


def _toml_string(value: str) -> str:
    # TOML basic strings accept the JSON escapes emitted here for the generated
    # loopback URL and UUID.  Keeping this helper general prevents config
    # injection if callers later supply a different run label.
    return json.dumps(value, ensure_ascii=False)


def codex_trace_config_arguments(endpoint: str) -> list[str]:
    """Return CLI overrides that enable only Codex's trace-safe exporter."""

    return [
        "-c",
        'otel.environment="codexscope-local"',
        "-c",
        "otel.log_user_prompt=false",
        "-c",
        'otel.exporter="none"',
        "-c",
        'otel.metrics_exporter="none"',
        "-c",
        (
            "otel.trace_exporter={otlp-http={endpoint="
            f"{_toml_string(endpoint)},protocol=\"json\"}}}}"
        ),
    ]


class _Server(ThreadingHTTPServer):
    # Let server_close wait for bounded in-flight requests so the final summary
    # cannot race a last Codex exporter batch.  Each connection has a 5 s read
    # timeout, which bounds monitor shutdown as well.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False


class OtelTraceCollector:
    """Bounded loopback OTLP/HTTP JSON collector for Codex trace-safe data."""

    def __init__(
        self,
        output: Path,
        *,
        max_events: int = 100_000,
        max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
        max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        if not 1 <= max_events <= 10_000_000:
            raise ValueError("max_events must be between 1 and 10000000")
        if max_request_bytes < 1024 or max_total_bytes < max_request_bytes:
            raise ValueError("invalid OTLP byte limits")
        self.output = output.expanduser().resolve()
        self.max_events = max_events
        self.max_request_bytes = max_request_bytes
        self.max_total_bytes = max_total_bytes
        self._lock = threading.Lock()
        self._ingest_lock = threading.Lock()
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._closed = False
        self._stats: Counter[str] = Counter()
        self._event_names: Counter[str] = Counter()
        self._span_names: Counter[str] = Counter()

    @property
    def endpoint(self) -> str:
        server = self._server
        if server is None:
            raise RuntimeError("OTLP collector is not running")
        return f"http://{_LOOPBACK_HOST}:{server.server_port}{_TRACE_PATH}"

    def start(self) -> "OtelTraceCollector":
        if self._server is not None or self._closed:
            raise RuntimeError("OTLP collector cannot be started twice")
        self.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output.parent.chmod(0o700)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.output, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"refusing non-regular OTLP destination: {self.output}")
        finally:
            os.close(fd)

        collector = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "CodexScopeOTLP/1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def _reply(self, status: int, payload: bytes = b"{}") -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                if self.path != _TRACE_PATH:
                    collector._increment("unexpected_paths")
                    self._reply(404)
                    return
                if self.headers.get("Transfer-Encoding"):
                    collector._increment("rejected_requests")
                    self._reply(400)
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    length = -1
                if length < 0:
                    collector._increment("rejected_requests")
                    self._reply(411)
                    return
                if length > collector.max_request_bytes:
                    collector._increment("rejected_requests")
                    self._reply(413)
                    return
                content_type = self.headers.get("Content-Type", "")
                if not content_type.casefold().startswith("application/json"):
                    collector._increment("rejected_requests")
                    self._reply(415)
                    return
                self.connection.settimeout(5.0)
                try:
                    body = self.rfile.read(length)
                except OSError:
                    collector._increment("rejected_requests")
                    self._reply(408)
                    return
                if len(body) != length:
                    collector._increment("rejected_requests")
                    self._reply(400)
                    return
                status = collector._ingest(body)
                self._reply(status)

        server = _Server((_LOOPBACK_HOST, 0), Handler)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="codexscope-otel-trace",
            daemon=True,
        )
        self._thread.start()
        return self

    def _increment(self, key: str, value: int = 1) -> None:
        with self._lock:
            self._stats[key] += value

    def _reserve(self, received_bytes: int, record_count: int) -> int:
        with self._lock:
            self._stats["received_requests"] += 1
            if self._stats["received_bytes"] + received_bytes > self.max_total_bytes:
                self._stats["rejected_requests"] += 1
                self._stats["dropped_records"] += record_count
                self._stats["total_byte_limit_reached"] = 1
                return 0
            self._stats["received_bytes"] += received_bytes
            remaining = max(0, self.max_events - self._stats["persisted_records"])
            accepted = min(record_count, remaining)
            if accepted < record_count:
                self._stats["dropped_records"] += record_count - accepted
                self._stats["event_limit_reached"] = 1
            return accepted

    def _ingest(self, body: bytes) -> int:
        # ThreadingHTTPServer may deliver exporter batches concurrently.  Keep
        # limit reservation and append accounting atomic across one batch.
        with self._ingest_lock:
            return self._ingest_serialized(body)

    def _ingest_serialized(self, body: bytes) -> int:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._increment("parse_errors")
            self._increment("received_requests")
            return 400
        if not isinstance(payload, Mapping):
            self._increment("parse_errors")
            self._increment("received_requests")
            return 400
        try:
            rows, omitted = self._flatten(payload)
        except (TypeError, ValueError, RecursionError):
            self._increment("parse_errors")
            self._increment("received_requests")
            return 400
        accepted = self._reserve(len(body), len(rows))
        if accepted == 0 and rows:
            # Acknowledge valid OTLP after recording the local limit gap.  A
            # retry cannot restore a deliberately bounded local trace and can
            # otherwise create an exporter retry loop.
            with self._lock:
                self._stats["accepted_requests"] += 1
                self._stats["omitted_attributes"] += omitted
            return 200
        persisted = 0
        try:
            for row in rows[:accepted]:
                append_jsonl_locked(self.output, row)
                persisted += 1
        except OSError:
            with self._lock:
                self._stats["persistence_errors"] += 1
                self._stats["dropped_records"] += accepted - persisted
                self._stats["persisted_records"] += persisted
            return 500
        with self._lock:
            self._stats["accepted_requests"] += 1
            self._stats["persisted_records"] += persisted
            self._stats["omitted_attributes"] += omitted
            for row in rows[:persisted]:
                if row["record_kind"] == "event":
                    self._stats["events"] += 1
                    self._event_names[str(row["name"])] += 1
                else:
                    self._stats["spans"] += 1
                    self._span_names[str(row["name"])] += 1
        return 200

    def _flatten(self, payload: Mapping[str, object]) -> tuple[list[dict[str, object]], int]:
        rows: list[dict[str, object]] = []
        omitted_total = 0
        resources = payload.get("resourceSpans")
        if not isinstance(resources, list):
            return rows, omitted_total
        for resource_span in resources[:256]:
            if not isinstance(resource_span, Mapping):
                continue
            resource_value = resource_span.get("resource")
            resource_attrs, omitted = _attributes(
                resource_value.get("attributes")
                if isinstance(resource_value, Mapping)
                else None,
                allow=_SAFE_RESOURCE_ATTRIBUTE,
            )
            omitted_total += omitted
            scope_spans = resource_span.get("scopeSpans")
            if not isinstance(scope_spans, list):
                # Older OTLP JSON encoders used instrumentationLibrarySpans.
                scope_spans = resource_span.get("instrumentationLibrarySpans")
            if not isinstance(scope_spans, list):
                continue
            for scope_span in scope_spans[:256]:
                if not isinstance(scope_span, Mapping):
                    continue
                scope_value = scope_span.get("scope")
                if not isinstance(scope_value, Mapping):
                    scope_value = scope_span.get("instrumentationLibrary")
                scope = _scope(scope_value)
                spans = scope_span.get("spans")
                if not isinstance(spans, list):
                    continue
                for span in spans[:4096]:
                    if not isinstance(span, Mapping):
                        continue
                    attributes, omitted = _attributes(
                        span.get("attributes"), allow=_SAFE_ATTRIBUTE
                    )
                    omitted_total += omitted
                    trace_id = _bounded_text(span.get("traceId") or "", limit=64)
                    span_id = _bounded_text(span.get("spanId") or "", limit=32)
                    common: dict[str, object] = {
                        "schema_version": OTEL_TRACE_SCHEMA,
                        "received_at": now_iso(),
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": _bounded_text(
                            span.get("parentSpanId") or "", limit=32
                        ),
                        "resource": resource_attrs,
                        "scope": scope,
                    }
                    span_name = _bounded_text(span.get("name") or "unknown", limit=256)
                    rows.append(
                        {
                            **common,
                            "record_kind": "span",
                            "name": span_name,
                            "start_time_unix_nano": _integer(
                                span.get("startTimeUnixNano")
                            ),
                            "end_time_unix_nano": _integer(
                                span.get("endTimeUnixNano")
                            ),
                            "attributes": attributes,
                            "status": _status(span.get("status")),
                        }
                    )
                    events = span.get("events")
                    if not isinstance(events, list):
                        continue
                    for event_index, event in enumerate(events[:4096]):
                        if not isinstance(event, Mapping):
                            continue
                        event_attributes, omitted = _attributes(
                            event.get("attributes"), allow=_SAFE_ATTRIBUTE
                        )
                        omitted_total += omitted
                        name = event_attributes.get("event.name") or event.get("name")
                        rows.append(
                            {
                                **common,
                                "record_kind": "event",
                                "event_index": event_index,
                                "name": _bounded_text(name or "unknown", limit=256),
                                "time_unix_nano": _integer(event.get("timeUnixNano")),
                                "attributes": event_attributes,
                            }
                        )
        return rows, omitted_total

    def stats_dict(self) -> dict[str, object]:
        with self._lock:
            stats = dict(self._stats)
            event_names = dict(self._event_names.most_common())
            span_names = dict(self._span_names.most_common())
        for key in (
            "received_requests",
            "accepted_requests",
            "received_bytes",
            "persisted_records",
            "events",
            "spans",
            "dropped_records",
            "parse_errors",
            "rejected_requests",
            "unexpected_paths",
            "omitted_attributes",
        ):
            stats.setdefault(key, 0)
        return {
            "schema_version": OTEL_TRACE_SCHEMA,
            "running": self._server is not None and not self._closed,
            "bind_host": _LOOPBACK_HOST,
            "endpoint_path": _TRACE_PATH,
            "max_events": self.max_events,
            "max_request_bytes": self.max_request_bytes,
            "max_total_bytes": self.max_total_bytes,
            **stats,
            "event_names": event_names,
            "span_names": span_names,
            "content_capture": False,
            "unknown_attributes_persisted": False,
        }

    def stop(self) -> dict[str, object]:
        if self._closed:
            return self.stats_dict()
        server = self._server
        thread = self._thread
        self._closed = True
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                self._increment("reader_stop_timeout")
        self._server = None
        self._thread = None
        result = self.stats_dict()
        result["running"] = False
        return result
