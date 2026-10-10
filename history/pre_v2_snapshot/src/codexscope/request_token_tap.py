"""Opt-in HTTP request-boundary token observation for OpenAI Responses.

The relay borrows TokenTap's useful observation point—the fully assembled API
request—but deliberately does not archive request bodies. By default it forwards
bytes unchanged; an explicit local input compressor can shorten prose before
observation and forwarding. It emits numeric input estimates and raw tool-argument
SSE deltas so the live reducer can avoid an item-snapshot approximation. For
multimodal Responses requests it also performs a fail-open provider token-count
preflight against the same configured origin.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping
from urllib.parse import SplitResult, urlsplit

from .media_token_task import estimate_image_input_tokens, image_dimensions_from_bytes
from .proxy_usage import TokenCounter, default_token_counter
from .input_compression import ResponsesInputCompressor
from .request_usage_ledger import RequestUsageLedger, provider_usage


_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_REQUEST_CONTEXT_REFERENCE_KEYS = frozenset(
    {"conversation", "previous_response_id", "prompt"}
)
_HEALTH_PATH = "/.codexscope-request-token-tap-health"
_NON_TEXT_CONTENT_TYPES = frozenset(
    {"input_image", "image_url", "input_file", "file", "input_audio", "audio"}
)
# ``/responses/input_tokens`` does not accept generation/transport controls
# such as ``stream``, ``store``, or ``max_output_tokens``. Forwarding the
# complete ``responses.create`` body works against permissive test doubles but
# strict providers reject those extra fields before they can count a PDF. Drop
# only fields known not to affect rendered input; unknown/new fields are kept
# so a future input-bearing field can never be silently omitted from a result
# labelled provider-exact. The original generation request bytes stay intact.
_PROVIDER_INPUT_TOKEN_OMITTED_FIELDS = frozenset(
    {
        "background",
        "include",
        "max_output_tokens",
        "max_tool_calls",
        "metadata",
        "moderation",
        "prompt_cache_key",
        "prompt_cache_options",
        "prompt_cache_retention",
        "safety_identifier",
        "service_tier",
        "store",
        "stream",
        "stream_options",
        "temperature",
        "top_logprobs",
        "top_p",
        "user",
    }
)
_MAX_PROVIDER_COUNT_RESPONSE_BYTES = 1024 * 1024
_MAX_LOCAL_IMAGE_HEADER_BYTES = 2 * 1024 * 1024


def _is_loopback_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class RequestInputEstimate:
    """Privacy-safe result of tokenizing one model-visible request prefix."""

    input_tokens: int
    model: str
    source: str
    tokenizer_source: str
    component_tokens: dict[str, int]
    context_complete: bool
    request_id: str | None = None
    modality_counts: dict[str, int] = field(default_factory=dict)
    text_input_tokens: int | None = None
    multimodal_input_tokens: int | None = None
    multimodal_input_quality: str | None = None
    provider_count_latency_ms: float | None = None
    provider_count_status: str | None = None


def _compact_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _looks_like_pdf(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    if normalized.startswith("data:application/pdf"):
        return True
    path = normalized.split("?", 1)[0].split("#", 1)[0]
    return path.endswith(".pdf")


def summarize_openai_request_modalities(body: object) -> dict[str, int]:
    """Return privacy-safe image/PDF/file/audio counts for one request."""

    counts: dict[str, int] = {}

    def note(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    def visit(value: object) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, Mapping):
            return
        content_type = value.get("type")
        if content_type in {"input_image", "image_url"}:
            note("image")
            return
        if content_type in {"input_audio", "audio"}:
            note("audio")
            return
        if content_type in {"input_file", "file"}:
            candidates: list[object] = [
                value.get("filename"),
                value.get("file_name"),
                value.get("file_url"),
                value.get("file_data"),
            ]
            nested_file = value.get("file")
            if isinstance(nested_file, Mapping):
                candidates.extend(
                    (
                        nested_file.get("filename"),
                        nested_file.get("file_name"),
                        nested_file.get("file_url"),
                        nested_file.get("file_data"),
                    )
                )
            # ``input_file`` is a transport type, not a PDF guarantee. Only a
            # filename, URL, or data-URI with PDF evidence earns the PDF label;
            # opaque file IDs stay in the generic file bucket.
            is_pdf = any(_looks_like_pdf(item) for item in candidates)
            note("pdf" if is_pdf else "file")
            return
        for item in value.values():
            visit(item)

    visit(body)
    return counts


_DROP_NON_TEXT = object()


def _strip_non_text_content(value: object) -> object:
    """Copy a request while removing multimodal blocks for differential count."""

    if isinstance(value, list):
        result = []
        for item in value:
            stripped = _strip_non_text_content(item)
            if stripped is not _DROP_NON_TEXT:
                result.append(stripped)
        return result
    if not isinstance(value, Mapping):
        return value
    if value.get("type") in _NON_TEXT_CONTENT_TYPES:
        return _DROP_NON_TEXT

    result: dict[str, object] = {}
    for raw_key, item in value.items():
        key = str(raw_key)
        stripped = _strip_non_text_content(item)
        if stripped is _DROP_NON_TEXT:
            continue
        if key == "content" and isinstance(stripped, list) and not stripped:
            # An easy message with an empty content list is not a valid count
            # request.  An empty text value preserves its role framing.
            result[key] = ""
        else:
            result[key] = stripped
    if isinstance(result.get("input"), list) and not result["input"]:
        result["input"] = ""
    return result


def _provider_input_token_payload(value: object) -> dict[str, object] | None:
    """Project a Responses generation body onto the token-count schema."""

    if not isinstance(value, Mapping):
        return None
    projected = {
        str(key): item
        for key, item in value.items()
        if str(key) not in _PROVIDER_INPUT_TOKEN_OMITTED_FIELDS
    }
    return projected or None


def _sanitize_non_text_content(value: object) -> tuple[object, bool]:
    """Remove binary/image payloads whose provider token cost is unavailable."""

    if isinstance(value, list):
        result: list[object] = []
        incomplete = False
        for item in value:
            sanitized, item_incomplete = _sanitize_non_text_content(item)
            result.append(sanitized)
            incomplete = incomplete or item_incomplete
        return result, incomplete
    if not isinstance(value, Mapping):
        return value, False

    result: dict[str, object] = {}
    incomplete = False
    content_type = value.get("type")
    omitted_keys: frozenset[str] = frozenset()
    if content_type in {"input_image", "image_url"}:
        omitted_keys = frozenset({"image_url", "file_id"})
    elif content_type in {"input_file", "file"}:
        omitted_keys = frozenset({"file", "file_data", "file_id", "file_url"})
    elif content_type in {"input_audio", "audio"}:
        omitted_keys = frozenset({"input_audio", "audio", "data"})
    for raw_key, item in value.items():
        key = str(raw_key)
        if key in omitted_keys:
            # Retain the request shape but do not pretend that a textual
            # placeholder represents provider-side image/file/audio tokens.
            result[key] = ""
            incomplete = True
            continue
        sanitized, item_incomplete = _sanitize_non_text_content(item)
        result[key] = sanitized
        incomplete = incomplete or item_incomplete
    return result, incomplete


def _image_data_uri_header(value: object) -> bytes | None:
    """Decode only enough inline image bytes to read dimensions."""

    if not isinstance(value, str) or not value.lower().startswith("data:image/"):
        return None
    try:
        metadata, encoded = value.split(",", 1)
    except ValueError:
        return None
    if ";base64" not in metadata.lower():
        return None
    # Dimension metadata is near the beginning for supported image formats.
    # Bounding the decode avoids duplicating a very large request body in RAM.
    encoded_limit = ((_MAX_LOCAL_IMAGE_HEADER_BYTES + 2) // 3) * 4
    prefix = encoded[:encoded_limit]
    prefix += "=" * (-len(prefix) % 4)
    try:
        return base64.b64decode(prefix, validate=False)
    except (ValueError, TypeError):
        return None


def _estimate_inline_image_tokens(
    body: Mapping[str, object],
    *,
    model: str,
) -> tuple[int, int]:
    """Return (tokens, image-count-covered) for inline image request blocks."""

    total = 0
    covered = 0

    def visit(value: object) -> None:
        nonlocal total, covered
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, Mapping):
            return
        content_type = value.get("type")
        if content_type in {"input_image", "image_url"}:
            candidate: object = value.get("image_url")
            detail: object = value.get("detail")
            if isinstance(candidate, Mapping):
                detail = candidate.get("detail", detail)
                candidate = candidate.get("url")
            header = _image_data_uri_header(candidate)
            dimensions = (
                image_dimensions_from_bytes(header) if header is not None else None
            )
            if dimensions is not None:
                estimate = estimate_image_input_tokens(
                    *dimensions,
                    model=model,
                    detail=detail if isinstance(detail, str) else None,
                )
                if estimate is not None:
                    total += estimate
                    covered += 1
            return
        for item in value.values():
            visit(item)

    visit(body)
    return total, covered


def estimate_openai_request_input(
    body: object,
    *,
    model_hint: str | None = None,
    token_counter: TokenCounter | None = None,
    token_counter_source: str | None = None,
) -> RequestInputEstimate | None:
    """Tokenize the complete model-visible portion of a Responses/chat request.

    Provider usage remains authoritative.  Local JSON tokenization cannot know
    provider-only message framing, retrieved ``previous_response_id`` context,
    or image/audio tokenization, so those cases are explicitly marked as
    incomplete and remain eligible for estimate-to-official calibration.
    """

    if not isinstance(body, Mapping):
        return None
    raw_model = body.get("model")
    model = (
        raw_model.strip()
        if isinstance(raw_model, str) and raw_model.strip()
        else (model_hint or "unknown-model")
    )
    counter = token_counter
    source = token_counter_source
    if counter is None:
        counter, source = default_token_counter(model)
    if source is None:
        source = "custom-tokenizer-est"

    selected: dict[str, object] = {}
    # Responses API fields that are directly model-visible.
    for key in ("instructions", "input", "tools", "prompt"):
        if key in body and body[key] not in (None, "", [], {}):
            selected[key] = body[key]
    # Chat Completions compatibility, useful for custom Codex providers.
    if "messages" in body and body["messages"] not in (None, [], {}):
        selected["messages"] = body["messages"]
    if "functions" in body and body["functions"] not in (None, [], {}):
        selected["functions"] = body["functions"]

    text_controls = body.get("text")
    if isinstance(text_controls, Mapping) and text_controls.get("format") is not None:
        selected["output_format"] = text_controls["format"]
    if body.get("response_format") is not None:
        selected["output_format"] = body["response_format"]
    if not selected:
        return None

    sanitized, non_text_incomplete = _sanitize_non_text_content(selected)
    try:
        serialized = _compact_json(sanitized)
    except (TypeError, ValueError):
        return None
    text_total = int(counter(serialized))
    if text_total < 0:
        return None

    component_tokens: dict[str, int] = {}
    assert isinstance(sanitized, Mapping)
    for key, value in sanitized.items():
        component_text = value if isinstance(value, str) else _compact_json(value)
        count = int(counter(component_text))
        if count >= 0:
            component_tokens[str(key)] = count

    has_remote_context = any(
        body.get(key) not in (None, "", [], {})
        for key in _REQUEST_CONTEXT_REFERENCE_KEYS
    )
    modality_counts = summarize_openai_request_modalities(body)
    local_multimodal_tokens, covered_images = _estimate_inline_image_tokens(
        body,
        model=model,
    )
    if local_multimodal_tokens:
        component_tokens["image_input_estimate"] = local_multimodal_tokens
    media_count = sum(modality_counts.values())
    multimodal_quality: str | None = None
    if local_multimodal_tokens:
        multimodal_quality = (
            "local_estimate"
            if covered_images == media_count
            else "local_estimate_partial"
        )
    return RequestInputEstimate(
        input_tokens=text_total + local_multimodal_tokens,
        model=model,
        source=f"request-body/{source}",
        tokenizer_source=source,
        component_tokens=component_tokens,
        context_complete=not (non_text_incomplete or has_remote_context),
        modality_counts=modality_counts,
        multimodal_input_tokens=(
            local_multimodal_tokens if local_multimodal_tokens else None
        ),
        multimodal_input_quality=multimodal_quality,
    )


class SseDecoder:
    """Incrementally decode SSE records without retaining the full response."""

    def __init__(
        self,
        callback: Callable[[str, Mapping[str, Any]], None],
        *,
        max_buffer_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self.callback = callback
        self.max_buffer_bytes = max_buffer_bytes
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._buffer.extend(chunk)
        if len(self._buffer) > self.max_buffer_bytes:
            self._buffer.clear()
            return
        while True:
            lf_index = self._buffer.find(b"\n\n")
            crlf_index = self._buffer.find(b"\r\n\r\n")
            candidates = [index for index in (lf_index, crlf_index) if index >= 0]
            if not candidates:
                return
            index = min(candidates)
            separator_length = 4 if index == crlf_index else 2
            record = bytes(self._buffer[:index])
            del self._buffer[: index + separator_length]
            self._consume_record(record)

    def _consume_record(self, record: bytes) -> None:
        event_name: str | None = None
        data_lines: list[bytes] = []
        for raw_line in record.splitlines():
            line = raw_line.rstrip(b"\r")
            if line.startswith(b"event:"):
                event_name = line[6:].strip().decode("utf-8", errors="replace")
            elif line.startswith(b"data:"):
                data_lines.append(line[5:].lstrip())
        if not data_lines:
            return
        raw_data = b"\n".join(data_lines)
        if raw_data.strip() == b"[DONE]":
            return
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(data, Mapping):
            return
        event_type = event_name or data.get("type") or data.get("object")
        if isinstance(event_type, str):
            self.callback(event_type, data)


class _TapHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        upstream: SplitResult,
        on_input_estimate: Callable[[RequestInputEstimate], None] | None,
        on_sse_event: Callable[[str, Mapping[str, Any]], None] | None,
        timeout_s: float,
        provider_count_timeout_s: float,
        input_compressor: ResponsesInputCompressor | None = None,
        on_request_usage: Callable[[dict], None] | None = None,
    ) -> None:
        self.upstream = upstream
        self.on_input_estimate = on_input_estimate
        self.on_sse_event = on_sse_event
        self.timeout_s = timeout_s
        self.provider_count_timeout_s = provider_count_timeout_s
        self.input_compressor = input_compressor
        self.usage_ledger = RequestUsageLedger(on_record=on_request_usage)
        self.stats_lock = threading.Lock()
        self.request_sequence = 0
        self.request_count = 0
        self.observed_request_count = 0
        self.multimodal_request_count = 0
        self.provider_count_attempt_count = 0
        self.provider_count_success_count = 0
        self.provider_count_error_count = 0
        self.provider_breakdown_attempt_count = 0
        self.provider_breakdown_success_count = 0
        self.provider_breakdown_error_count = 0
        self.sse_event_count = 0
        self.error_count = 0
        self.provider_threads: set[threading.Thread] = set()
        self.provider_threads_lock = threading.Lock()
        self.stopping = threading.Event()
        super().__init__(address, _TapRequestHandler)

    def note(self, field: str) -> None:
        with self.stats_lock:
            setattr(self, field, int(getattr(self, field)) + 1)

    def next_request_id(self) -> str:
        with self.stats_lock:
            self.request_sequence += 1
            return f"tap-{self.request_sequence}"

    def emit_input_estimate(self, estimate: RequestInputEstimate) -> bool:
        callback = self.on_input_estimate
        if callback is None:
            return False
        try:
            callback(estimate)
        except Exception:
            self.note("error_count")
            return False
        return True

    def start_provider_thread(self, target: Callable[[], None], *, name: str) -> None:
        thread: threading.Thread

        def run() -> None:
            try:
                target()
            finally:
                with self.provider_threads_lock:
                    self.provider_threads.discard(thread)

        thread = threading.Thread(target=run, name=name, daemon=True)
        with self.provider_threads_lock:
            if self.stopping.is_set():
                return
            self.provider_threads.add(thread)
        thread.start()

    def join_provider_threads(self, timeout_s: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout_s)
        while True:
            with self.provider_threads_lock:
                threads = list(self.provider_threads)
            if not threads:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))


class _TapRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CodexScopeRequestTap/1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Never print URLs or headers from authenticated model traffic.
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == _HEALTH_PATH:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        self._relay()

    def do_HEAD(self) -> None:  # noqa: N802
        self._relay()

    def do_POST(self) -> None:  # noqa: N802
        self._relay()

    def do_PUT(self) -> None:  # noqa: N802
        self._relay()

    def do_PATCH(self) -> None:  # noqa: N802
        self._relay()

    def do_DELETE(self) -> None:  # noqa: N802
        self._relay()

    @property
    def tap_server(self) -> _TapHTTPServer:
        assert isinstance(self.server, _TapHTTPServer)
        return self.server

    def _read_body(self) -> bytes:
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" not in transfer_encoding:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                return b""
            length = int(raw_length)
            if length < 0:
                raise ValueError("negative content length")
            return self.rfile.read(length)

        chunks: list[bytes] = []
        while True:
            size_line = self.rfile.readline(128)
            if not size_line:
                raise ValueError("incomplete chunked request")
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while self.rfile.readline(8_192) not in {b"\r\n", b"\n", b""}:
                    pass
                break
            chunks.append(self.rfile.read(size))
            if self.rfile.read(2) != b"\r\n":
                raise ValueError("invalid chunk delimiter")
        return b"".join(chunks)

    def _observe_request(self, body: bytes, target: str, request_id: str | None = None) -> None:
        server = self.tap_server
        if server.on_input_estimate is None or not body:
            return
        endpoint = urlsplit(target).path.rstrip("/")
        if not endpoint.endswith(
            ("/responses", "/responses/compact", "/chat/completions")
        ):
            return
        encoding = self.headers.get("Content-Encoding", "").strip().lower()
        if encoding not in {"", "identity"}:
            return
        try:
            payload = json.loads(body)
            estimate = estimate_openai_request_input(payload)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            return
        if estimate is None:
            return
        request_id = request_id or server.next_request_id()
        provider_count_supported = bool(
            estimate.modality_counts and endpoint.endswith("/responses")
        )
        estimate = replace(
            estimate,
            request_id=request_id,
            provider_count_status=(
                "pending"
                if provider_count_supported
                else ("unsupported" if estimate.modality_counts else None)
            ),
        )
        if not server.emit_input_estimate(estimate):
            return
        server.note("observed_request_count")
        if provider_count_supported:
            self._start_provider_input_count(
                target=target,
                payload=payload,
                local_estimate=estimate,
            )

    @staticmethod
    def _provider_count_target(target: str) -> str | None:
        parsed = urlsplit(target)
        path = parsed.path.rstrip("/")
        if not path.endswith("/responses"):
            return None
        count_path = f"{path}/input_tokens"
        return f"{count_path}?{parsed.query}" if parsed.query else count_path

    def _provider_count_headers(self) -> dict[str, str]:
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _HOP_BY_HOP_HEADERS
            and key.lower()
            not in {
                "host",
                "content-length",
                "content-md5",
                "content-encoding",
                "digest",
                "idempotency-key",
                "accept",
                "accept-encoding",
            }
        }
        headers["Accept"] = "application/json"
        headers["Accept-Encoding"] = "identity"
        headers["Content-Type"] = "application/json"
        return headers

    def _provider_input_token_count(
        self,
        *,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> int | None:
        connection = self._upstream_connection(
            timeout_s=self.tap_server.provider_count_timeout_s
        )
        try:
            connection.request("POST", target, body=body, headers=dict(headers))
            response = connection.getresponse()
            raw = response.read(_MAX_PROVIDER_COUNT_RESPONSE_BYTES + 1)
            if response.status != 200 or len(raw) > _MAX_PROVIDER_COUNT_RESPONSE_BYTES:
                return None
            payload = json.loads(raw)
            if not isinstance(payload, Mapping):
                return None
            count = payload.get("input_tokens")
            if type(count) is not int or count < 0:
                return None
            return count
        except Exception:
            return None
        finally:
            connection.close()

    def _start_provider_input_count(
        self,
        *,
        target: str,
        payload: object,
        local_estimate: RequestInputEstimate,
    ) -> None:
        """Count a multimodal request in parallel without delaying generation."""

        count_target = self._provider_count_target(target)
        if count_target is None:
            return
        try:
            count_payload = _provider_input_token_payload(payload)
            if count_payload is None:
                return
            count_body = _compact_json(count_payload).encode("utf-8")
            text_only = _strip_non_text_content(count_payload)
            if text_only is _DROP_NON_TEXT or not isinstance(text_only, Mapping):
                text_only_body = None
            else:
                text_only_body = _compact_json(text_only).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            text_only_body = None
        headers = self._provider_count_headers()
        server = self.tap_server
        server.note("multimodal_request_count")
        server.note("provider_count_attempt_count")

        def count_in_background() -> None:
            started = time.monotonic()
            exact_total = self._provider_input_token_count(
                target=count_target,
                body=count_body,
                headers=headers,
            )
            if server.stopping.is_set():
                return
            if exact_total is None:
                server.note("provider_count_error_count")
                server.emit_input_estimate(
                    replace(
                        local_estimate,
                        provider_count_status="unavailable",
                        provider_count_latency_ms=round(
                            1000.0 * (time.monotonic() - started), 3
                        ),
                    )
                )
                return
            server.note("provider_count_success_count")
            exact = replace(
                local_estimate,
                input_tokens=exact_total,
                source="provider_preflight_exact",
                tokenizer_source="provider",
                context_complete=True,
                text_input_tokens=None,
                provider_count_latency_ms=round(
                    1000.0 * (time.monotonic() - started), 3
                ),
                provider_count_status="exact",
            )
            server.emit_input_estimate(exact)

            if text_only_body is None:
                return
            server.note("provider_breakdown_attempt_count")
            exact_text = self._provider_input_token_count(
                target=count_target,
                body=text_only_body,
                headers=headers,
            )
            if server.stopping.is_set():
                return
            if exact_text is None or exact_text > exact_total:
                server.note("provider_breakdown_error_count")
                return
            server.note("provider_breakdown_success_count")
            server.emit_input_estimate(
                replace(
                    exact,
                    text_input_tokens=exact_text,
                    multimodal_input_tokens=exact_total - exact_text,
                    multimodal_input_quality="provider_exact",
                    provider_count_latency_ms=round(
                        1000.0 * (time.monotonic() - started), 3
                    ),
                    provider_count_status="exact_with_breakdown",
                )
            )

        server.start_provider_thread(
            count_in_background,
            name=f"codexscope-provider-input-counter-{local_estimate.request_id}",
        )

    def _upstream_connection(
        self,
        *,
        timeout_s: float | None = None,
    ) -> http.client.HTTPConnection:
        upstream = self.tap_server.upstream
        port = upstream.port
        timeout = self.tap_server.timeout_s if timeout_s is None else timeout_s
        if upstream.scheme == "https":
            return http.client.HTTPSConnection(
                upstream.hostname,
                port=port,
                timeout=timeout,
            )
        return http.client.HTTPConnection(
            upstream.hostname,
            port=port,
            timeout=timeout,
        )

    def _upstream_target(self) -> str:
        """Return one origin-form target confined to the configured base."""

        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ValueError("absolute or fragmented relay target is not allowed")
        path = parsed.path or "/"
        base_path = self.tap_server.upstream.path.rstrip("/")
        if base_path and path != base_path and not path.startswith(f"{base_path}/"):
            raise ValueError("relay target is outside the configured upstream base")
        return f"{path}?{parsed.query}" if parsed.query else path

    def _send_bad_gateway(self, *, response_started: bool) -> None:
        if response_started or self.wfile.closed:
            return
        try:
            headers_buffer = getattr(self, "_headers_buffer", None)
            if isinstance(headers_buffer, list):
                headers_buffer.clear()
            self.send_error(502, "upstream relay failed")
        except (BrokenPipeError, ConnectionError):
            pass

    def _relay(self) -> None:
        server = self.tap_server
        server.note("request_count")
        connection: http.client.HTTPConnection | None = None
        response_started = False
        usage_record = None
        request_stream = False
        started = time.monotonic()
        try:
            target = self._upstream_target()
            body = self._read_body()
            original_body = body
            endpoint = urlsplit(target).path.rstrip('/')
            if self.command == 'POST' and endpoint.endswith(('/responses', '/chat/completions', '/responses/compact')):
                try:
                    request_json = json.loads(body)
                    request_stream = isinstance(request_json, dict) and request_json.get('stream') is True
                    estimate = estimate_openai_request_input(request_json)
                    if estimate:
                        usage_record = {'request_id': server.next_request_id(),
                            'started_at': datetime.now(UTC).isoformat(), 'model': estimate.model,
                            'input_tokens_before_estimate': estimate.input_tokens,
                            'input_tokens_after_estimate': estimate.input_tokens,
                            'tokenizer_source': estimate.tokenizer_source,
                            'context_complete': estimate.context_complete,
                            'official_usage': None, 'usage_source': 'unavailable', 'status': 'pending'}
                except (ValueError, UnicodeDecodeError, TypeError):
                    pass
            if (
                server.input_compressor is not None
                and self.command == "POST"
                and (endpoint.endswith('/responses') or (
                    endpoint.endswith('/chat/completions')
                    and getattr(server.input_compressor, 'supports_chat_completions', False)))
                and self.headers.get("Content-Encoding", "").strip().lower() in {"", "identity"}
                and self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() == "application/json"
                and not any(self.headers.get(key) for key in (
                    "Content-MD5", "Digest", "Content-Digest", "Signature", "Signature-Input",
                ))
            ):
                try:
                    body, observation = server.input_compressor.compress_observed(body)
                    if usage_record is not None:
                        usage_record['compression'] = asdict(observation)
                        after_estimate = estimate_openai_request_input(json.loads(body))
                        if after_estimate:
                            usage_record['input_tokens_after_estimate'] = after_estimate.input_tokens
                except Exception:
                    # Compression is an optimization, never a generation gate.
                    server.note("error_count")
                    body = original_body
            # Count the exact body that will be forwarded, including preflight.
            self._observe_request(body, target, usage_record['request_id'] if usage_record else None)
            request_headers = {
                key: value
                for key, value in self.headers.items()
                if key.lower() not in _HOP_BY_HOP_HEADERS
                and key.lower() not in {"host", "content-length", "accept-encoding"}
            }
            # HTTPConnection computes Content-Length for the rewritten UTF-8
            # body. Signed/digested requests above retain their original bytes.
            # HTTP content encoding is independent of semantic token compression.
            request_headers["Accept-Encoding"] = "identity"
            connection = self._upstream_connection()
            connection.request(
                self.command,
                target,
                body=body if body else None,
                headers=request_headers,
            )
            response = connection.getresponse()
            if usage_record is not None:
                usage_record['http_status'] = response.status
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                lower = key.lower()
                if lower in _HOP_BY_HOP_HEADERS:
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True
            self.close_connection = True

            content_type = response.getheader("Content-Type", "").lower()
            if usage_record is not None:
                usage_record['response_content_type'] = content_type
                usage_record['response_content_encoding'] = response.getheader('Content-Encoding', 'identity').lower()
            def capture_usage(data: Mapping[str, Any], source: str) -> None:
                if usage_record is None:
                    return
                usage, model = provider_usage(dict(data))
                if usage is not None:
                    usage_record['official_usage'] = usage
                    usage_record['usage_source'] = source
                    if model:
                        usage_record['response_model'] = model
                if data.get('type') in {'response.failed', 'error'}:
                    usage_record['status'] = 'failed'
                elif data.get('type') == 'response.incomplete':
                    usage_record['status'] = 'incomplete'
            decoder = None
            # The authenticated Codex endpoint can omit Content-Type on SSE.
            # Use the explicit request stream flag in that case.
            if (server.on_sse_event is not None or usage_record is not None) and (
                "text/event-stream" in content_type or (not content_type and request_stream)):

                def observe_sse(
                    event_name: str,
                    data: Mapping[str, Any],
                ) -> None:
                    event_type = data.get("type") or event_name
                    capture_usage(data, 'provider_sse_usage')
                    if event_type != "response.function_call_arguments.delta":
                        return
                    if server.on_sse_event is None:
                        return
                    try:
                        server.on_sse_event(event_name, data)
                    except Exception:
                        server.note("error_count")
                        return
                    server.note("sse_event_count")

                decoder = SseDecoder(observe_sse)

            if self.command != "HEAD":
                json_response = bytearray()
                json_overflow = False
                while True:
                    reader = getattr(response, "read1", response.read)
                    chunk = reader(16 * 1024)
                    if not chunk:
                        break
                    if decoder is not None:
                        decoder.feed(chunk)
                    elif usage_record is not None and ('application/json' in content_type or not content_type) and not json_overflow:
                        json_response.extend(chunk)
                        if len(json_response) > 8 * 1024 * 1024:
                            json_response.clear(); json_overflow = True
                    self.wfile.write(chunk)
                    self.wfile.flush()
                if json_response and not json_overflow:
                    try:
                        data = json.loads(json_response)
                        if isinstance(data, dict):
                            capture_usage(data, 'provider_json_usage')
                    except (ValueError, UnicodeDecodeError):
                        pass
            if usage_record is not None and usage_record['status'] == 'pending':
                usage_record['status'] = 'completed' if 200 <= response.status < 300 else 'failed'
        except BrokenPipeError:
            server.note("error_count")
        except ConnectionError:
            server.note("error_count")
            self._send_bad_gateway(response_started=response_started)
        except Exception:
            server.note("error_count")
            self._send_bad_gateway(response_started=response_started)
        finally:
            if usage_record is not None:
                if usage_record['status'] == 'pending':
                    usage_record['status'] = 'interrupted'
                usage_record['latency_ms'] = round(1000 * (time.monotonic() - started), 3)
                server.usage_ledger.append(usage_record)
            if connection is not None:
                connection.close()


class RequestTokenTap:
    """Numeric loopback observer with optional, explicitly enabled input edits."""

    def __init__(
        self,
        upstream_base_url: str,
        *,
        on_input_estimate: Callable[[RequestInputEstimate], None] | None = None,
        on_sse_event: Callable[[str, Mapping[str, Any]], None] | None = None,
        timeout_s: float = 300.0,
        provider_count_timeout_s: float = 30.0,
        input_compressor: ResponsesInputCompressor | None = None,
        on_request_usage: Callable[[dict], None] | None = None,
    ) -> None:
        upstream = urlsplit(upstream_base_url.strip())
        if (
            upstream.scheme not in {"http", "https"}
            or not upstream.hostname
            or upstream.username is not None
            or upstream.password is not None
            or upstream.query
            or upstream.fragment
        ):
            raise ValueError(
                "request token tap upstream must be an http(s) base URL "
                "without credentials, query, or fragment"
            )
        if upstream.scheme == "http" and not _is_loopback_hostname(
            upstream.hostname
        ):
            raise ValueError(
                "request token tap upstream must use HTTPS unless the host "
                "is an explicit loopback address"
            )
        if timeout_s <= 0:
            raise ValueError("request token tap timeout must be positive")
        if provider_count_timeout_s <= 0:
            raise ValueError("provider count timeout must be positive")
        self.upstream = upstream
        self.on_input_estimate = on_input_estimate
        self.on_sse_event = on_sse_event
        self.timeout_s = timeout_s
        self.provider_count_timeout_s = provider_count_timeout_s
        self.input_compressor = input_compressor
        self.on_request_usage = on_request_usage
        self._server: _TapHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def local_base_url(self) -> str:
        server = self._server
        if server is None:
            raise RuntimeError("request token tap is not running")
        host, port = server.server_address[:2]
        path = self.upstream.path.rstrip("/")
        return f"http://{host}:{port}{path}"

    def start(self) -> RequestTokenTap:
        if self._server is not None:
            return self
        server = _TapHTTPServer(
            ("127.0.0.1", 0),
            upstream=self.upstream,
            on_input_estimate=self.on_input_estimate,
            on_sse_event=self.on_sse_event,
            timeout_s=self.timeout_s,
            provider_count_timeout_s=self.provider_count_timeout_s,
            input_compressor=self.input_compressor,
            on_request_usage=self.on_request_usage,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            name="codexscope-request-token-tap",
            daemon=True,
        )
        thread.start()
        try:
            # Besides checking readiness, this closes BaseServer's documented
            # shutdown-before-serve_forever race for immediate stop callers.
            host, port = server.server_address[:2]
            connection = http.client.HTTPConnection(host, port, timeout=5)
            try:
                connection.request("GET", _HEALTH_PATH)
                response = connection.getresponse()
                response.read()
                if response.status != 204:
                    raise RuntimeError("request token tap health check failed")
            finally:
                connection.close()
        except BaseException:
            server.server_close()
            thread.join(timeout=5)
            raise
        self._server = server
        self._thread = thread
        return self

    def stats_dict(self) -> dict[str, object]:
        server = self._server
        if server is None:
            return {
                "running": False,
                "request_count": 0,
                "observed_request_count": 0,
                "multimodal_request_count": 0,
                "provider_count_attempt_count": 0,
                "provider_count_success_count": 0,
                "provider_count_error_count": 0,
                "provider_breakdown_attempt_count": 0,
                "provider_breakdown_success_count": 0,
                "provider_breakdown_error_count": 0,
                "sse_event_count": 0,
                "error_count": 0,
            }
        with server.stats_lock:
            return {
                "running": True,
                "request_count": server.request_count,
                "observed_request_count": server.observed_request_count,
                "multimodal_request_count": server.multimodal_request_count,
                "provider_count_attempt_count": server.provider_count_attempt_count,
                "provider_count_success_count": server.provider_count_success_count,
                "provider_count_error_count": server.provider_count_error_count,
                "provider_breakdown_attempt_count": (
                    server.provider_breakdown_attempt_count
                ),
                "provider_breakdown_success_count": (
                    server.provider_breakdown_success_count
                ),
                "provider_breakdown_error_count": (
                    server.provider_breakdown_error_count
                ),
                "sse_event_count": server.sse_event_count,
                "error_count": server.error_count,
                "upstream_origin": (
                    f"{self.upstream.scheme}://{self.upstream.hostname}"
                    f"{f':{self.upstream.port}' if self.upstream.port else ''}"
                ),
                "upstream_path": self.upstream.path or "/",
                "usage_ledger": server.usage_ledger.snapshot(),
                **(
                    {"input_compression": self.input_compressor.stats()}
                    if self.input_compressor is not None else {}
                ),
            }

    def stop(self) -> dict[str, object]:
        server = self._server
        thread = self._thread
        if server is None:
            return self.stats_dict()
        server.stopping.set()
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        server.join_provider_threads(timeout_s=5)
        stats = self.stats_dict()
        self._server = None
        self._thread = None
        stats["running"] = False
        return stats
