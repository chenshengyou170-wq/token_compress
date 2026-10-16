"""Local SSE demo for a proposed cumulative token-usage event.

This module deliberately does not call OpenAI.  It starts a loopback mock
Responses server that owns scripted, authoritative decoder counters and emits a
proposed ``response.usage.updated`` event while a response is in progress.  A
small client consumes the stream and renders the counters without estimating.

Run it with::

    python -m codexscope.usage_stream_demo
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue
from typing import Any, BinaryIO, Iterable, Iterator, Mapping, Sequence, TextIO, cast
from urllib.request import Request, urlopen

from codexscope.proxy_usage import ProxyUsageMeter


class DemoProtocolError(ValueError):
    """The mock server or client observed an invalid usage-stream payload."""


def _non_negative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise DemoProtocolError(f"{field} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    """One authoritative cumulative usage snapshot from the model server."""

    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_tokens: int

    def __post_init__(self) -> None:
        for field, value in (
            ("input_tokens", self.input_tokens),
            ("cached_input_tokens", self.cached_input_tokens),
            ("output_tokens", self.output_tokens),
            ("reasoning_tokens", self.reasoning_tokens),
        ):
            _non_negative_int(value, field)
        if self.cached_input_tokens > self.input_tokens:
            raise DemoProtocolError("cached_input_tokens cannot exceed input_tokens")
        if self.reasoning_tokens > self.output_tokens:
            raise DemoProtocolError("reasoning_tokens cannot exceed output_tokens")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def as_wire(self) -> dict[str, Any]:
        """Return the same usage field names used by a Responses result."""

        return {
            "input_tokens": self.input_tokens,
            "input_tokens_details": {"cached_tokens": self.cached_input_tokens},
            "output_tokens": self.output_tokens,
            "output_tokens_details": {"reasoning_tokens": self.reasoning_tokens},
            "total_tokens": self.total_tokens,
        }

    @classmethod
    def from_wire(cls, value: object) -> UsageSnapshot:
        if not isinstance(value, Mapping):
            raise DemoProtocolError("usage must be an object")
        input_details = value.get("input_tokens_details")
        output_details = value.get("output_tokens_details")
        if not isinstance(input_details, Mapping):
            raise DemoProtocolError("input_tokens_details must be an object")
        if not isinstance(output_details, Mapping):
            raise DemoProtocolError("output_tokens_details must be an object")
        snapshot = cls(
            input_tokens=_non_negative_int(value.get("input_tokens"), "input_tokens"),
            cached_input_tokens=_non_negative_int(
                input_details.get("cached_tokens"), "cached_tokens"
            ),
            output_tokens=_non_negative_int(
                value.get("output_tokens"), "output_tokens"
            ),
            reasoning_tokens=_non_negative_int(
                output_details.get("reasoning_tokens"), "reasoning_tokens"
            ),
        )
        reported_total = _non_negative_int(value.get("total_tokens"), "total_tokens")
        if reported_total != snapshot.total_tokens:
            raise DemoProtocolError(
                "total_tokens must equal input_tokens + output_tokens"
            )
        return snapshot

    def assert_not_before(self, previous: UsageSnapshot) -> None:
        """Reject regressions in a cumulative stream."""

        current = (
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.reasoning_tokens,
        )
        older = (
            previous.input_tokens,
            previous.cached_input_tokens,
            previous.output_tokens,
            previous.reasoning_tokens,
        )
        if any(new < old for new, old in zip(current, older, strict=True)):
            raise DemoProtocolError("cumulative usage counters cannot decrease")


@dataclass(frozen=True, slots=True)
class SseEvent:
    event: str
    data: dict[str, Any]
    event_id: str | None = None

    def encode(self) -> bytes:
        payload = json.dumps(
            self.data, ensure_ascii=False, separators=(",", ":")
        )
        event_id = f"id: {self.event_id}\n" if self.event_id is not None else ""
        return f"{event_id}event: {self.event}\ndata: {payload}\n\n".encode()


def build_demo_events(response_id: str = "resp_usage_demo_001") -> list[SseEvent]:
    """Build a deterministic stream with hidden reasoning before visible text."""

    events: list[SseEvent] = []
    sequence_number = 0
    item_id = "msg_usage_demo_001"

    def append(event_type: str, payload: dict[str, Any]) -> None:
        nonlocal sequence_number
        data = {
            "type": event_type,
            "sequence_number": sequence_number,
            **payload,
        }
        events.append(
            SseEvent(event=event_type, data=data, event_id=str(sequence_number))
        )
        sequence_number += 1

    def append_usage(snapshot: UsageSnapshot) -> None:
        append(
            "response.usage.updated",
            {"response_id": response_id, "usage": snapshot.as_wire()},
        )

    append(
        "response.created",
        {
            "response": {
                "id": response_id,
                "object": "response",
                "status": "in_progress",
                "usage": None,
            }
        },
    )

    # The server knows the fully assembled input and cache result before output
    # decoding starts, so the first cumulative snapshot is already exact.
    input_tokens = 148
    cached_tokens = 64
    append_usage(UsageSnapshot(input_tokens, cached_tokens, 0, 0))

    # No output_text.delta is emitted during these ticks.  Only a provider-side
    # counter can reveal that hidden reasoning is consuming output tokens.
    for reasoning_tokens in (12, 25, 39, 52):
        append_usage(
            UsageSnapshot(
                input_tokens,
                cached_tokens,
                reasoning_tokens,
                reasoning_tokens,
            )
        )

    visible_segments = (
        ("服务端已经掌握", 6),
        ("累计 token 计数，", 7),
        ("即使还没有文本 delta，", 8),
        ("也能显示隐藏 reasoning 的增长。", 10),
    )
    output_tokens = 52
    text_parts: list[str] = []
    for delta, generated_tokens in visible_segments:
        text_parts.append(delta)
        append(
            "response.output_text.delta",
            {
                "response_id": response_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": delta,
            },
        )
        output_tokens += generated_tokens
        append_usage(
            UsageSnapshot(
                input_tokens,
                cached_tokens,
                output_tokens,
                52,
            )
        )

    # The final two output tokens represent server-visible message/channel
    # structure.  They are exact server counters but have no text delta.
    output_tokens += 2
    final_usage = UsageSnapshot(input_tokens, cached_tokens, output_tokens, 52)
    append_usage(final_usage)
    append(
        "response.completed",
        {
            "response": {
                "id": response_id,
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "id": item_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "".join(text_parts)}
                        ],
                    }
                ],
                "usage": final_usage.as_wire(),
            }
        },
    )
    return events


def build_proxy_demo_events(
    response_id: str = "resp_proxy_usage_demo_001",
) -> list[SseEvent]:
    """Build a remote-provider stream with no in-flight usage extension.

    These events intentionally contain only documented-style lifecycle and
    text-delta information.  The proxy must obtain input tokens separately,
    observe visible tokens from ``logprobs``, and wait for completion before it
    learns reasoning, cached-input, and total output usage.
    """

    events: list[SseEvent] = []
    sequence_number = 0
    item_id = "msg_proxy_usage_demo_001"
    model = "demo-remote-model"
    maximum_output_tokens = 160

    def append(event_type: str, payload: dict[str, Any]) -> None:
        nonlocal sequence_number
        data = {
            "type": event_type,
            "sequence_number": sequence_number,
            **payload,
        }
        events.append(
            SseEvent(event=event_type, data=data, event_id=str(sequence_number))
        )
        sequence_number += 1

    response_stub = {
        "id": response_id,
        "object": "response",
        "model": model,
        "status": "in_progress",
        "max_output_tokens": maximum_output_tokens,
        "usage": None,
    }
    append("response.created", {"response": response_stub})
    append("response.in_progress", {"response": response_stub})

    visible_segments = (
        ("远端 API 只提供可见 delta，", 8),
        ("代理并行精确计算输入，", 7),
        ("实时累计可观察 token，", 7),
        ("结束后再用官方 usage 校准。", 8),
    )
    text_parts: list[str] = []
    token_index = 0
    for delta, token_count in visible_segments:
        text_parts.append(delta)
        logprobs = []
        for _ in range(token_count):
            logprobs.append(
                {
                    "token": f"demo_token_{token_index}",
                    "logprob": -0.1,
                    "top_logprobs": [],
                }
            )
            token_index += 1
        append(
            "response.output_text.delta",
            {
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": delta,
                "logprobs": logprobs,
            },
        )

    final_usage = UsageSnapshot(
        input_tokens=148,
        cached_input_tokens=64,
        output_tokens=86,
        reasoning_tokens=52,
    )
    append(
        "response.completed",
        {
            "response": {
                **response_stub,
                "status": "completed",
                "output": [
                    {
                        "id": item_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "".join(text_parts)}
                        ],
                    }
                ],
                "usage": final_usage.as_wire(),
            }
        },
    )
    return events


def iter_sse_events(stream: BinaryIO) -> Iterator[SseEvent]:
    """Parse a minimal standards-compliant SSE stream."""

    event_name = "message"
    event_id: str | None = None
    data_lines: list[str] = []

    def finish_event() -> SseEvent | None:
        nonlocal event_name, event_id, data_lines
        if not data_lines:
            event_name = "message"
            event_id = None
            return None
        raw_data = "\n".join(data_lines)
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise DemoProtocolError("SSE data is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise DemoProtocolError("SSE data must decode to an object")
        event = SseEvent(event=event_name, data=parsed, event_id=event_id)
        event_name = "message"
        event_id = None
        data_lines = []
        return event

    for raw_line in stream:
        try:
            line = raw_line.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise DemoProtocolError("SSE stream is not UTF-8") from exc
        if not line:
            event = finish_event()
            if event is not None:
                yield event
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "id":
            event_id = value
        elif field == "data":
            data_lines.append(value)

    event = finish_event()
    if event is not None:
        yield event


@dataclass(slots=True)
class RunningUsageMeter:
    """Client reducer for cumulative, idempotent usage snapshots."""

    response_id: str | None = None
    phase: str = "connecting"
    usage: UsageSnapshot | None = None
    last_sequence_number: int = -1
    visible_chars: int = 0
    text_parts: list[str] | None = None
    completed: bool = False

    def __post_init__(self) -> None:
        if self.text_parts is None:
            self.text_parts = []

    @property
    def text(self) -> str:
        return "".join(self.text_parts or [])

    def consume(self, event: SseEvent) -> bool:
        event_type = event.data.get("type")
        if event_type != event.event:
            raise DemoProtocolError("SSE event name and data.type must match")
        sequence_number = _non_negative_int(
            event.data.get("sequence_number"), "sequence_number"
        )
        if sequence_number <= self.last_sequence_number:
            # Cumulative snapshots plus sequence numbers make replay harmless.
            return False
        self.last_sequence_number = sequence_number

        if event_type == "response.created":
            response = event.data.get("response")
            if not isinstance(response, Mapping) or not response.get("id"):
                raise DemoProtocolError("response.created is missing response.id")
            self.response_id = str(response["id"])
            self.phase = "waiting"
            return True

        if event_type == "response.usage.updated":
            self._check_response_id(event.data.get("response_id"))
            snapshot = UsageSnapshot.from_wire(event.data.get("usage"))
            previous = self.usage
            if previous is not None:
                snapshot.assert_not_before(previous)
            self.usage = snapshot
            if self.visible_chars:
                self.phase = "streaming"
            elif previous is not None and snapshot.reasoning_tokens > previous.reasoning_tokens:
                self.phase = "reasoning"
            else:
                self.phase = "waiting"
            return True

        if event_type == "response.output_text.delta":
            self._check_response_id(event.data.get("response_id"))
            delta = event.data.get("delta")
            if not isinstance(delta, str):
                raise DemoProtocolError("output_text.delta is missing delta text")
            cast(list[str], self.text_parts).append(delta)
            self.visible_chars += len(delta)
            self.phase = "streaming"
            return True

        if event_type == "response.completed":
            response = event.data.get("response")
            if not isinstance(response, Mapping):
                raise DemoProtocolError("response.completed is missing response")
            self._check_response_id(response.get("id"))
            final_usage = UsageSnapshot.from_wire(response.get("usage"))
            if self.usage is not None:
                final_usage.assert_not_before(self.usage)
            self.usage = final_usage
            self.phase = "completed"
            self.completed = True
            return True

        return False

    def _check_response_id(self, value: object) -> None:
        if self.response_id is None:
            raise DemoProtocolError("usage event arrived before response.created")
        if value != self.response_id:
            raise DemoProtocolError("event response_id does not match active response")

    def format_line(self, elapsed_s: float) -> str:
        if self.usage is None:
            counts = "in - | out - | total -"
            quality = "usage pending"
        else:
            counts = (
                f"in {self.usage.input_tokens} "
                f"(cached {self.usage.cached_input_tokens}) | "
                f"out {self.usage.output_tokens} "
                f"(reason {self.usage.reasoning_tokens}) | "
                f"total {self.usage.total_tokens}"
            )
            quality = "server exact/final" if self.completed else "server exact/live"
        return (
            f"{elapsed_s:5.2f}s  {self.phase:<10}  {counts} | "
            f"visible {self.visible_chars} chars | {quality}"
        )


class _DemoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        events: Iterable[SseEvent],
        delay_s: float,
        input_tokens: int,
        input_count_delay_s: float,
    ) -> None:
        self.events = tuple(events)
        self.delay_s = delay_s
        self.input_tokens = input_tokens
        self.input_count_delay_s = input_count_delay_s
        super().__init__(server_address, _DemoRequestHandler)


class _DemoRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path not in {"/v1/responses", "/v1/responses/input_tokens"}:
            self.send_error(404)
            return
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        if content_length:
            self.rfile.read(content_length)

        server = cast(_DemoHTTPServer, self.server)
        if self.path == "/v1/responses/input_tokens":
            if server.input_count_delay_s:
                time.sleep(server.input_count_delay_s)
            payload = json.dumps(
                {
                    "object": "response.input_tokens",
                    "input_tokens": server.input_tokens,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            self.close_connection = True
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        try:
            for event in server.events:
                self.wfile.write(event.encode())
                self.wfile.flush()
                if server.delay_s:
                    time.sleep(server.delay_s)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def start_demo_server(
    *,
    delay_s: float = 0.25,
    port: int = 0,
    events: Iterable[SseEvent] | None = None,
    input_tokens: int = 148,
    input_count_delay_s: float = 0.0,
) -> tuple[_DemoHTTPServer, threading.Thread, str]:
    """Start the loopback mock server and return ``(server, thread, url)``."""

    if delay_s < 0:
        raise ValueError("delay_s cannot be negative")
    if not 0 <= port <= 65_535:
        raise ValueError("port must be between 0 and 65535")
    _non_negative_int(input_tokens, "input_tokens")
    if input_count_delay_s < 0:
        raise ValueError("input_count_delay_s cannot be negative")
    server = _DemoHTTPServer(
        ("127.0.0.1", port),
        build_demo_events() if events is None else events,
        delay_s,
        input_tokens,
        input_count_delay_s,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        name="codexscope-usage-demo-server",
        daemon=True,
    )
    thread.start()
    actual_port = int(server.server_address[1])
    return server, thread, f"http://127.0.0.1:{actual_port}/v1/responses"


def stop_demo_server(server: _DemoHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def consume_demo_stream(
    url: str,
    *,
    mode: str = "interactive",
    output: TextIO = sys.stdout,
) -> RunningUsageMeter:
    """POST to the mock endpoint and consume its proposed usage events."""

    if mode not in {"interactive", "plain", "wire"}:
        raise ValueError("mode must be interactive, plain, or wire")
    request = Request(
        url,
        data=b'{"model":"demo-decoder","stream":true}',
        headers={"Accept": "text/event-stream", "Content-Type": "application/json"},
        method="POST",
    )
    meter = RunningUsageMeter()
    started = time.monotonic()
    with urlopen(request, timeout=10) as response:  # noqa: S310 - loopback demo URL
        for event in iter_sse_events(cast(BinaryIO, response)):
            changed = meter.consume(event)
            if mode == "wire":
                print(
                    json.dumps(
                        {
                            "event": event.event,
                            "id": event.event_id,
                            "data": event.data,
                        },
                        ensure_ascii=False,
                    ),
                    file=output,
                    flush=True,
                )
            elif changed:
                line = meter.format_line(time.monotonic() - started)
                if mode == "plain":
                    print(f"{event.event:<30} {line}", file=output, flush=True)
                else:
                    output.write(f"\r\033[K{line}")
                    output.flush()

    if mode == "interactive":
        output.write("\n")
    if not meter.completed:
        raise DemoProtocolError("stream ended before response.completed")
    return meter


def _input_tokens_url(responses_url: str) -> str:
    suffix = "/v1/responses"
    if not responses_url.endswith(suffix):
        raise ValueError(f"responses URL must end with {suffix}")
    return f"{responses_url}/input_tokens"


def consume_proxy_demo_stream(
    url: str,
    *,
    mode: str = "interactive",
    output: TextIO = sys.stdout,
    refresh_s: float = 0.10,
) -> ProxyUsageMeter:
    """Run token counting and a remote-style SSE request concurrently.

    The upstream stream has no custom usage updates.  Everything rendered
    before ``response.completed`` comes from the separate exact input count,
    observable delta/logprob data, or the explicitly labelled calibrator.
    """

    if mode not in {"interactive", "plain", "wire"}:
        raise ValueError("mode must be interactive, plain, or wire")
    if refresh_s <= 0:
        raise ValueError("refresh_s must be positive")

    base_payload = {
        "model": "demo-remote-model",
        "input": "演示远端 API 代理的进行中 token 估算。",
    }
    stream_payload = json.dumps(
        {
            **base_payload,
            "max_output_tokens": 160,
            "stream": True,
            "include": ["message.output_text.logprobs"],
            "top_logprobs": 0,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    count_payload = json.dumps(base_payload, separators=(",", ":")).encode(
        "utf-8"
    )
    messages: Queue[tuple[str, object]] = Queue()

    def count_input() -> None:
        request = Request(
            _input_tokens_url(url),
            data=count_payload,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:  # noqa: S310 - loopback
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload, Mapping):
                raise DemoProtocolError("input-token response must be an object")
            count = _non_negative_int(payload.get("input_tokens"), "input_tokens")
            messages.put(("input_count", count))
        except Exception as exc:  # Forward worker failures to the caller.
            messages.put(("error", exc))
        finally:
            messages.put(("count_done", None))

    def read_stream() -> None:
        request = Request(
            url,
            data=stream_payload,
            headers={
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:  # noqa: S310 - loopback
                for event in iter_sse_events(cast(BinaryIO, response)):
                    messages.put(("stream_event", event))
        except Exception as exc:  # Forward worker failures to the caller.
            messages.put(("error", exc))
        finally:
            messages.put(("stream_done", None))

    count_thread = threading.Thread(
        target=count_input,
        name="codexscope-proxy-input-counter",
        daemon=True,
    )
    stream_thread = threading.Thread(
        target=read_stream,
        name="codexscope-proxy-stream-reader",
        daemon=True,
    )
    meter = ProxyUsageMeter(model=str(base_payload["model"]))
    started = time.monotonic()
    count_done = False
    stream_done = False
    last_status_key: tuple[object, ...] | None = None
    count_thread.start()
    stream_thread.start()
    try:
        while not (count_done and stream_done):
            try:
                message_type, payload = messages.get(timeout=refresh_s)
            except Empty:
                message_type, payload = "tick", None

            elapsed_s = time.monotonic() - started
            event_label = "proxy.estimator.tick"
            wire_payload: dict[str, Any] | None = None
            if message_type == "input_count":
                meter.set_exact_input_tokens(payload)
                event_label = "proxy.input_tokens.counted"
                wire_payload = {
                    "event": event_label,
                    "data": {
                        "input_tokens": meter.preflight_input_tokens,
                        "quality": "provider exact/preflight",
                    },
                }
            elif message_type == "stream_event":
                if not isinstance(payload, SseEvent):
                    raise DemoProtocolError("stream worker returned an invalid event")
                meter.consume(payload.event, payload.data, elapsed_s=elapsed_s)
                event_label = payload.event
                wire_payload = {
                    "event": payload.event,
                    "id": payload.event_id,
                    "data": payload.data,
                }
            elif message_type == "count_done":
                count_done = True
            elif message_type == "stream_done":
                stream_done = True
            elif message_type == "error":
                if isinstance(payload, BaseException):
                    raise payload
                raise DemoProtocolError("proxy worker failed without an exception")

            if mode == "wire":
                if wire_payload is not None:
                    print(
                        json.dumps(wire_payload, ensure_ascii=False),
                        file=output,
                        flush=True,
                    )
                continue

            status_key = meter.status_key(elapsed_s)
            if mode == "interactive":
                output.write(f"\r\033[K{meter.format_line(elapsed_s)}")
                output.flush()
            elif status_key != last_status_key or message_type == "input_count":
                print(
                    f"{event_label:<30} {meter.format_line(elapsed_s)}",
                    file=output,
                    flush=True,
                )
            last_status_key = status_key
    finally:
        count_thread.join(timeout=2.0)
        stream_thread.join(timeout=2.0)

    if mode == "interactive":
        output.write("\n")
    if not meter.completed:
        raise DemoProtocolError("stream ended before response.completed")
    return meter


def _delay(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _positive_delay(value: str) -> float:
    parsed = _delay(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 0 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m codexscope.usage_stream_demo",
        description=(
            "Compare provider-side exact cumulative usage with a remote-API "
            "proxy estimator using a loopback Responses server."
        ),
    )
    parser.add_argument(
        "--proxy",
        action="store_true",
        help=(
            "simulate a remote API with no in-flight usage event; combine exact "
            "input counting, observed output, and a calibrated hidden interval"
        ),
    )
    parser.add_argument(
        "--delay",
        type=_delay,
        default=0.25,
        help="seconds between mock SSE events (default: 0.25)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=0,
        help="loopback port; 0 chooses an ephemeral port (default: 0)",
    )
    parser.add_argument(
        "--refresh",
        type=_positive_delay,
        default=0.10,
        help="proxy status refresh interval in seconds (default: 0.10)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plain",
        action="store_true",
        help="print one readable status line per event",
    )
    mode.add_argument(
        "--wire",
        action="store_true",
        help="print received SSE events as JSON Lines",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    mode = "wire" if args.wire else "plain" if args.plain else "interactive"
    server: _DemoHTTPServer | None = None
    thread: threading.Thread | None = None
    try:
        events = build_proxy_demo_events() if args.proxy else build_demo_events()
        server, thread, url = start_demo_server(
            delay_s=args.delay,
            port=args.port,
            events=events,
            input_tokens=148,
            input_count_delay_s=args.delay * 0.60 if args.proxy else 0.0,
        )
        if args.proxy:
            print(
                "Proxy mode: upstream sends no mid-request usage; exact input, "
                "observed output, and estimated hidden output stay distinct."
            )
        else:
            print(
                "Demo protocol only: response.usage.updated is proposed, not a "
                "currently documented OpenAI event."
            )
        print(f"mock endpoint: {url}")
        if args.proxy:
            meter = consume_proxy_demo_stream(
                url,
                mode=mode,
                refresh_s=args.refresh,
            )
        else:
            meter = consume_demo_stream(url, mode=mode)
        if mode != "wire":
            print(f"final text: {meter.text}")
            if args.proxy and meter.calibration_residual is not None:
                print(
                    "calibration sample: official output - observed output = "
                    f"{meter.calibration_residual} hidden/format tokens"
                )
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    finally:
        if server is not None and thread is not None:
            stop_demo_server(server, thread)


if __name__ == "__main__":
    raise SystemExit(main())
