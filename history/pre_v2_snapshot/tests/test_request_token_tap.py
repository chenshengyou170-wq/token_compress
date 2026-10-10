from __future__ import annotations

import base64
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codexscope.request_token_tap import (
    RequestTokenTap,
    SseDecoder,
    estimate_openai_request_input,
)


def _compact(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_full_responses_request_estimate_includes_model_visible_structure():
    body = {
        "model": "gpt-5.4",
        "instructions": "You are a coding agent.",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Fix the test"}],
            }
        ],
        "tools": [
            {
                "type": "function",
                "name": "write_file",
                "parameters": {
                    "type": "object",
                    "properties": {"data": {"type": "string"}},
                },
            }
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "result",
                "schema": {"type": "object"},
            },
            "verbosity": "low",
        },
        "reasoning": {"effort": "high"},
        "stream": True,
    }
    selected = {
        "instructions": body["instructions"],
        "input": body["input"],
        "tools": body["tools"],
        "output_format": body["text"]["format"],
    }

    estimate = estimate_openai_request_input(
        body,
        token_counter=len,
        token_counter_source="character-test",
    )

    assert estimate is not None
    assert estimate.input_tokens == len(_compact(selected))
    assert estimate.model == "gpt-5.4"
    assert estimate.source == "request-body/character-test"
    assert estimate.context_complete is True
    assert estimate.component_tokens == {
        "input": len(_compact(body["input"])),
        "instructions": len(body["instructions"]),
        "output_format": len(_compact(body["text"]["format"])),
        "tools": len(_compact(body["tools"])),
    }

    changed_control = {**body, "reasoning": {"effort": "minimal"}, "stream": False}
    changed = estimate_openai_request_input(
        changed_control,
        token_counter=len,
        token_counter_source="character-test",
    )
    assert changed is not None
    assert changed.input_tokens == estimate.input_tokens


def test_remote_or_non_text_request_context_is_explicitly_partial():
    counted_text: list[str] = []

    def count_characters(text: str) -> int:
        counted_text.append(text)
        return len(text)

    estimate = estimate_openai_request_input(
        {
            "model": "gpt-5.4",
            "previous_response_id": "resp_previous",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_image",
                            "image_url": "data:image/png;base64,very-secret-image",
                        },
                        {
                            "type": "input_audio",
                            "input_audio": {
                                "data": "very-secret-audio",
                                "format": "wav",
                            },
                        },
                    ],
                }
            ],
        },
        token_counter=count_characters,
        token_counter_source="character-test",
    )

    assert estimate is not None
    assert estimate.context_complete is False
    assert estimate.modality_counts == {"image": 1, "audio": 1}
    assert all("very-secret-image" not in text for text in counted_text)
    assert all("very-secret-audio" not in text for text in counted_text)


def test_inline_image_adds_documented_gpt56_patch_estimate() -> None:
    png_header = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (1191).to_bytes(4, "big")
        + (1684).to_bytes(4, "big")
    )
    image_url = "data:image/png;base64," + base64.b64encode(png_header).decode()

    estimate = estimate_openai_request_input(
        {
            "model": "gpt-5.6-sol",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_image", "image_url": image_url},
                        {"type": "input_text", "text": "Read this page"},
                    ],
                }
            ],
        },
        token_counter=len,
        token_counter_source="character-test",
    )

    assert estimate is not None
    assert estimate.multimodal_input_tokens == 2_014
    assert estimate.multimodal_input_quality == "local_estimate"
    assert estimate.component_tokens["image_input_estimate"] == 2_014
    assert estimate.input_tokens > 2_014
    assert estimate.context_complete is False


def test_sse_decoder_handles_chunk_boundaries_and_multiline_data():
    observed: list[tuple[str, dict]] = []
    decoder = SseDecoder(lambda name, data: observed.append((name, dict(data))))
    payload = (
        b"event: response.function_call_arguments.delta\r\n"
        b'data: {"type":"response.function_call_arguments.delta",\r\n'
        b'data: "item_id":"call-1","delta":"{}"}\r\n\r\n'
    )
    for split in (payload[:17], payload[17:61], payload[61:]):
        decoder.feed(split)

    assert observed == [
        (
            "response.function_call_arguments.delta",
            {
                "type": "response.function_call_arguments.delta",
                "item_id": "call-1",
                "delta": "{}",
            },
        )
    ]


def test_request_token_tap_relays_bytes_and_emits_numeric_observations():
    upstream_requests: list[dict] = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            upstream_requests.append(
                {
                    "path": self.path,
                    "body": body,
                    "authorization": self.headers.get("Authorization"),
                    "accept_encoding": self.headers.get("Accept-Encoding"),
                }
            )
            events = (
                b"event: response.function_call_arguments.delta\n"
                b'data: {"type":"response.function_call_arguments.delta",'
                b'"item_id":"call-1","delta":"{\\"command\\":"}\n\n'
                b"event: response.function_call_arguments.delta\n"
                b'data: {"type":"response.function_call_arguments.delta",'
                b'"item_id":"call-1","delta":"\\"pytest\\"}"}\n\n'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(events)))
            self.end_headers()
            self.wfile.write(events[:41])
            self.wfile.flush()
            self.wfile.write(events[41:])
            self.wfile.flush()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    estimates = []
    sse_events: list[tuple[str, dict]] = []
    upstream_host, upstream_port = upstream.server_address[:2]
    tap = RequestTokenTap(
        f"http://{upstream_host}:{upstream_port}/v1",
        on_input_estimate=estimates.append,
        on_sse_event=lambda name, data: sse_events.append((name, dict(data))),
    ).start()
    try:
        local = tap.local_base_url.removeprefix("http://")
        local_host_port, local_path = local.split("/", 1)
        local_host, local_port = local_host_port.rsplit(":", 1)
        request_body = json.dumps(
            {
                "model": "gpt-5.4",
                "instructions": "Keep this body private",
                "input": [{"role": "user", "content": "Run tests"}],
                "tools": [{"type": "function", "name": "shell"}],
                "stream": True,
            }
        ).encode()
        connection = http.client.HTTPConnection(local_host, int(local_port), timeout=3)
        try:
            connection.request(
                "POST",
                f"/{local_path}/responses",
                body=request_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer fake-test-token",
                },
            )
            response = connection.getresponse()
            response_body = response.read()
        finally:
            connection.close()

        assert response.status == 200
        assert b"response.function_call_arguments.delta" in response_body
        assert upstream_requests == [
            {
                "path": "/v1/responses",
                "body": request_body,
                "authorization": "Bearer fake-test-token",
                "accept_encoding": "identity",
            }
        ]
        assert len(estimates) == 1
        assert estimates[0].input_tokens > 0
        assert estimates[0].component_tokens.keys() == {
            "input",
            "instructions",
            "tools",
        }
        assert len(sse_events) == 2
        assert all(
            name == "response.function_call_arguments.delta"
            for name, _data in sse_events
        )

        rejected = http.client.HTTPConnection(
            local_host,
            int(local_port),
            timeout=3,
        )
        try:
            rejected.request("GET", "/outside-configured-base")
            rejected_response = rejected.getresponse()
            rejected_response.read()
        finally:
            rejected.close()
        assert rejected_response.status == 502
        assert len(upstream_requests) == 1

        stats = tap.stats_dict()
        assert stats["request_count"] == 2
        assert stats["observed_request_count"] == 1
        assert stats["sse_event_count"] == 2
        assert stats["error_count"] == 1
        assert "Keep this body private" not in json.dumps(stats)
    finally:
        stopped = tap.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)
    assert stopped["running"] is False


def test_request_token_tap_upgrades_pdf_input_to_provider_exact_count():
    upstream_requests: list[dict] = []

    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            payload = json.loads(raw)
            upstream_requests.append(
                {
                    "path": self.path,
                    "payload": payload,
                    "authorization": self.headers.get("Authorization"),
                }
            )
            if self.path == "/v1/responses/input_tokens":
                serialized = json.dumps(payload)
                count = 1_200 if "input_file" in serialized else 200
                response_body = json.dumps(
                    {
                        "object": "response.input_tokens",
                        "input_tokens": count,
                    }
                ).encode()
            else:
                response_body = b'{"id":"resp-test","status":"completed"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    estimates = []
    breakdown_ready = threading.Event()

    def observe(estimate) -> None:
        estimates.append(estimate)
        if estimate.multimodal_input_tokens is not None:
            breakdown_ready.set()

    upstream_host, upstream_port = upstream.server_address[:2]
    tap = RequestTokenTap(
        f"http://{upstream_host}:{upstream_port}/v1",
        on_input_estimate=observe,
        provider_count_timeout_s=3,
    ).start()
    try:
        local = tap.local_base_url.removeprefix("http://")
        local_host_port, local_path = local.split("/", 1)
        local_host, local_port = local_host_port.rsplit(":", 1)
        request_payload = {
            "model": "gpt-5.4",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_file",
                            "filename": "analysis.pdf",
                            "file_data": (
                                "data:application/pdf;base64,private-pdf-data"
                            ),
                        },
                        {"type": "input_text", "text": "Summarize it"},
                    ],
                }
            ],
            "stream": True,
            "store": False,
            "max_output_tokens": 64,
            "include": ["reasoning.encrypted_content"],
            # Input-bearing fields that are not generation controls must be
            # forwarded rather than silently omitted from an "exact" count.
            "prompt": {"id": "pmpt-test", "variables": {"topic": "PDF"}},
            "future_input_control": {"mode": "test"},
        }
        request_body = json.dumps(request_payload).encode()
        connection = http.client.HTTPConnection(
            local_host,
            int(local_port),
            timeout=3,
        )
        try:
            connection.request(
                "POST",
                f"/{local_path}/responses",
                body=request_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer fake-test-token",
                },
            )
            response = connection.getresponse()
            response.read()
        finally:
            connection.close()

        assert response.status == 200
        assert breakdown_ready.wait(3), "provider PDF token breakdown did not arrive"
        local_estimate = estimates[0]
        exact_estimate = estimates[-1]
        assert local_estimate.context_complete is False
        assert local_estimate.modality_counts == {"pdf": 1}
        assert local_estimate.provider_count_status == "pending"
        assert exact_estimate.source == "provider_preflight_exact"
        assert exact_estimate.context_complete is True
        assert exact_estimate.request_id == local_estimate.request_id
        assert exact_estimate.input_tokens == 1_200
        assert exact_estimate.text_input_tokens == 200
        assert exact_estimate.multimodal_input_tokens == 1_000
        assert exact_estimate.provider_count_latency_ms is not None
        assert exact_estimate.provider_count_status == "exact_with_breakdown"

        count_requests = [
            item
            for item in upstream_requests
            if item["path"] == "/v1/responses/input_tokens"
        ]
        generation_requests = [
            item for item in upstream_requests if item["path"] == "/v1/responses"
        ]
        assert len(count_requests) == 2
        assert len(generation_requests) == 1
        expected_count_payload = {
            key: value
            for key, value in request_payload.items()
            if key not in {"stream", "store", "max_output_tokens", "include"}
        }
        assert count_requests[0]["payload"] == expected_count_payload
        assert "private-pdf-data" not in json.dumps(count_requests[1]["payload"])
        assert generation_requests[0]["payload"] == request_payload
        assert all(
            item["authorization"] == "Bearer fake-test-token"
            for item in upstream_requests
        )
        stats = tap.stats_dict()
        assert stats["multimodal_request_count"] == 1
        assert stats["provider_count_success_count"] == 1
        assert stats["provider_breakdown_success_count"] == 1
        assert "private-pdf-data" not in json.dumps(stats)
    finally:
        tap.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_pdf_provider_count_failure_is_fail_open_and_reported():
    class UpstreamHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if self.path == "/v1/responses/input_tokens":
                response_body = b'{"error":"unsupported"}'
                self.send_response(404)
            else:
                response_body = b'{"id":"resp-test","status":"completed"}'
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    estimates = []
    failure_ready = threading.Event()

    def observe(estimate) -> None:
        estimates.append(estimate)
        if estimate.provider_count_status == "unavailable":
            failure_ready.set()

    upstream_host, upstream_port = upstream.server_address[:2]
    tap = RequestTokenTap(
        f"http://{upstream_host}:{upstream_port}/v1",
        on_input_estimate=observe,
        provider_count_timeout_s=3,
    ).start()
    try:
        local = tap.local_base_url.removeprefix("http://")
        local_host_port, local_path = local.split("/", 1)
        local_host, local_port = local_host_port.rsplit(":", 1)
        request_body = json.dumps(
            {
                "model": "gpt-5.4",
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "input_file",
                                "filename": "analysis.pdf",
                                "file_id": "file-test",
                            }
                        ],
                    }
                ],
            }
        ).encode()
        connection = http.client.HTTPConnection(
            local_host,
            int(local_port),
            timeout=3,
        )
        try:
            connection.request(
                "POST",
                f"/{local_path}/responses",
                body=request_body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
        finally:
            connection.close()

        assert response.status == 200
        assert failure_ready.wait(3), "provider count failure was not reported"
        assert estimates[0].provider_count_status == "pending"
        assert estimates[-1].provider_count_status == "unavailable"
        assert all(
            estimate.source != "provider_preflight_exact" for estimate in estimates
        )
        stats = tap.stats_dict()
        assert stats["provider_count_attempt_count"] == 1
        assert stats["provider_count_success_count"] == 0
        assert stats["provider_count_error_count"] == 1
    finally:
        tap.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


@pytest.mark.parametrize(
    "value",
    [
        "file:///tmp/provider",
        "https://user:secret@example.test/v1",
        "http://provider.example/v1",
    ],
)
def test_request_token_tap_rejects_unsafe_upstream_urls(value: str):
    with pytest.raises(ValueError, match="upstream"):
        RequestTokenTap(value)


@pytest.mark.parametrize('mode,endpoint,encoding,should_change', [
    ('off', '/v1/responses', '', False),
    ('caveman', '/v1/responses', '', True),
    ('caveman', '/v1/responses/compact', '', False),
    ('caveman', '/v1/chat/completions', '', False),
    ('caveman', '/v1/responses', 'gzip', False),
    ('broken', '/v1/responses', '', False),
    ('signed', '/v1/responses', '', False),
])
def test_input_compression_is_applied_before_observation_and_forwarding(mode, endpoint, encoding, should_change):
    import gzip
    from urllib.parse import urlsplit
    from codexscope.input_compression import ResponsesInputCompressor

    observed = []
    estimates = []
    reply = b'data: {"type":"response.completed"}\n\n'

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers['Content-Length'])
            body = self.rfile.read(length)
            observed.append((body, dict(self.headers)))
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    compressor = None if mode == 'off' else ResponsesInputCompressor(token_counter=len)
    if mode == 'broken':
        def fail(_raw):
            raise RuntimeError('test compressor failure')
        compressor.compress_observed = fail
    body = {
        'model': 'test', 'instructions': 'Please check the context in order to act.',
        'input': [{'role': 'user', 'content': 'Please read the report. 请你进行核对，不得上传。'}],
        'tools': [{'type': 'function', 'name': 'the_tool', 'description': 'the exact schema'}],
        'stream': True,
    }
    raw = json.dumps(body, ensure_ascii=False, indent=2).encode()
    if encoding:
        raw = gzip.compress(raw)
    tap = RequestTokenTap(
        f'http://127.0.0.1:{server.server_port}/v1',
        input_compressor=compressor, on_input_estimate=estimates.append,
    ).start()
    try:
        local = urlsplit(tap.local_base_url)
        connection = http.client.HTTPConnection(local.hostname, local.port, timeout=5)
        connection.request('POST', endpoint, body=raw, headers={
            'Content-Type': 'application/json', 'Content-Encoding': encoding or 'identity',
            'Authorization': 'Bearer fake-test-token',
            **({'Content-MD5': 'old-entity-digest'} if mode == 'signed' else {}),
        })
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == reply
        connection.close()
        received, headers = observed[0]
        assert (received != raw) == should_change
        assert int(headers['Content-Length']) == len(received)
        assert headers['Authorization'] == 'Bearer fake-test-token'
        if should_change:
            assert 'Content-MD5' not in headers
            payload = json.loads(received)
            assert payload['tools'] == body['tools']
            assert '不得上传' in payload['input'][0]['content']
            assert estimates[0].input_tokens == estimate_openai_request_input(payload).input_tokens
            assert tap.stats_dict()['input_compression']['compressed_requests'] == 1
        elif mode == 'signed':
            assert headers['Content-MD5'] == 'old-entity-digest'
    finally:
        tap.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
