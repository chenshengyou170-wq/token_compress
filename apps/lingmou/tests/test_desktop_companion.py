"""Desktop integration uses temporary Codex configs and synthetic providers only."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest

from codexscope.desktop_companion import Companion, DesktopCompressor, _source_available, remote_configuration
from codexscope.desktop_connection import CodexConnection, ConnectionError
from codexscope.reference_selection import SourceStore


SERVER = "lingmou_desktop_sources_test"
READER = {"type": "function", "name": f"mcp__{SERVER}__lingmou_source_read",
          "parameters": {"type": "object", "properties": {"source_id": {"type": "string"}}}}


@pytest.fixture(autouse=True)
def isolate_remote_environment(monkeypatch):
    for key in ("KIMI_API_KEY", "MOONSHOT_API_KEY", "KIMI_API_KEY_FILE", "TYPESAFE_API_KEY",
                "LINGMOU_LLMLINGUA_MODEL", "LINGMOU_CAVEMAN_PATH", "LINGMOU_MLM_MODEL"):
        monkeypatch.delenv(key, raising=False)


def request_body():
    # Large repeating field names produce a measurable local budget for the
    # optional rewrite. The task and schema must survive every compression mode.
    material = json.dumps([{"warehouse_region_identifier": f"region-{i}",
                            "warehouse_inventory_description": "stable inventory",
                            "warehouse_inventory_quantity": 100} for i in range(500)])
    return {"model": "test", "instructions": "Never execute payments.", "tools": [READER],
            "input": [{"role": "user", "content": "Check inventory; keep quantity 100."},
                      {"type": "function_call", "call_id": "c1", "name": "inventory", "arguments": '{ "limit": 100 }'},
                      {"type": "function_call_output", "call_id": "c1", "output": material}],
            "text": {"format": {"type": "json_schema", "name": "result", "schema": {"const": False}}}}


@pytest.mark.parametrize("body", [
    {"tools": [READER]},
    {"input": [{"type": "additional_tools", "tools": [READER]}]},
    {"input": [{"additional_tools": {"tools": [READER]}}]},
    {"tools": [{"type": "namespace", "name": f"mcp.{SERVER}", "tools": [
        {"type": "function", "name": "lingmou_source_read"}]}]},
    {"tools": [{"type": "function", "function": {"name": READER["name"]}}]},
])
def test_current_connection_reader_is_recognized_in_all_supported_locations(body):
    assert _source_available(body, SERVER)
    assert not _source_available(body, "lingmou_desktop_sources_other")
    assert not _source_available(body, "desktop_sources_test")


def test_full_without_reader_only_uses_structure_and_does_not_archive(tmp_path, monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "synthetic-key")
    monkeypatch.setenv("TYPESAFE_API_KEY", "synthetic-key")
    compressor = DesktopCompressor("full", SourceStore(tmp_path), SERVER, remote_enabled=True, token_counter=len)
    body = request_body()
    body["tools"] = []
    body["instructions"] = "Preserve every instruction. " * 20
    sent, observation = compressor.compress_observed(json.dumps(body).encode())
    got = json.loads(sent)
    assert got["instructions"] == body["instructions"] and got["input"][0] == body["input"][0]
    assert got["text"] == body["text"]
    assert observation.reason == "source_tool_unavailable"
    assert not observation.compression_calls and not list(tmp_path.glob("*.txt"))
    assert compressor.stats()["last_mode"] == "structure"


def test_full_local_ignores_ambient_remote_flags_and_preserves_recoverable_history(tmp_path, monkeypatch):
    for key, value in {"KIMI_API_KEY": "synthetic-key", "TYPESAFE_API_KEY": "synthetic-key",
                       "LINGMOU_FULL_ALLOW_UNFUNDED_REMOTE": "1", "LINGMOU_FULL_OUTPUT_REWRITE": "1",
                       "LINGMOU_FULL_STARTUP_REMOTE_TOKENS": "999999"}.items():
        monkeypatch.setenv(key, value)
    import codexscope.full_compression as full
    def forbidden(*args, **kwargs):
        pytest.fail("Local desktop mode must not invoke remote or optional model backends")
    monkeypatch.setattr(full.FullCompressionPipeline, "_rewrite_batch", forbidden)
    monkeypatch.setattr(full.FullCompressionPipeline, "_verify_batch", forbidden)
    monkeypatch.setattr(full.FullCompressionPipeline, "_backend", forbidden)
    store = SourceStore(tmp_path)
    compressor = DesktopCompressor("full", store, SERVER, token_counter=len)
    body = {"tools": [READER], "instructions": "Never delete files.", "input": []}
    # Whole old turns are archived only at a session checkpoint above the
    # history watermark, so this history must exceed it.
    for i in range(10):
        body["input"] += [{"role": "user", "content": f"Task {i}"},
                          {"role": "assistant", "content": f"Earlier evidence {i}. " * 700}]
    sent, observation = compressor.compress_observed(json.dumps(body).encode())
    got = json.loads(sent)
    assert observation.status == "compressed" and not observation.compression_calls
    assert got["instructions"] == body["instructions"] and got["tools"] == body["tools"]
    kept = [item["content"] for item in got["input"] if item.get("role") == "user"]
    assert 2 <= len(kept) < 10 and kept == [f"Task {i}" for i in range(10 - len(kept), 10)]
    removed = 2 * (10 - len(kept))
    assert any(json.loads(path.read_text()) == body["input"][:removed] for path in tmp_path.glob("*.txt"))
    assert observation.cache_prefix["checkpoint"]["archived_messages"] == removed
    assert compressor.stats()["last_mode"] == "full"


@pytest.mark.parametrize("accept", [True, False])
def test_remote_rewrite_requires_verification_and_records_additional_usage(monkeypatch, tmp_path, accept):
    import codexscope.full_compression as full
    monkeypatch.setenv("KIMI_API_KEY", "synthetic-kimi")
    monkeypatch.setenv("TYPESAFE_API_KEY", "synthetic-jev")
    captured = []
    short = "Record widget status, reconcile inventory and report discrepancies."
    class Kimi:
        def __init__(self, **kwargs): pass
        def chat(self, messages, **kwargs):
            segments = json.loads(messages[-1]["content"])
            captured.append("kimi")
            return {"text": json.dumps({key: short for key in segments}), "finish_reason": "stop",
                    "model": "fake-kimi", "usage": {"input_tokens": 80, "output_tokens": 20, "total_tokens": 100}}
    class Verifier:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def post(self, url, **kwargs):
            captured.append("jev")
            request = kwargs["json"]
            assert url == "https://api.typesafe.ai/v1/systemone"
            assert all(question["type"] == "noul" for question in request["questions"].values())
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {
                "model": "fake-jev", "answers": {key: {"type": "noul", "noul": .99 if accept else .1}
                                                for key in request["questions"]},
                "usage": {"input_tokens": 90, "output_tokens": 10}})
    monkeypatch.setattr(full, "KimiClient", Kimi)
    monkeypatch.setattr(full, "httpx", SimpleNamespace(Client=Verifier))
    compressor = DesktopCompressor("full", SourceStore(tmp_path), SERVER, remote_enabled=True, token_counter=len)
    body = request_body()
    body["instructions"] = (short + " ") * 6
    sent, observation = compressor.compress_observed(json.dumps(body).encode())
    got = json.loads(sent)
    assert captured == ["kimi", "jev"]
    assert got["instructions"] == (short if accept else body["instructions"])
    assert got["input"][0] == body["input"][0] and got["tools"] == body["tools"]
    assert got["text"] == body["text"]
    assert sum(call["official_usage"]["total_tokens"] for call in observation.compression_calls) == 200
    assert len(observation.compression_calls) <= 4
    # A new request has no startup allowance, even when credentials are present.
    captured.clear()
    no_savings = {"tools": [READER], "instructions": body["instructions"], "input": "Check inventory."}
    for _ in range(2):
        raw = json.dumps(no_savings).encode()
        assert compressor.compress_observed(raw)[0] == raw
    assert not captured
    compressor.set_mode("full", remote_enabled=False)
    compressor.compress_observed(json.dumps(body).encode())
    assert not captured


def test_configuration_reports_presence_without_exposing_credentials(tmp_path, monkeypatch):
    assert remote_configuration() == {"kimi_configured": False, "jev_configured": False, "ready": False}
    monkeypatch.setenv("KIMI_API_KEY_FILE", str(tmp_path / "missing"))
    assert not remote_configuration()["kimi_configured"]
    monkeypatch.setenv("MOONSHOT_API_KEY", "synthetic-secret")
    monkeypatch.setenv("TYPESAFE_API_KEY", "synthetic-secret")
    status = Companion(tmp_path / "state").status()
    assert status["remote_configuration"]["ready"]
    assert "synthetic-secret" not in json.dumps(status)


def test_configuration_round_trip_and_legacy_remote_default(tmp_path):
    target = tmp_path / "中文 配置.toml"
    original = b'# Keep this comment.\nmodel = "test"\n'
    target.write_bytes(original)
    connection = CodexConnection(tmp_path / "state")
    arguments = dict(path=str(target), auth_kind="api", upstream="", mode="full",
                     source_command="python", source_args=["sources"])
    with pytest.raises(ConnectionError, match="布尔"):
        connection.prepare(**arguments, remote_enabled="true")
    connection.prepare(**arguments, remote_enabled=True)
    connection.apply(12345)
    reopened = CodexConnection(connection.root)
    assert reopened.public()["mode"] == "full" and reopened.public()["remote_enabled"]
    assert "access_token" not in reopened.public()
    reopened.restore()
    assert target.read_bytes() == original
    reopened.record.pop("remote_enabled")
    reopened._save()
    assert CodexConnection(connection.root).public()["remote_enabled"] is False


def test_relay_mode_switch_restart_usage_and_restore(tmp_path, monkeypatch):
    received = []
    wire = b'data: {"type":"response.completed","response":{"usage":{"input_tokens":123,"output_tokens":4,"total_tokens":127}}}\n\n'
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = tmp_path / "config.toml"
    original = b'model = "test"\n'
    target.write_bytes(original)
    companion = Companion(tmp_path / "state")
    try:
        companion.connect(config_path=str(target), auth_kind="api", upstream=f"http://127.0.0.1:{server.server_port}/v1",
                          mode="full", remote_enabled=True)
        body = request_body()
        body["client_metadata"] = {"thread_id": "desktop-test", "turn_id": "turn-1"}
        body["tools"] = [{**READER, "name": f'mcp__{companion.connection.record["source_server"]}__lingmou_source_read'}]
        for mode in ("full", "off"):
            companion.set_mode(mode)
            response = httpx.post(companion.tap.local_base_url + "/responses", json=body,
                                  headers={"X-Lingmou-Relay-Token": companion.connection.record["access_token"]}, trust_env=False)
            assert response.status_code == 200 and response.content == wire
        assert received[0]["input"][-1]["output"] != body["input"][-1]["output"]
        assert received[1] == body
        # The relay records usage after the response body reaches the client.
        deadline = time.monotonic() + 2
        while (status := companion.status())["tokens"]["official"]["total_tokens"] != 254 and time.monotonic() < deadline:
            time.sleep(.01)
        assert status["tokens"]["official"]["total_tokens"] == 254
        assert status["tokens"]["official"]["known_compression_tokens"] == 0
        assert status["last_mode"] == "off"
        companion.set_mode("full", remote_enabled=False)
        with monkeypatch.context() as patch:
            def failed_save(): raise OSError("disk full")
            patch.setattr(companion.connection, "_save", failed_save)
            with pytest.raises(OSError):
                companion.set_mode("off", remote_enabled=True)
        assert companion.connection.public()["mode"] == companion.compressor.mode == "full"
        assert not companion.compressor.remote_enabled
        companion.restart()
        assert companion.compressor.mode == "full" and not companion.compressor.remote_enabled
        companion.disconnect()
        assert target.read_bytes() == original and not companion.status()["running"]
    finally:
        companion.stop()
        if companion.connection.enabled:
            companion.connection.restore()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
