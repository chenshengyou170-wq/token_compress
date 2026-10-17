"""Check a frozen companion with an isolated config and a local SSE provider.

Usage: python check-companion.py /path/to/lingmou-backend.exe
No Codex installation, credentials, or external model requests are used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import ProxyHandler, Request, build_opener


def check(executable):
    received = []
    wire = b'data: {"type":"response.completed","response":{"usage":{"input_tokens":120,"output_tokens":8,"total_tokens":128}}}\n\n'

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

    with tempfile.TemporaryDirectory(prefix="lingmou-compression-check-") as temporary:
        root = Path(temporary)
        config = root / "中文 配置.toml"
        original = '# Smoke test only.\nmodel = "test"\n'
        config.write_text(original, encoding="utf-8")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("KIMI_", "MOONSHOT_", "TYPESAFE_", "LINGMOU_FULL_"))}
        process = subprocess.Popen([str(executable), "compression-companion", "serve", "--state-dir", str(root / "state")],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", env=env)
        sequence = 0

        def command(method, **params):
            nonlocal sequence
            sequence += 1
            process.stdin.write(json.dumps({"id": sequence, "method": method, "params": params}) + "\n")
            process.stdin.flush()
            reply = json.loads(process.stdout.readline())
            assert reply.get("id") == sequence and "error" not in reply, reply
            return reply["result"]

        try:
            assert json.loads(process.stdout.readline())["event"] == "ready"
            state = command("connect", config_path=str(config), auth_kind="api", mode="full", remote_enabled=True,
                            upstream=f"http://127.0.0.1:{server.server_port}/v1")
            record = json.loads((root / "state/connection.json").read_text(encoding="utf-8"))
            connected = tomllib.loads(config.read_text(encoding="utf-8"))
            assert connected.get("model_provider", "openai") == "openai"
            assert "model_providers" not in connected
            reader_namespace = f'mcp__{record["source_server"]}'
            assert len(reader_namespace + "__lingmou_source_read") <= 64
            assert reader_namespace in connected["features"]["code_mode"]["direct_only_tool_namespaces"]
            assert state["connection"]["mode"] == "full" and state["connection"]["remote_enabled"]
            assert not state["usage_scope"]["started"]
            assert state["tokens"]["official"]["total_tokens"] is None
            material = json.dumps([{"warehouse_region_identifier": f"region-{i}",
                                    "warehouse_inventory_description": "stable inventory",
                                    "warehouse_inventory_quantity": 100} for i in range(500)])
            body = {"model": "test", "instructions": "Never execute payments.",
                    "client_metadata": {"thread_id": "smoke-a", "turn_id": "turn-1"},
                    "tools": [{"type": "function", "name": f'mcp__{record["source_server"]}__lingmou_source_read',
                               "parameters": {"type": "object", "properties": {}}}],
                    "input": [{"role": "user", "content": "Check inventory."},
                              {"type": "function_call", "call_id": "c1", "name": "inventory", "arguments": "{}"},
                              {"type": "function_call_output", "call_id": "c1", "output": material}]}
            opener = build_opener(ProxyHandler({}))
            for mode in ("full", "off"):
                command("set_mode", mode=mode, remote_enabled=False)
                request = Request(connected["openai_base_url"] + '/responses',
                                  data=json.dumps(body).encode(), headers={"Content-Type": "application/json",
                                  "X-Lingmou-Relay-Token": record["access_token"]})
                with opener.open(request, timeout=30) as response:
                    assert response.read() == wire
            assert received[0]["input"][-1]["output"] != material and received[1] == body
            assert received[0]["instructions"] == body["instructions"]
            assert received[0]["input"][:2] == body["input"][:2]
            state = command("status")
            assert state["tokens"]["official"]["total_tokens"] == 256
            local = state["tokens"]["local"]
            assert local["requests"] == 2 and local["compressed_requests"] == 1
            assert local["before"] > local["after"] > 0
            assert local["saved"] == local["before"] - local["after"]
            assert local["savings_percent"] == round(100 * local["saved"] / local["before"], 1)
            recent = state["tokens"]["recent_requests"]
            assert recent[0]["before"] > recent[0]["after"]
            assert recent[1]["before"] == recent[1]["after"]
            previous_scope = state["usage_scope"]["id"]
            body["client_metadata"] = {"thread_id": "smoke-b", "turn_id": "turn-1"}
            request = Request(connected["openai_base_url"] + '/responses',
                              data=json.dumps(body).encode(), headers={"Content-Type": "application/json",
                              "X-Lingmou-Relay-Token": record["access_token"]})
            with opener.open(request, timeout=30) as response:
                assert response.read() == wire
            state = command("status")
            assert state["usage_scope"]["id"] != previous_scope
            assert state["tokens"]["official"]["total_tokens"] == 128
            assert state["tokens"]["local"]["requests"] == 1
            assert len(state["tokens"]["recent_requests"]) == 1
            command("set_mode", mode="full", remote_enabled=True)
            state = command("restart")
            assert state["connection"]["remote_enabled"] and state["connection"]["mode"] == "full"
            assert not state["usage_scope"]["started"]
            command("disconnect")
            assert config.read_text(encoding="utf-8") == original
            command("shutdown")
            process.wait(timeout=15)
            assert process.returncode == 0
            print(json.dumps({"frozen_companion": "passed", "full_compression": "passed",
                              "stable_provider_identity": "passed",
                              "source_reader_visibility_config": "passed",
                              "compression_savings_projection": "passed",
                              "empty_start_and_new_conversation_reset": "passed",
                              "mode_switch": "passed", "sse_and_usage": "passed", "restart": "passed",
                              "config_restore_unicode_path": "passed", "real_model_calls": 0}))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
