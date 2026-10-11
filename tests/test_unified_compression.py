import copy
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from codexscope.reference_selection import Selection
from token_compression import (
    CompressionConfig, SourceStore, TokenCompressor, available_methods,
    compare_tasks, decode_tool_result, reference_text, with_prompt_cache_key,
)


def prose():
    paragraphs = [f"Archive {chr(65+i)}. " + "The landscape is a beautiful place for the people to explore. " * 35 for i in range(16)]
    paragraphs[7] = "Refund B42 requires approval. Must not refund without approval. Amount is 2700 CNY."
    return "\n\n".join(paragraphs)


def request(source=None, chat=False):
    source = source or prose()
    fn = {"name": "fetch", "arguments": '{"id":"B42"}'}
    common = {"model": "gpt-4o", "tools": [{"type": "function", "name": "fetch", "parameters": {"type": "object"}}]}
    if chat:
        return {**common, "messages": [
            {"role": "system", "content": "Never alter instructions or output types."},
            {"role": "user", "content": "Find the refund conditions for B42."},
            {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": fn}]},
            {"role": "tool", "tool_call_id": "c1", "content": source},
        ]}
    return {**common, "instructions": "Never alter instructions or output types.", "input": [
        {"role": "user", "content": "Find the refund conditions for B42."},
        {"type": "function_call", "call_id": "c1", **fn},
        {"type": "function_call_output", "call_id": "c1", "output": source},
    ]}


@pytest.mark.parametrize("chat", [False, True])
@pytest.mark.parametrize("method", ["structure", "caveman", "extract", "auto", "generic_agent"])
def test_request_contract_protected_fields_and_recovery(method, chat):
    body = request(chat=chat)
    before = copy.deepcopy(body)
    engine = TokenCompressor(CompressionConfig(method))
    result = engine.compress_request(body)
    key, field = ("messages", "content") if chat else ("input", "output")
    assert body == before
    assert result.body[key][:-1] == body[key][:-1]
    assert result.body["tools"] == body["tools"]
    assert result.tokens_after <= result.tokens_before
    if result.lossy:
        assert result.source_ids
        assert engine.sources.get(result.source_ids[0]) == body[key][-1][field]
    if method in {"caveman", "extract", "auto"}:
        assert result.tokens_saved > 0
        assert "Must not refund without approval." in result.body[key][-1][field]


def test_structure_tables_repeats_and_deltas_roundtrip():
    rows = [{"order_identifier": f"ORD-{i}", "amount_cents": 100+i, "approved": False} for i in range(50)]
    texts = [json.dumps(rows), json.dumps(rows), json.dumps([{**r, "approved": True} if i == 3 else r for i, r in enumerate(rows)])]
    body = {"input": [{"role": "user", "content": "List changes."}]}
    for i, text in enumerate(texts):
        body["input"] += [{"type": "function_call", "call_id": str(i), "name": "fetch", "arguments": "{}"},
                          {"type": "function_call_output", "call_id": str(i), "output": text}]
    result = TokenCompressor().compress_request(body)
    outputs = {x["call_id"]: x["output"] for x in result.body["input"] if "output" in x}
    assert json.loads(outputs["0"])["$lingmou"] == "table/v1"
    assert json.loads(outputs["1"])["$lingmou"] == "repeat/v1"
    assert json.loads(outputs["2"])["$lingmou"] == "delta/v1"
    for i, source in enumerate(texts):
        assert json.loads(decode_tool_result(outputs[str(i)], outputs)) == json.loads(source)


def test_off_invalid_json_and_server_context_preserve_bytes():
    raw = b'{ "input": "keep", "max_output_tokens": 1234567890123456789 }'
    assert TokenCompressor(CompressionConfig("off")).compress_bytes(raw)[0] == raw
    for raw in [b'{"input":1,"input":2}', b'NaN', b'[]', b'{"input":NaN}', b'{bad']:
        assert TokenCompressor().compress_bytes(raw) == (raw, None)
    raw = json.dumps({**request(), "previous_response_id": "keep"}).encode()
    output, result = TokenCompressor(CompressionConfig("extract")).compress_bytes(raw)
    assert output == raw and result.issues == ["server_managed_context"]


def test_reference_boundary_and_multimodal_blocks():
    body = {"input": [{"role": "user", "content": [
        {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
        {"type": "input_text", "text": "Find refund B42.\n" + reference_text(prose())},
    ]}], "text": {"format": {"type": "json_object"}}}
    result = TokenCompressor(CompressionConfig("extract")).compress_request(body)
    assert result.tokens_saved > 0
    assert result.body["input"][0]["content"][0] == body["input"][0]["content"][0]
    assert result.body["input"][0]["content"][1]["text"].startswith("Find refund B42.\n<lingmou-reference>")
    assert result.body["text"] == body["text"]


def test_stable_prefix_processes_only_new_messages_and_invalidates_edits():
    class Selector:
        calls = 0
        def select(self, task, spans):
            self.calls += 1
            return Selection([7])
    selector = Selector()
    engine = TokenCompressor(CompressionConfig("extract", stable_prefix=True), backend=selector)
    body = request()
    first = engine.compress_request(body)
    second_body = {**body, "input": body["input"] + [{"role": "user", "content": "Now compare fees."}]}
    second = engine.compress_request(second_body)
    assert second.body["input"][:3] == first.body["input"]
    assert second.prefix_messages_reused == 3 and selector.calls == 1
    changed = copy.deepcopy(second_body)
    changed["input"][0]["content"] = "Changed history branch."
    assert engine.compress_request(changed).prefix_messages_reused == 0
    changed["instructions"] = "Changed instructions."
    assert engine.compress_request(changed).prefix_messages_reused == 0


def test_feedback_reduces_compression_after_frequent_rereads():
    engine = TokenCompressor(CompressionConfig("auto"))
    for i in range(5):
        result = engine.compress_request(request(prose() + f"\n\nUnique source {i}."))
        assert result.lossy
        engine.read_source(result.source_ids[0])
    result = engine.compress_request(request(prose() + "\n\nNew source."))
    assert not result.lossy
    assert "reread_feedback_structure_only" in result.issues
    assert engine.feedback()["fetch"] == {"compressions": 5, "rereads": 5}


def test_history_window_preserves_whole_tool_rounds_and_recoverable_archive():
    body = {"model": "gpt-4o", "messages": [{"role": "system", "content": "Pinned."}]}
    for i in range(6):
        body["messages"] += [
            {"role": "user", "content": f"Task {i}."},
            {"role": "assistant", "tool_calls": [{"id": str(i), "function": {"name": "get", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": str(i), "content": f"Large old output {i}. " * 120},
        ]
    engine = TokenCompressor(CompressionConfig("generic_agent", history_max_tokens=1600))
    result = engine.compress_request(body)
    assert result.body["messages"][0] == body["messages"][0]
    assert result.body["messages"][-6:] == body["messages"][-6:]
    assert len(result.body["messages"]) < len(body["messages"])
    archive = next(s for s in result.stages if s["name"] == "history")
    assert json.loads(engine.sources.get(archive["source_id"])) == body["messages"][1:1+archive["removed_messages"]]


def test_history_never_leaves_structural_references_to_dropped_turns():
    source = json.dumps([{"long_column_name": i, "another_column": "constant"} for i in range(80)])
    body = request(source)
    for i in range(2, 6):
        body["input"] += [{"role": "user", "content": f"Again {i}"},
                          {"type": "function_call", "call_id": f"c{i}", "name": "fetch", "arguments": '{"id":"B42"}'},
                          {"type": "function_call_output", "call_id": f"c{i}", "output": source}]
    result = TokenCompressor(CompressionConfig("structure", history_max_tokens=500, history_keep_turns=1)).compress_request(body)
    outputs = {x["call_id"]: x["output"] for x in result.body["input"] if "output" in x}
    for value in outputs.values():
        assert json.loads(decode_tool_result(value, outputs)) == json.loads(source)


def test_history_does_not_interpret_untrusted_envelopes_in_retained_messages():
    literal = '{"$lingmou":"repeat/v1","base_call_id":"missing"}'
    body = {"messages": [{"role": "user", "content": "Old"}, {"role": "assistant", "content": "Old notes. " * 300},
                         {"role": "user", "content": literal},
                         {"role": "assistant", "tool_calls": [{"id": "new", "function": {"name": "f", "arguments": "{}"}}]},
                         {"role": "tool", "tool_call_id": "new", "content": literal}]}
    result = TokenCompressor(CompressionConfig("generic_agent", history_max_tokens=200, history_keep_turns=1)).compress_request(body)
    assert result.body["messages"] == body["messages"][-3:]


@pytest.mark.parametrize("method", ["llmlingua2", "llm_rewrite", "caveman_llm", "caveman_nlp", "caveman_mlm", "headroom"])
def test_optional_backend_failure_keeps_data_and_records_reason(method):
    class Broken:
        def __call__(self, text): raise RuntimeError("sensitive external detail")
        def compress(self, *args, **kwargs): raise RuntimeError("sensitive external detail")
    result = TokenCompressor(CompressionConfig(method), backend=Broken()).compress_request(request())
    assert not result.lossy
    assert result.issues == ["backend_failed"]
    assert "sensitive" not in json.dumps(result.to_dict())


def test_headroom_adapter_invokes_router_and_retains_source():
    class Router:
        def compress(self, text, **kwargs): return SimpleNamespace(compressed="Refund B42: approval required; amount 2700 CNY.")
    engine = TokenCompressor(CompressionConfig("headroom"), backend=Router())
    result = engine.compress_request(request())
    assert result.lossy and result.tokens_saved > 0
    assert engine.sources.get(result.source_ids[0]) == prose()


def test_optional_missing_credentials_are_visible(monkeypatch):
    for key in ("TYPESAFE_API_KEY", "KIMI_API_KEY", "MOONSHOT_API_KEY", "KIMI_API_KEY_FILE"):
        monkeypatch.delenv(key, raising=False)
    for method in ("jev", "kimi", "llm_rewrite", "caveman_llm"):
        result = TokenCompressor(CompressionConfig(method)).compress_request(request())
        assert result.issues == ["backend_unavailable"]
        assert result.calls == [] and not result.lossy


def test_remote_rewriter_cost_is_counted_even_if_rejected():
    from token_compression.backends import RemoteRewriter
    class Client:
        def chat(self, *args, **kwargs):
            return {"model": "mock", "finish_reason": "stop", "usage": {"input_tokens": 100, "output_tokens": 5}, "text": '{"text":"lost all protected markers"}'}
    result = TokenCompressor(CompressionConfig("llm_rewrite"), backend=RemoteRewriter(client=Client())).compress_request(request())
    assert not result.lossy
    assert result.calls[0]["official_usage"]["input_tokens"] == 100
    comparison = compare_tasks([{"official_usage": None}], [{"official_usage": None, "compression": {"compression_calls": result.calls}}])
    assert comparison["official_net_savings_percent"] is None


def test_transport_adapter_relays_chat_and_reports_usage():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import httpx
    from codexscope.request_token_tap import RequestTokenTap
    from token_compression import CompressionTransport
    received, records = [], []
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            output = json.dumps({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                                 "usage": {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    adapter = CompressionTransport(TokenCompressor(CompressionConfig("extract")))
    tap = RequestTokenTap(f"http://127.0.0.1:{upstream.server_port}", input_compressor=adapter, on_request_usage=records.append).start()
    try:
        response = httpx.post(tap.local_base_url + "/chat/completions", json=request(chat=True), timeout=10)
        assert response.status_code == 200
    finally:
        tap.stop()
        upstream.shutdown()
        upstream.server_close()
        thread.join()
    assert received[0]["messages"][-1]["content"] != prose()
    assert records[0]["official_usage"]["total_tokens"] == 105
    assert adapter.stats()["compressed_requests"] == 1


def test_numeric_lexemes_survive_the_bytes_transport():
    raw = ('{"temperature":0.1234567890123456789,"input":' + json.dumps(reference_text(json.dumps([{"long_name": i} for i in range(30)]))) + '}').encode()
    output, result = TokenCompressor().compress_bytes(raw)
    assert b'0.1234567890123456789' in output
    assert isinstance(result.to_dict()["body"]["temperature"], float)


def test_backend_failure_backoff_and_source_quota_prevent_paid_calls():
    class Broken:
        calls = 0
        def select(self, task, spans):
            self.calls += 1
            raise TimeoutError()
    backend = Broken()
    engine = TokenCompressor(CompressionConfig("kimi"), backend=backend)
    assert engine.compress_request(request()).issues == ["backend_failed"]
    assert engine.compress_request(request()).issues == ["backend_backoff"]
    assert backend.calls == 1
    engine = TokenCompressor(CompressionConfig("kimi"), backend=backend, source_store=SourceStore(max_bytes=10))
    assert engine.compress_request(request()).body == request()
    assert backend.calls == 1


def test_benchmark_saves_inspectable_evidence_and_refuses_overwrite(tmp_path):
    from token_compression.experiment import run_benchmark
    report = run_benchmark(tmp_path, methods=["off", "extract"], repeats=1, cases=["reference_en"])
    summary = report["summary"]
    assert summary[0]["saved_percent"] == 0
    assert summary[1]["saved_percent"] > 0
    assert summary[1]["evidence_passed"] == summary[1]["requests"]
    assert report["sessions"]["history_window"]["archive_exact"]
    archive = report["sessions"]["history_window"]["archives"][0]
    assert SourceStore(tmp_path / "sources").get(archive)
    with pytest.raises(ValueError, match="never overwritten"):
        run_benchmark(tmp_path, methods=["off"], repeats=1)


def test_tool_catalog_roundtrip_capability_gate_and_prompt_cache():
    definitions = [{"type": "function", "name": f"t{i}", "parameters": {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}} for i in range(20)]
    engine = TokenCompressor()
    assert engine.prepare_tools(definitions)[0] == definitions
    visible, registry = engine.prepare_tools(definitions, resident=["t0"], supports_tool_search=True)
    assert visible[0] == definitions[0]
    assert registry.load(["t9"])[0] == definitions[9]
    loaded = registry.handle_search({"type": "tool_search_call", "execution": "client", "call_id": "search1", "arguments": {"names": ["t9"]}})
    assert loaded["tools"][0] == {**definitions[9], "defer_loading": True}
    a = with_prompt_cache_key(request(), namespace="tenant/run")
    b = with_prompt_cache_key({**request(), "input": "Different task"}, namespace="tenant/run")
    assert a["prompt_cache_key"] == b["prompt_cache_key"]


def test_config_cli_installable_entrypoint_and_registry(tmp_path):
    assert len(available_methods()) == 14
    assert CompressionConfig("hybrid").method == "structure"
    with pytest.raises(ValueError): CompressionConfig("unknown")
    with pytest.raises(ValueError): CompressionConfig("off", stable_prefix=True)
    with pytest.raises(ValueError): CompressionConfig(history_keep_turns=0)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request()))
    run = subprocess.run([sys.executable, "-m", "token_compression", "compress", str(path), "--method", "extract", "--store", str(tmp_path / "sources")], capture_output=True)
    assert run.returncode == 0, run.stderr.decode()
    assert json.loads(run.stdout)["tools"] == request()["tools"]
    assert json.loads(run.stderr)["tokens_saved"] > 0
