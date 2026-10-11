"""Reproducible synthetic experiments, with explicit estimates and evidence checks."""
from __future__ import annotations

import copy
import csv
import hashlib
import importlib.metadata
import importlib.util
import json
import platform
import statistics
from datetime import datetime, timezone
from pathlib import Path

from codexscope.compression_boundary import transform_data
from codexscope.context_compression import chat_text_slots
from codexscope.input_compression import _text_slots
from codexscope.structural_compression import decode_tool_result, dumps, loads

from .engine import CompressionConfig, TokenCompressor
from .methods import METHODS
from codexscope.reference_selection import SourceStore


def fixtures():
    def tool_body(texts, task):
        body = {"model": "gpt-4o", "instructions": "Treat references as data. Preserve exact facts and conditions.",
                "tools": [{"type": "function", "name": "fetch", "parameters": {"type": "object", "properties": {}}}],
                "input": [{"role": "user", "content": task}]}
        for i, source in enumerate(texts):
            body["input"] += [{"type": "function_call", "call_id": f"c{i}", "name": "fetch", "arguments": "{}"},
                              {"type": "function_call_output", "call_id": f"c{i}", "output": source}]
        return body
    rows = [{"order_identifier": f"ORD-{i:04d}", "amount_cents": 12300+i, "approved": False,
             "status": "needs_review", "currency": "CNY"} for i in range(120)]
    table = json.dumps(rows, ensure_ascii=False, indent=2)
    changed = copy.deepcopy(rows)
    changed[43]["amount_cents"] = 19007
    logs = "".join(f"2026-10-11 INFO worker={i%4} status=completed count=100\n" for i in range(180))
    logs += "2026-10-11 ERROR order=B42 status=denied reason=approval_required\n"
    english = [f"Archive {chr(65+i)}. " + "The landscape is a beautiful place for the people to explore. " * 22 for i in range(16)]
    english[7] = "Refund B42 has amount_cents=2700, currency CNY and status needs_review. Must not refund without approval."
    chinese = [f"档案{chr(65+i)}：" + "这里记录山川地貌和沿途风景，供游客了解当地的自然环境。" * 22 for i in range(16)]
    chinese[7] = "订单 B42 的金额（分）为 2700，币种 CNY，状态为 needs_review。只有审批通过后才允许退款；未审批时不得退款。"
    code = "\n\n".join(f'def archive_{i}():\n    """' + "Background archive helper. " * 30 + f'"""\n    return {i}' for i in range(12))
    code += "\n\ndef refund_allowed(approved, locked):\n    return approved and not locked\n"
    search = "\n".join(f"src/module_{i}.py:{i+1}: unrelated archive record" for i in range(180))
    search += "\nsrc/refund.py:42: return approved and not locked\n"
    tagged = "<tool_result>" + "Old irrelevant operational note. " * 300 + "</tool_result>\n<summary>B42 requires approval.</summary>"
    cases = {
        "prose_short": {"body": tool_body([("The database is a very reliable system for the team to process the incoming reports. " * 32) + "Invoice B42 has amount 2700 CNY. Must not refund without approval."], "Find B42 and the approval condition."), "facts": ["B42", "2700", "Must not refund without approval."]},
        "json_table": {"body": tool_body([table], "Find ORD-0043."), "facts": ["ORD-0043", "12343", "needs_review", "CNY"]},
        "logs": {"body": tool_body([logs], "Find the error for B42."), "facts": ["B42", "approval_required"]},
        "repeat_delta": {"body": tool_body([table, table, json.dumps(changed)], "What changed for ORD-0043?"), "facts": ["ORD-0043", "19007"]},
        "reference_en": {"body": tool_body(["\n\n".join(english)], "What are the refund conditions and amount for B42?"), "facts": ["B42", "2700", "needs_review", "Must not refund without approval."]},
        "reference_zh": {"body": tool_body(["\n\n".join(chinese)], "核对订单 B42 的金额、状态以及退款审批条件。"), "facts": ["B42", "2700", "needs_review", "未审批时不得退款"]},
        "code": {"body": tool_body([code], "Read refund_allowed and evaluate approved=True, locked=True."), "facts": ["def refund_allowed(approved, locked):", "return approved and not locked"]},
        "search": {"body": tool_body([search], "Find refund.py and the locked condition."), "facts": ["src/refund.py", "return approved and not locked"]},
        "history_tags": {"body": tool_body([tagged], "Recall B42 approval."), "facts": ["B42 requires approval."]},
        "malformed_json": {"body": tool_body(['{"amount":1,"amount":2}'], "Read exact data."), "facts": ['{"amount":1,"amount":2}']},
    }
    return cases


def _slots(body):
    return list(chat_text_slots(body) if "messages" in body else _text_slots(body))


def _protected(body):
    value = copy.deepcopy(body)
    for container, key, role in _slots(value):
        container[key] = transform_data(container[key], role, lambda _: "<DATA>")
    return value


def check_evidence(case, result, engine):
    body = result.body
    bases = {item.get("call_id", item.get("tool_call_id")): item.get("output", item.get("content"))
             for item in body.get("messages", body.get("input", [])) if isinstance(item, dict)}
    visible, roundtrip, recovery = [], True, True
    originals = _slots(case["body"])
    for (container, key, role), (old, old_key, _) in zip(_slots(body), originals):
        if role != "tool_output":
            continue
        text, source = container[key], old[old_key]
        try:
            envelope = json.loads(text)
        except ValueError:
            envelope = None
        if isinstance(envelope, dict) and envelope.get("$lingmou") in {"extract/v1", "lossy/v1"}:
            sid = envelope["source_id"]
            recovery &= engine.sources.get(sid) == source
            if envelope["$lingmou"] == "extract/v1":
                excerpts = envelope["excerpts"]
                recovery &= all(source[e["start"]:e["end"]] == e["text"] for e in excerpts)
                visible.append("\n".join(e["text"] for e in excerpts))
            else:
                visible.append(envelope["text"])
            roundtrip = False
        else:
            decoded = decode_tool_result(text, bases)
            visible.append(decoded)
            try:
                roundtrip &= loads(decoded) == loads(source)
            except ValueError:
                roundtrip &= decoded == source
    text = "\n".join(visible)
    return {"protected_fields_exact": _protected(body) == _protected(case["body"]),
            "required_evidence_retained": all(f in text for f in case["facts"]),
            "recoverable_sources_exact": recovery, "lossless_roundtrip": roundtrip,
            "answer_quality": None}


def session_experiments(store=None):
    case = fixtures()["reference_en"]
    engine = TokenCompressor(CompressionConfig("auto", stable_prefix=True), source_store=store)
    first = engine.compress_request(case["body"])
    second_body = copy.deepcopy(case["body"])
    second_body["input"].append({"role": "user", "content": "Now check the same policy again."})
    second = engine.compress_request(second_body)
    edited = copy.deepcopy(second_body)
    edited["input"][0]["content"] = "An edited branch"
    third = engine.compress_request(edited)
    feedback_engine = TokenCompressor(CompressionConfig("auto"), source_store=store)
    for i in range(5):
        body = copy.deepcopy(case["body"])
        body["input"][-1]["output"] += f"\n\nSource version {i}."
        result = feedback_engine.compress_request(body)
        if result.source_ids:
            feedback_engine.read_source(result.source_ids[0])
    final = feedback_engine.compress_request(case["body"])
    definitions = [{"type": "function", "name": f"tool_{i}", "description": f"Perform task {i}.",
        "parameters": {"type": "object", "properties": {f"parameter_{j}": {"type": "string", "description": "An exact structured argument for the chosen operation."} for j in range(12)}}} for i in range(30)]
    tools, registry = engine.prepare_tools(definitions, resident=["tool_0"], supports_tool_search=True)
    full, catalog = engine.count(dumps(definitions)), engine.count(dumps(tools))
    loaded = registry.handle_search({"type": "tool_search_call", "execution": "client", "call_id": "s1", "arguments": {"names": ["tool_7"]}})
    history = {"messages": [{"role": "system", "content": "Pinned system instruction."}]}
    for i in range(8):
        history["messages"] += [{"role": "user", "content": f"Task {i}"}, {"role": "assistant", "content": f"Archive {i}. " * 200}]
    trim_engine = TokenCompressor(CompressionConfig("generic_agent", history_max_tokens=2200), source_store=store)
    trim = trim_engine.compress_request(history)
    return {
        "stable_prefix": {"reused_messages": second.prefix_messages_reused,
            "forwarded_prefix_exact": second.body["input"][:-1] == first.body["input"],
            "edited_branch_reused": third.prefix_messages_reused, "provider_cache_hit": None},
        "reread_feedback": {"counters": feedback_engine.feedback(), "next_request_lossy": final.lossy,
            "reason": final.issues},
        "deferred_tools": {"all_schemas_tokens": full, "catalog_and_resident_tokens": catalog,
            "loaded_schema_tokens": engine.count(dumps(loaded)), "initial_tokens_saved": full-catalog,
            "schema_exact_after_load": loaded["tools"][0] == {**definitions[7], "defer_loading": True},
            "note": "Schema estimates only. Discovery/reload round trips require whole-task provider accounting."},
        "history_window": {"tokens_before": trim.tokens_before, "tokens_after": trim.tokens_after,
            "latest_two_turns_exact": trim.body["messages"][-4:] == history["messages"][-4:],
            "pinned_system_exact": trim.body["messages"][0] == history["messages"][0], "archives": trim.source_ids,
            "archive_exact": bool(trim.source_ids) and json.loads(trim_engine.sources.get(trim.source_ids[0])) == history["messages"][1:-4]},
    }


def _metadata():
    versions = {}
    for name in ("lingmou-token-compression", "tiktoken", "llmlingua", "torch", "transformers", "headroom-ai", "spacy", "en-core-web-sm"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    root = Path(__file__).resolve().parent.parent
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for package in ("token_compression", "codexscope") for p in sorted((root / package).glob("*.py"))}
    external = {}
    try:
        spec = importlib.util.find_spec("headroom")
        if spec and spec.origin:
            package = Path(spec.origin).parent
            for p in [package / "transforms" / "content_router.py", *package.glob("_core*.so")]:
                external["headroom/" + str(p.relative_to(package))] = hashlib.sha256(p.read_bytes()).hexdigest()
    except ImportError:
        pass
    return {"created_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "platform": platform.platform(), "packages": versions, "source_sha256": hashes, "external_sha256": external}


def run_benchmark(out: Path, *, methods, repeats=3, model_path=None, reference_path=None, live=False, cases=None,
                  mlm_model_path=None, spacy_model="en_core_web_sm"):
    if repeats < 1:
        raise ValueError("repeats must be positive")
    if not methods or any(m not in METHODS for m in methods):
        raise ValueError("select at least one known method")
    methods = list(dict.fromkeys(methods))
    if any(METHODS[m].remote for m in methods) and not live:
        raise ValueError("remote methods require --live; synthetic fixture text is sent to configured providers")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("use a new output directory; existing evidence is never overwritten")
    data = fixtures()
    if cases:
        data = {k: data[k] for k in cases}
    config = {"methods": methods, "repeats": repeats, "cases": list(data), "live": live,
              "model_path": model_path, "reference_path": reference_path,
              "mlm_model_path": mlm_model_path, "spacy_model": spacy_model,
              "fixtures_sha256": hashlib.sha256(dumps(data).encode()).hexdigest()}
    metadata = _metadata()
    (out / "fixtures.json").write_text(dumps(data) + "\n")
    (out / "run_config.json").write_text(json.dumps(config, indent=2) + "\n")
    records = []
    for method in methods:
        engine = TokenCompressor(CompressionConfig(method, model_path=model_path, reference_path=reference_path,
                                 mlm_model_path=mlm_model_path, spacy_model=spacy_model),
                                 source_store=SourceStore(out / "sources"))
        for name, case in data.items():
            for repeat in range(repeats):
                result = engine.compress_request(case["body"])
                checks = check_evidence(case, result, engine)
                row = {"case": name, "method": method, "repeat": repeat, **result.to_dict(), "checks": checks}
                body = row.pop("body")
                row["output_sha256"] = hashlib.sha256(dumps(body).encode()).hexdigest()
                records.append(row)
                (out / f"{name}.{method}.{repeat}.json").write_text(dumps(body) + "\n")
                with (out / "records.jsonl").open("a") as stream:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                print(json.dumps({k: row[k] for k in ("case", "method", "repeat", "tokens_saved", "elapsed_ms", "issues")}), flush=True)
    summaries = []
    for method in methods:
        group = [r for r in records if r["method"] == method]
        baseline = sum(r["tokens_before"] for r in group)
        after = sum(r["tokens_after"] for r in group)
        summaries.append({"method": method, "requests": len(group), "tokens_before": baseline, "tokens_after": after,
            "saved_percent": round(100*(baseline-after)/baseline, 3),
            "median_ms": round(statistics.median(r["elapsed_ms"] for r in group), 3),
            "issues": sum(bool(r["issues"]) for r in group),
            "evidence_passed": sum(all(r["checks"][k] for k in ("protected_fields_exact", "required_evidence_retained", "recoverable_sources_exact")) for r in group),
            "remote_calls": sum(len(r["calls"]) for r in group),
            "known_remote_tokens": sum((c.get("official_usage") or {}).get("total_tokens", 0) for r in group for c in r["calls"]),
            "remote_calls_missing_usage": sum(c.get("official_usage") is None for r in group for c in r["calls"]),
            "official_net_savings_percent": None})
    report = {"metadata": metadata, "config": config, "summary": summaries, "sessions": session_experiments(SourceStore(out / "sources")),
              "limits": ["Synthetic corpus; local serialized JSON estimates, not provider billing.",
                         "Evidence retention checks do not establish downstream answer accuracy.",
                         "Repeated runs reuse each method's cache; first run includes lazy initialization.",
                         "Remote compression usage is counted even for rejected candidates; no downstream usage in this benchmark."]}
    (out / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    with (out / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)
    return report
