import copy
import json

from codexscope.desktop_companion import DesktopCompressor
from codexscope.full_compression import FullCompressionConfig, FullCompressionPipeline
from codexscope.input_compression import _MAX_BODY_BYTES
from codexscope.reference_selection import SourceStore
from codexscope.session_compression import (SessionCompressionLedger, SessionConfig, archive_old_images,
                                            media_free, supersede_stale_outputs)
from codexscope.tool_output_cleanup import clean_tool_text
from token_compression.history import trim_history

SERVER = "lingmou_src_test"
READER = {"type": "namespace", "name": "mcp__" + SERVER,
          "tools": [{"type": "function", "name": "lingmou_source_read", "parameters": {"type": "object"}}]}
SKILLS = ("<skills_instructions>\n### Available skills\n"
          + "\n".join(f"- skill{i}: prepares document kind {i} with charts (file: /s/{i}/SKILL.md)" for i in range(12))
          + "\n</skills_instructions>")


def quarter(text):
    return len(text) // 4


def tool_pair(n, *, cmd=None, lines=300, text=None):
    identity = f"c{n}"
    cmd = cmd or f'text(await tools.exec_command({{cmd:"sed -n 1,400p paper/section{n}.md"}}))'
    text = text or "\n".join(f"Section {n} line {i}: value {i * 7} measured \x1b[32mok\x1b[0m" for i in range(lines))
    return [{"type": "reasoning", "encrypted_content": "e" * 400, "summary": []},
            {"type": "custom_tool_call", "call_id": identity, "name": "exec", "input": cmd},
            {"type": "custom_tool_call_output", "call_id": identity, "output": text}]


def base_body(task="Make a slide deck from the paper."):
    meta = {"x-codex-turn-metadata": json.dumps({"thread_id": "thread-1", "turn_id": "turn-1"})}
    return {"model": "gpt-5", "tools": [READER], "instructions": "Be careful.\n" + SKILLS,
            "client_metadata": meta, "input": [{"role": "user", "content": task}]}


def send(compressor, body):
    sent, observation = compressor.compress_observed(json.dumps(body).encode())
    return json.loads(sent), observation


def test_long_tool_loop_is_append_only_between_rare_checkpoints():
    compressor = DesktopCompressor("full", SourceStore(), SERVER, token_counter=quarter)
    body = base_body()
    previous, checkpoints = None, 0
    for n in range(36):
        body["input"] += tool_pair(n)
        if n == 18:
            body["input"].append({"role": "user", "content": "Now also check the figures and tables."})
        got, observation = send(compressor, body)
        info = observation.cache_prefix
        if info["checkpoint"]:
            checkpoints += 1
            assert info["break"]["cause"] == "lingmou"
        elif previous is not None:
            # A changed task or a new user message never rewrites what was sent.
            assert got["instructions"] == previous["instructions"]
            assert got["input"][:len(previous["input"])] == previous["input"]
            assert info["break"] is None
        previous = got
        compressor.observe_response({"compression": {"cache_prefix": info},
                                     "official_usage": {"input_tokens": 1000, "cached_input_tokens": 900}})
    assert 1 <= checkpoints <= 3
    assert compressor.stats()["session"]["prefix_breaks_lingmou"] == checkpoints


def test_task_dependent_instruction_rendering_is_frozen_per_conversation():
    compressor = DesktopCompressor("full", SourceStore(), SERVER, token_counter=quarter)
    first, _ = send(compressor, base_body("Use skill3 for the report."))
    later = base_body("Use skill3 for the report.")
    later["input"] += [{"role": "assistant", "content": "Done."},
                       {"role": "user", "content": "Now use skill7 for slides."}]
    second, observation = send(compressor, later)
    assert second["instructions"] == first["instructions"]
    assert observation.cache_prefix["header_stable"] is True


def test_client_history_rewrite_is_attributed_to_client():
    compressor = DesktopCompressor("structure", SourceStore(), SERVER, token_counter=quarter)
    body = base_body()
    for n in range(3):
        body["input"] += tool_pair(n, lines=20)
    send(compressor, body)
    rewritten = base_body()
    rewritten["input"] += [{"role": "assistant", "content": "Summary of earlier work."}] + tool_pair(9, lines=20)
    _, observation = send(compressor, rewritten)
    assert observation.cache_prefix["break"]["cause"] == "client"


def test_checkpoint_declined_when_cache_break_is_not_repaid():
    config = SessionConfig(tool_checkpoint_tokens=6000, tool_target_tokens=1500, min_future_requests=1,
                           max_future_requests=1, cache_price_ratio=.01, supersede_stale_outputs=False)
    ledger = SessionCompressionLedger(config)
    store = SourceStore()
    body = base_body()
    for n in range(8):
        body["input"] += tool_pair(n, lines=120)
    # The first request establishes a cached prefix without checkpointing.
    small = copy.deepcopy(body)
    small["input"] = small["input"][:4]
    ledger.apply(small, copy.deepcopy(small), count=quarter, store=store, checkpoint=True)
    ledger.observe_usage(ledger.apply(small, copy.deepcopy(small), count=quarter)[1]["session"],
                         {"input_tokens": 100, "cached_input_tokens": 90})
    sent, info = ledger.apply(body, copy.deepcopy(body), count=quarter, store=store, checkpoint=True)
    assert info["checkpoint"] is None and ledger.stats()["declined_checkpoints"] == 1
    # Without observed caching, breaking the prefix has no extra cost.
    ledger = SessionCompressionLedger(config)
    for _ in range(2):
        ledger.apply(small, copy.deepcopy(small), count=quarter)
        ledger.observe_usage(ledger.apply(small, copy.deepcopy(small), count=quarter)[1]["session"],
                             {"input_tokens": 100, "cached_input_tokens": 0})
    sent, info = ledger.apply(body, copy.deepcopy(body), count=quarter, store=store, checkpoint=True)
    assert info["checkpoint"]["performed"] and info["checkpoint"]["break_cost_estimate"] == 0


def test_repeated_calls_and_modified_files_supersede_older_outputs_exactly():
    store = SourceStore()
    read = 'text(await tools.exec_command({cmd:"cat src/app.py"}))'
    patch = "*** Begin Patch\n*** Update File: src/app.py\n@@\n-a\n+b\n*** End Patch"
    status = 'text(await tools.exec_command({cmd:"git status"}))'
    items = (tool_pair(1, cmd=read, lines=60) + tool_pair(2, cmd=status, lines=60)
             + [{"type": "custom_tool_call", "call_id": "p", "name": "apply_patch", "input": patch},
                {"type": "custom_tool_call_output", "call_id": "p", "output": "Done"}]
             + tool_pair(3, cmd=status, lines=60) + tool_pair(4, lines=5))
    original = copy.deepcopy(items)
    changed = supersede_stale_outputs(items, sources={}, count=quarter, store=store)
    assert changed == 2
    notices = {item["call_id"]: json.loads(item["output"]) for item in items
               if item.get("type") == "custom_tool_call_output" and item["output"].startswith('{"$lingmou"')}
    assert notices["c1"]["reason"] == "file_modified_later" and notices["c1"]["superseded_by"] == "p"
    assert notices["c2"]["reason"] == "same_call_repeated" and notices["c2"]["superseded_by"] == "c3"
    for call_id, notice in notices.items():
        before = next(i["output"] for i in original if i.get("call_id") == call_id and "output" in i)
        assert store.read(notice["source_id"], 1, notice["total_lines"])["text"] == before
    assert [i for i in items if i.get("type") != "custom_tool_call_output"] == \
        [i for i in original if i.get("type") != "custom_tool_call_output"]


def test_archived_notice_keeps_error_lines_visible():
    from codexscope.tool_output_history import archive_notice
    text = "\n".join(["noise line %d" % i for i in range(200)] + ["FAILED tests/test_x.py::test_y - AssertionError"]
                     + ["noise line %d" % i for i in range(200)])
    notice = json.loads(archive_notice(text, store=SourceStore(), count=quarter))
    assert any("FAILED tests/test_x.py" in line for _, line in notice["salient_lines"])


def test_old_images_are_replaced_and_latest_user_images_kept():
    image = {"type": "input_image", "image_url": "data:image/png;base64," + "A" * 100}
    items = [{"role": "user", "content": [{"type": "input_text", "text": "a"}, dict(image)]}]
    for n in range(4):
        items.append({"type": "function_call_output", "call_id": f"v{n}", "output": [dict(image)]})
    items.append({"role": "user", "content": [dict(image)]})
    changed, _ = archive_old_images(items, keep_recent=2)
    assert changed == 4
    remaining = [p for item in items for key in ("content", "output") if isinstance(item.get(key), list)
                 for p in item[key] if p.get("type") == "input_image"]
    assert len(remaining) == 2 and items[-1]["content"][0]["type"] == "input_image"


def test_inline_media_no_longer_skips_text_compression(tmp_path):
    store = SourceStore(tmp_path)
    pipeline = FullCompressionPipeline(source_store=store, token_counter=quarter,
                                       config=FullCompressionConfig(max_remote_calls=0, max_remote_tokens=0,
                                                                    session_managed=True))
    image = {"type": "input_image", "image_url": "data:image/png;base64," + "A" * (_MAX_BODY_BYTES + 1024)}
    body = {"model": "gpt-5", "tools": [READER], "input": [{"role": "user", "content": [
        {"type": "input_text", "text": "Summarize the logs."}, image]}] + tool_pair(1, lines=400)}
    raw = json.dumps(body).encode()
    assert len(raw) > _MAX_BODY_BYTES
    sent, observation = pipeline.compress(raw)
    assert observation.status == "compressed"
    assert json.loads(sent)["input"][0]["content"][1] == image
    # Media and encrypted reasoning do not inflate the request estimate.
    assert observation.full_request_tokens_before_estimate < 100_000


def test_history_trim_accepts_reasoning_items_inside_whole_turns():
    items = []
    for n in range(6):
        items += [{"role": "user", "content": f"Task {n}"},
                  {"type": "reasoning", "encrypted_content": "x" * 50, "summary": []},
                  {"role": "assistant", "content": f"Answer {n} " * 200}]
    body = {"input": items}
    trimmed, archive = trim_history(body, original_body=body, budget=4000, keep_turns=2, count=len,
                                    store=SourceStore(), archive_notice=True)
    assert archive and archive["removed_messages"] % 3 == 0
    assert trimmed["input"][-3:] == items[-3:]


def test_terminal_cleanup_is_deterministic_and_keeps_content():
    text = "\x1b[31mERROR\x1b[0m build\r\n10%\r50%\r100%\nsame\nsame\nsame\nsame\nend"
    cleaned = clean_tool_text(text)
    assert cleaned == "ERROR build\n100%\nsame\n[previous line repeated 3 more times]\nend"
    assert clean_tool_text(cleaned) == cleaned


def test_media_free_count_ignores_media_and_ciphertext():
    count = media_free(len)
    body = json.dumps({"a": "data:image/png;base64," + "A" * 1000, "encrypted_content": "z" * 1000, "t": "hi"})
    assert count(body) < 80


def test_token_panel_reports_cache_weighted_input_and_calibration(tmp_path, monkeypatch):
    from codexscope.token_panel import token_panel_snapshot
    monkeypatch.setenv("LINGMOU_CACHE_PRICE_RATIO", "0.25")
    rows = [{"request_id": "r1", "status": "completed", "official_usage": {"input_tokens": 500, "cached_input_tokens": 400,
             "output_tokens": 5, "total_tokens": 505},
             "compression": {"full_request_tokens_after_estimate": 1000, "cache_prefix": {"break": {"cause": "client"}}}},
            {"request_id": "r2", "status": "completed", "official_usage": {"input_tokens": 700, "cached_input_tokens": 100,
             "output_tokens": 5, "total_tokens": 705},
             "compression": {"full_request_tokens_after_estimate": 1400, "cache_prefix": {"checkpoint": {"performed": True},
                                                                                         "break": {"cause": "lingmou"}}}}]
    snapshot = {"running": True, "usage_ledger": {
        "totals": {"requests": 2, "requests_with_official_usage": 2, "official_input_tokens": 1200,
                   "official_output_tokens": 10, "official_total_tokens": 1210},
        "tasks": {"t": {"downstream": {"cached_input_tokens": 500}}}, "recent_requests": rows},
        "input_compression": {"requests": 2, "full_request_tokens_before_estimate": 4000,
                              "full_request_tokens_after_estimate": 2400, "session": {"declined_checkpoints": 2}}}
    panel = token_panel_snapshot(tmp_path, provider_snapshot=snapshot, allow_usage_fallback=False)
    official = panel["official"]
    assert official["uncached_input_tokens"] == 700 and official["effective_input_tokens"] == 825
    assert official["cache_hit_percent"] == 41.7 and official["cache_price_ratio"] == .25
    assert panel["calibration"]["official_per_local"] == .5 and panel["calibration"]["saved"] == 800
    assert panel["cache"] == {"recent_breaks_by_lingmou": 1, "recent_breaks_by_client": 1,
                              "recent_checkpoints": 1, "declined_checkpoints": 2}
    assert [row["cache_break"] for row in panel["recent_requests"]] == ["client", "lingmou"]
    assert panel["recent_requests"][1]["checkpoint"] is True


EXEC_DOC = ("Run JavaScript code to orchestrate tool calls.\n- Nested tools are on `tools`.\n\n"
            + "".join(f"### `tool_{i}`\nDoes thing {i}. More detail follows here.\n\nexec tool declaration:\n```ts\n"
                      f"declare const tools: {{ tool_{i}(args: {{\n  // Explains the argument at length.\n"
                      f"  value_{i}: string;\n}}): Promise<unknown>; }};\n```\n" + "Extra guidance line.\n" * 30
                      for i in range(6)))
STYLE_PROMPT = ("# How you work\nBe precise.\n\n## Personality\n" + "Friendly tone.\n" * 40
                + "## Task execution\nKeep going until done.\n\n## Presenting your work and final message\n"
                + "Format answers.\n" * 60 + "### Final answer structure and style guidelines\n" + "Use bullets.\n" * 40
                + "# Tool Guidelines\nUse rg.\n")


def test_header_abbreviation_is_recoverable_and_keeps_declarations():
    from codexscope.header_compression import compact_tool_definitions, defer_style_sections
    import re
    store = SourceStore()
    tools = [{"type": "custom", "name": "exec", "description": EXEC_DOC}, READER]
    reader = copy.deepcopy(READER)
    assert compact_tool_definitions(tools, store=store, count=quarter) == 1
    short = tools[0]["description"]
    assert len(short) < len(EXEC_DOC) * .7 and tools[1] == reader
    assert "value_3: string;" in short and "Explains the argument" not in short
    compact = defer_style_sections(STYLE_PROMPT, store=store, count=quarter)
    assert "Keep going until done." in compact and "Use rg." in compact
    assert "Friendly tone." not in compact and "Use bullets." not in compact
    for text, original in ((short, EXEC_DOC), (compact, STYLE_PROMPT)):
        for source_id, start, end in re.findall(r'source_id="([0-9a-f]{64})",start_line=(\d+),end_line=(\d+)', text):
            section = store.read(source_id, int(start), int(end))["text"]
            assert section.startswith("#") and section in original


def test_max_mode_compresses_headers_and_history_beyond_full():
    def run(mode):
        compressor = DesktopCompressor(mode, SourceStore(), SERVER, token_counter=quarter)
        body = base_body()
        body["tools"] = [{"type": "custom", "name": "exec", "description": EXEC_DOC}, READER]
        body["input"].insert(0, {"role": "developer", "content": STYLE_PROMPT})
        for n in range(14):
            prose = "\n".join(f"{word} {n} reads {i} distinct notes about module {i * n} and {word[::-1]}"
                              for i, word in enumerate(["alpha", "beta", "gamma", "delta", "omega", "sigma"] * 12))
            body["input"] += tool_pair(n, text=prose)
            body["input"][-2]["input"] += "\n// script body " + "x" * 1500
            got, observation = send(compressor, body)
        return got, observation
    full, full_obs = run("full")
    maximum, max_obs = run("max")
    assert max_obs.full_request_tokens_after_estimate < full_obs.full_request_tokens_after_estimate * .7
    assert full_obs.full_request_tokens_before_estimate == max_obs.full_request_tokens_before_estimate
    assert maximum["tools"][-1] == READER and "Abbreviated by Lingmou" in maximum["tools"][0]["description"]
    assert "Style guidance deferred" in json.dumps(maximum["input"][0])
    # The newest calls and outputs are always sent in full.
    assert maximum["input"][-3:] == full["input"][-3:]
    assert any("Lingmou archived this applied input" in item.get("input", "") for item in maximum["input"])
