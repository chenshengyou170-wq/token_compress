"""Desktop scope boundaries, including requests that finish out of order."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from codexscope.conversation_usage import ConversationUsage
from codexscope.desktop_companion import Companion
from codexscope.request_usage_ledger import RequestAccountingTracker


def body(thread="a", turn="1", **metadata):
    return {"model": "test", "input": "A short message", "client_metadata": {
        "x-codex-turn-metadata": json.dumps({"thread_id": thread, "turn_id": turn,
            "request_kind": "turn", "thread_source": "user", **metadata})}}


def until(check):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.01)
    assert check()


@pytest.mark.parametrize("metadata", [
    {"request_kind": "prewarm"}, {"request_kind": "memory"},
    {"request_kind": "compaction"}, {"subagent_kind": "review"},
    {"thread_source": "auto_review"}, {"thread_id": None}, {"turn_id": None},
])
def test_background_and_unidentified_calls_do_not_start_a_conversation(metadata):
    record = RequestAccountingTracker().observe({}, body(**metadata))
    scope = ConversationUsage()
    assert scope.begin(record) is None
    assert not scope.snapshot()["scope"]["started"]


def test_header_metadata_and_host_task_labels_preserve_independent_conversation_identity():
    tracker = RequestAccountingTracker()
    raw = body("private-thread", "private-turn")["client_metadata"]["x-codex-turn-metadata"]
    record = tracker.observe({"x-codex-turn-metadata": raw,
        "X-Lingmou-Task-Id": "host-task", "X-Lingmou-Purpose": "generation", "X-Lingmou-Attempt": "1"},
        {"model": "test", "input": "private-body"})
    assert record["conversation_foreground"] and record["task_id"] == "host-task"
    assert all(value not in json.dumps(record) for value in ("private-thread", "private-turn", "private-body"))
    warm = tracker.observe({}, {**body(), "generate": False})
    assert not warm["conversation_foreground"] and warm["request_kind"] == "prewarm"


def test_conversation_totals_survive_recent_limit_but_never_return_from_an_old_window():
    scope, tracker = ConversationUsage(), RequestAccountingTracker()
    def complete(thread, turn, timestamp):
        record = {**tracker.observe({}, body(thread, turn, turn_started_at_unix_ms=timestamp)),
                  "request_id": turn, "status": "completed", "official_usage": {"input_tokens": 10, "output_tokens": 1}}
        epoch = scope.begin(record)
        scope.finish(epoch, record)
        return epoch
    for i in range(205):
        complete("a", str(i), i + 1)
    before = scope.snapshot()
    assert before["usage_ledger"]["totals"]["official_total_tokens"] == 205 * 11
    assert len(before["usage_ledger"]["recent_requests"]) == 200
    complete("b", "new", 300)
    assert complete("a", "previously-unseen-old-turn", 200) is None
    # Returning to A with a new turn begins another window, not A's old total.
    complete("a", "return", 400)
    after = scope.snapshot()
    assert after["scope"]["id"] == before["scope"]["id"]
    assert after["scope"]["requests"] == 1
    assert after["usage_ledger"]["totals"]["official_total_tokens"] == 11


def test_desktop_starts_empty_and_separates_new_conversation_from_late_old_requests(tmp_path):
    release_old, release_new = threading.Event(), threading.Event()
    old_waiting, new_waiting = threading.Event(), threading.Event()

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            marker = request["input"]
            if marker == "old delayed":
                old_waiting.set()
                assert release_old.wait(10)
            if marker == "new delayed":
                new_waiting.set()
                assert release_new.wait(10)
            response = json.dumps({"usage": {"input_tokens": 100, "output_tokens": 5,
                                            "total_tokens": 105}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    config = tmp_path / "config.toml"
    config.write_text('model = "test"\n')
    companion = Companion(tmp_path / "state")
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        companion.connect(config_path=str(config), auth_kind="api", mode="off",
                          upstream=f"http://127.0.0.1:{upstream.server_port}/v1")
        headers = {"X-Lingmou-Relay-Token": companion.connection.record["access_token"]}
        def send(request):
            response = httpx.post(companion.tap.local_base_url + "/responses", json=request,
                                  headers=headers, trust_env=False, timeout=10)
            assert response.status_code == 200

        httpx.get(companion.tap.local_base_url + "/models", headers=headers, trust_env=False)
        send(body(request_kind="prewarm"))
        send({"model": "test", "input": "unattributed background"})
        until(lambda: companion.status()["active_requests"] == 0)
        initial = companion.status()
        assert initial["request_count"] == 3
        assert not initial["usage_scope"]["started"]
        assert initial["tokens"]["local"]["requests"] == 0
        assert initial["tokens"]["official"]["total_tokens"] is None
        assert not initial["tokens"]["recent_requests"]

        send(body(turn="1", turn_started_at_unix_ms=100))
        send(body(turn="2", turn_started_at_unix_ms=200))
        until(lambda: companion.status()["active_requests"] == 0)
        first = companion.status()
        assert first["tokens"]["official"]["total_tokens"] == 210
        assert first["tokens"]["local"]["requests"] == 2
        old = pool.submit(send, {**body(turn="3", turn_started_at_unix_ms=300), "input": "old delayed"})
        assert old_waiting.wait(5)
        new = pool.submit(send, {**body("b", "1", forked_from_thread_id="a", turn_started_at_unix_ms=400),
                                 "input": "new delayed"})
        assert new_waiting.wait(5)
        until(lambda: companion.status()["tokens"]["local"]["requests"] == 1)
        fresh = companion.status()
        assert fresh["usage_scope"]["id"] != first["usage_scope"]["id"]
        assert fresh["usage_scope"]["requests"] == fresh["usage_scope"]["active_requests"] == 1
        assert fresh["tokens"]["official"]["total_tokens"] is None
        assert not fresh["tokens"]["recent_requests"]
        assert fresh["tokens"]["local"]["before"] < first["tokens"]["local"]["before"]
        release_old.set()
        old.result(5)
        until(lambda: companion.status()["active_requests"] == 1)
        assert companion.status()["tokens"]["official"]["total_tokens"] is None
        # A further tool step in the old turn also cannot reclaim the display.
        send(body(turn="3", turn_started_at_unix_ms=300))
        assert companion.status()["usage_scope"]["id"] == fresh["usage_scope"]["id"]
        release_new.set()
        new.result(5)
        until(lambda: companion.status()["active_requests"] == 0)
        final = companion.status()
        assert final["tokens"]["official"]["total_tokens"] == 105
        assert final["tokens"]["local"]["requests"] == 1
        assert len(final["tokens"]["recent_requests"]) == 1
        send(body("b", "2", turn_started_at_unix_ms=500))
        until(lambda: companion.status()["active_requests"] == 0)
        assert companion.status()["tokens"]["official"]["total_tokens"] == 210
        # Diagnostic totals survive, but restarting never reuses their usage.
        assert companion.tap.stats_dict()["usage_ledger"]["totals"]["requests"] == 8
        companion.restart()
        assert not companion.status()["usage_scope"]["started"]
        assert companion.status()["tokens"]["official"]["total_tokens"] is None
        companion.disconnect()
        assert not companion.status()["usage_scope"]["started"]
        assert config.read_text() == 'model = "test"\n'
    finally:
        release_old.set()
        release_new.set()
        pool.shutdown(wait=True)
        companion.stop()
        if companion.connection.enabled:
            companion.connection.restore()
        upstream.shutdown()
        upstream.server_close()
        worker.join(2)
