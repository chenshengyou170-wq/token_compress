"""Formal, repeatable acceptance scenario for the live token dashboard.

The scenario models a production-style repository security review in one Agent
session: silent reasoning, streamed reasoning/answers, a command tool, an
approval-gated file change, tests, three model calls in one turn, and a second
turn.  It never calls a paid model API; documented app-server envelopes drive
the same live reducer used by ``codexscope monitor``.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .live_status import LiveSessionStatus, consume_envelope
from .live_status_server import (
    DEFAULT_LIVE_HOST,
    create_live_status_server,
)
from .storage import atomic_json_dump
from .util import now_iso


SCENARIO_NAME = "repository_security_review_and_fix"
PRIVATE_SENTINELS = (
    "CONFIDENTIAL-PAYMENT-INCIDENT-8472",
    "private streamed remediation detail",
)


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    name: str
    description: str
    direction: str | None = None
    message: Mapping[str, Any] | None = None
    checkpoint: str | None = None
    wait_s: float = 0.10

    def envelope(self, sequence: int) -> dict[str, Any] | None:
        if self.message is None or self.direction is None:
            return None
        return {
            "seq": sequence,
            "connection_id": "formal-scenario",
            "direction": self.direction,
            "wall_time": time.time(),
            "wall_time_ns": time.time_ns(),
            "mono_ns": time.monotonic_ns(),
            "message": dict(self.message),
        }


def _notification(method: str, params: Mapping[str, Any]) -> dict[str, Any]:
    return {"method": method, "params": dict(params)}


def _usage(
    *,
    thread_id: str,
    turn_id: str,
    last_input: int,
    last_cached: int,
    last_output: int,
    last_reasoning: int,
    total_input: int,
    total_cached: int,
    total_output: int,
    total_reasoning: int,
) -> dict[str, Any]:
    return _notification(
        "thread/tokenUsage/updated",
        {
            "threadId": thread_id,
            "turnId": turn_id,
            "tokenUsage": {
                "last": {
                    "inputTokens": last_input,
                    "cachedInputTokens": last_cached,
                    "outputTokens": last_output,
                    "reasoningOutputTokens": last_reasoning,
                    "totalTokens": last_input + last_output,
                },
                "total": {
                    "inputTokens": total_input,
                    "cachedInputTokens": total_cached,
                    "outputTokens": total_output,
                    "reasoningOutputTokens": total_reasoning,
                    "totalTokens": total_input + total_output,
                },
                "modelContextWindow": 258_400,
            },
        },
    )


def formal_scenario_steps() -> tuple[ScenarioStep, ...]:
    """Return the canonical multi-call, multi-tool acceptance sequence."""

    thread_id = "thread-security-review"
    turn_1 = "turn-review-and-fix"
    turn_2 = "turn-follow-up"
    return (
        ScenarioStep(
            "thread_ready",
            "Resolve the remote model before the first request.",
            "server_to_client",
            _notification(
                "thread/started",
                {"thread": {"id": thread_id, "model": "gpt-5.4"}},
            ),
        ),
        ScenarioStep(
            "request_submitted",
            "Submit a long bilingual security-review request.",
            "client_to_server",
            _notification(
                "turn/start",
                {
                    "threadId": thread_id,
                    "input": [
                        {
                            "type": "text",
                            "text": (
                                "Audit the payment retry subsystem, reproduce the race, "
                                "patch it, and run regression tests. Incident reference: "
                                f"{PRIVATE_SENTINELS[0]}。请给出风险边界和验证证据。"
                            ),
                        }
                    ],
                },
            ),
        ),
        ScenarioStep(
            "turn_1_started",
            "The first Agent turn becomes active.",
            "server_to_client",
            _notification(
                "turn/started",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_1, "status": "inProgress"},
                },
            ),
            checkpoint="request_started",
        ),
        ScenarioStep(
            "silent_reasoning",
            "No visible delta while the remote model reasons.",
            checkpoint="silent_reasoning",
            wait_s=0.65,
        ),
        ScenarioStep(
            "reasoning_item",
            "App-server surfaces a reasoning item.",
            "server_to_client",
            _notification(
                "item/started",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {"id": "reason-1", "type": "reasoning"},
                },
            ),
        ),
        ScenarioStep(
            "reasoning_delta",
            "A surfaced reasoning summary begins streaming.",
            "server_to_client",
            _notification(
                "item/reasoning/summaryTextDelta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "reason-1",
                    "delta": "先定位重试状态机、幂等键和并发写入窗口。",
                },
            ),
            checkpoint="streaming_reasoning",
        ),
        ScenarioStep(
            "analysis_delta",
            "The model explains its first inspection plan.",
            "server_to_client",
            _notification(
                "item/agentMessage/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "answer-1",
                    "delta": "I will inspect the retry state transitions and run the focused tests. ",
                },
            ),
        ),
        ScenarioStep(
            "analysis_private_delta",
            "A second answer delta verifies that text never enters status JSON.",
            "server_to_client",
            _notification(
                "item/agentMessage/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "answer-1",
                    "delta": PRIVATE_SENTINELS[1],
                },
            ),
            checkpoint="streaming_answer",
        ),
        ScenarioStep(
            "inspection_tool_started",
            "The model call yields to a local command tool.",
            "server_to_client",
            _notification(
                "item/started",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {
                        "id": "cmd-inspect",
                        "type": "commandExecution",
                        "status": "inProgress",
                        "source": "unifiedExecStartup",
                        "command": "python3 -m pytest -q tests/test_live_status.py",
                    },
                },
            ),
            checkpoint="tool_paused",
        ),
        ScenarioStep(
            "slice_1_usage",
            "Official usage for model call 1 arrives while the tool is active.",
            "server_to_client",
            _usage(
                thread_id=thread_id,
                turn_id=turn_1,
                last_input=12_000,
                last_cached=9_000,
                last_output=800,
                last_reasoning=620,
                total_input=12_000,
                total_cached=9_000,
                total_output=800,
                total_reasoning=620,
            ),
            checkpoint="slice_1_exact_during_tool",
        ),
        ScenarioStep(
            "inspection_output",
            "Local command output must not be counted as model output.",
            "server_to_client",
            _notification(
                "item/commandExecution/outputDelta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "cmd-inspect",
                    "delta": "17 focused tests collected\n",
                },
            ),
        ),
        ScenarioStep(
            "inspection_tool_completed",
            "Tool completion starts model call 2 with the exact baseline retained.",
            "server_to_client",
            _notification(
                "item/completed",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {
                        "id": "cmd-inspect",
                        "type": "commandExecution",
                        "status": "completed",
                    },
                },
            ),
            checkpoint="post_tool_waiting",
        ),
        ScenarioStep(
            "plan_delta",
            "Model call 2 streams a remediation plan.",
            "server_to_client",
            _notification(
                "item/plan/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "plan-1",
                    "delta": "Add a compare-and-swap guard, then test duplicate callbacks.",
                },
            ),
        ),
        ScenarioStep(
            "remediation_delta",
            "Model call 2 finishes its visible proposal.",
            "server_to_client",
            _notification(
                "item/agentMessage/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "answer-2",
                    "delta": "The race is reproducible; the patch needs one guarded state transition.",
                },
            ),
            checkpoint="second_model_streaming",
        ),
        ScenarioStep(
            "slice_2_usage",
            "Official usage reconciles model call 2 without altering prior exact data.",
            "server_to_client",
            _usage(
                thread_id=thread_id,
                turn_id=turn_1,
                last_input=13_400,
                last_cached=10_600,
                last_output=450,
                last_reasoning=300,
                total_input=25_400,
                total_cached=19_600,
                total_output=1_250,
                total_reasoning=920,
            ),
            checkpoint="slice_2_exact",
        ),
        ScenarioStep(
            "file_change_started",
            "A protected file change begins.",
            "server_to_client",
            _notification(
                "item/started",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {"id": "patch-1", "type": "fileChange"},
                },
            ),
        ),
        ScenarioStep(
            "approval_requested",
            "The UI must distinguish awaiting user from model silence.",
            "server_to_client",
            _notification(
                "item/fileChange/requestApproval",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "patch-1",
                },
            ),
            checkpoint="awaiting_approval",
        ),
        ScenarioStep(
            "approval_resolved",
            "The user approves the protected patch.",
            "server_to_client",
            _notification(
                "serverRequest/resolved",
                {"threadId": thread_id, "turnId": turn_1},
            ),
        ),
        ScenarioStep(
            "file_change_completed",
            "Patch completion starts model call 3.",
            "server_to_client",
            _notification(
                "item/completed",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {
                        "id": "patch-1",
                        "type": "fileChange",
                        "status": "completed",
                    },
                },
            ),
            checkpoint="patch_completed_next_model",
        ),
        ScenarioStep(
            "regression_tool_started",
            "Regression tests pause the next model-wait timer.",
            "server_to_client",
            _notification(
                "item/started",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {
                        "id": "cmd-tests",
                        "type": "commandExecution",
                        "status": "inProgress",
                        "source": "unifiedExecStartup",
                        "command": "python3 -m pytest -q",
                    },
                },
            ),
            checkpoint="regression_tool_paused",
        ),
        ScenarioStep(
            "regression_output",
            "The test runner streams non-model output.",
            "server_to_client",
            _notification(
                "item/commandExecution/outputDelta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "cmd-tests",
                    "delta": "216 passed in 12.60s\n",
                },
            ),
        ),
        ScenarioStep(
            "regression_tool_completed",
            "Regression tests complete and model call 3 resumes.",
            "server_to_client",
            _notification(
                "item/completed",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "item": {
                        "id": "cmd-tests",
                        "type": "commandExecution",
                        "status": "completed",
                    },
                },
            ),
        ),
        ScenarioStep(
            "final_reasoning_delta",
            "Model call 3 reasons over regression evidence.",
            "server_to_client",
            _notification(
                "item/reasoning/textDelta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "reason-3",
                    "delta": "回归通过，确认幂等保护覆盖重复回调与乱序完成。",
                },
            ),
        ),
        ScenarioStep(
            "final_answer_delta",
            "The final response streams with the third slice isolated.",
            "server_to_client",
            _notification(
                "item/agentMessage/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_1,
                    "itemId": "answer-3",
                    "delta": "Fixed the retry race and verified the focused and full regression suites.",
                },
            ),
            checkpoint="final_model_streaming",
        ),
        ScenarioStep(
            "slice_3_usage",
            "Official usage reconciles the third model call.",
            "server_to_client",
            _usage(
                thread_id=thread_id,
                turn_id=turn_1,
                last_input=14_200,
                last_cached=11_200,
                last_output=1_000,
                last_reasoning=580,
                total_input=39_600,
                total_cached=30_800,
                total_output=2_250,
                total_reasoning=1_500,
            ),
        ),
        ScenarioStep(
            "turn_1_completed",
            "Turn 1 becomes idle with only exact totals displayed.",
            "server_to_client",
            _notification(
                "turn/completed",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_1, "status": "completed"},
                },
            ),
            checkpoint="turn_1_complete",
        ),
        ScenarioStep(
            "follow_up_submitted",
            "A second turn tests isolation from the previous turn.",
            "client_to_server",
            _notification(
                "turn/start",
                {
                    "threadId": thread_id,
                    "input": [
                        {
                            "type": "text",
                            "text": "Summarize the residual production risk in three bullets.",
                        }
                    ],
                },
            ),
        ),
        ScenarioStep(
            "turn_2_started",
            "Turn 2 gets a new in-flight slice and retains the exact baseline.",
            "server_to_client",
            _notification(
                "turn/started",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_2, "status": "inProgress"},
                },
            ),
            checkpoint="turn_2_started",
        ),
        ScenarioStep(
            "follow_up_delta",
            "The follow-up answer streams independently.",
            "server_to_client",
            _notification(
                "item/agentMessage/delta",
                {
                    "threadId": thread_id,
                    "turnId": turn_2,
                    "itemId": "answer-follow-up",
                    "delta": "Residual risk is limited to provider retries outside the guarded transaction.",
                },
            ),
        ),
        ScenarioStep(
            "turn_2_usage",
            "The fourth official usage update closes the follow-up slice.",
            "server_to_client",
            _usage(
                thread_id=thread_id,
                turn_id=turn_2,
                last_input=15_000,
                last_cached=12_000,
                last_output=120,
                last_reasoning=45,
                total_input=54_600,
                total_cached=42_800,
                total_output=2_370,
                total_reasoning=1_545,
            ),
        ),
        ScenarioStep(
            "turn_2_completed",
            "The session ends with exact cumulative usage and four reconciliations.",
            "server_to_client",
            _notification(
                "turn/completed",
                {
                    "threadId": thread_id,
                    "turn": {"id": turn_2, "status": "completed"},
                },
            ),
            checkpoint="all_complete",
        ),
    )


def _nested(payload: Mapping[str, Any], *keys: str) -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def validate_checkpoint(
    checkpoint: str,
    payload: Mapping[str, Any],
    history: Mapping[str, Mapping[str, Any]],
    *,
    minimum_silent_elapsed_s: float = 0.45,
) -> list[str]:
    """Validate one formal checkpoint and return passed assertion labels."""

    live = payload.get("inflight_token_estimate")
    live = live if isinstance(live, Mapping) else {}
    total = _nested(payload, "token_usage", "total")
    total = total if isinstance(total, Mapping) else {}
    passed: list[str] = []

    def require(condition: object, label: str) -> None:
        if not condition:
            raise AssertionError(f"{checkpoint}: {label}")
        passed.append(label)

    if checkpoint == "request_started":
        require(live.get("active") is True, "in-flight meter starts immediately")
        require(payload.get("activity") == "waiting_model", "activity is waiting_model")
        require(int(live.get("input_tokens_observed") or 0) > 0, "visible prompt is tokenized")
        require("~" in str(payload.get("status_line")), "status line marks estimate")
    elif checkpoint == "silent_reasoning":
        require(live.get("active") is True, "silent request remains active")
        require(int(live.get("output_tokens_observed") or 0) == 0, "no fake visible output")
        require(live.get("seconds_since_delta") is None, "silence is explicit")
        require(
            float(live.get("active_elapsed_seconds") or 0)
            >= minimum_silent_elapsed_s,
            "active elapsed advances",
        )
    elif checkpoint in {"streaming_reasoning", "streaming_answer"}:
        require(payload.get("activity") == "streaming", "delta changes activity to streaming")
        require(int(live.get("output_tokens_observed") or 0) > 0, "observed output increases")
        require(int(live.get("delta_count") or 0) > 0, "delta counter advances")
        if checkpoint == "streaming_answer":
            previous = history["streaming_reasoning"]["inflight_token_estimate"]
            require(
                int(live.get("output_tokens_observed") or 0)
                >= int(previous.get("output_tokens_observed") or 0),
                "observed output is monotonic",
            )
            serialized = json.dumps(payload, ensure_ascii=False)
            require(
                all(sentinel not in serialized for sentinel in PRIVATE_SENTINELS),
                "status JSON contains no prompt or response text",
            )
    elif checkpoint == "tool_paused":
        require(payload.get("activity") == "local_tool", "tool activity is distinct")
        require(live.get("active") is True, "unfinished model slice is retained")
        require(live.get("paused") is True, "model timer pauses during tool")
        require(
            int(live.get("output_tool_argument_tokens_observed") or 0) > 0,
            "model-authored tool arguments count as output",
        )
        require(
            int(live.get("output_tokens_observed") or 0)
            == int(live.get("output_text_tokens_observed") or 0)
            + int(live.get("output_tool_argument_tokens_observed") or 0),
            "observed output equals text plus tool arguments",
        )
    elif checkpoint == "slice_1_exact_during_tool":
        require(live.get("active") is False, "official usage closes estimate")
        require(int(total.get("total_tokens") or 0) == 12_800, "first exact total is authoritative")
        require(int(live.get("reconciliation_count") or 0) == 1, "first reconciliation recorded")
        require(payload.get("activity") == "local_tool", "tool remains active after reconciliation")
    elif checkpoint == "post_tool_waiting":
        require(live.get("active") is True, "second model slice starts")
        require(int(live.get("slice_index") or 0) == 2, "slice index increments")
        require(int(live.get("baseline_exact_total_tokens") or 0) == 12_800, "exact baseline is retained")
        require(int(live.get("delta_count") or 0) == 0, "delta counter resets per slice")
    elif checkpoint == "second_model_streaming":
        require(live.get("active") is True, "second model call is active")
        require(int(live.get("slice_index") or 0) == 2, "second call stays isolated")
        require(
            int(live.get("session_tokens_likely_p50") or 0) > 12_800,
            "live session estimate exceeds exact baseline",
        )
        require(int(total.get("total_tokens") or 0) == 12_800, "estimate does not mutate exact total")
    elif checkpoint == "slice_2_exact":
        require(live.get("active") is False, "second estimate reconciles")
        require(int(total.get("total_tokens") or 0) == 26_650, "second cumulative exact total matches")
        require(int(live.get("reconciliation_count") or 0) == 2, "second reconciliation recorded")
    elif checkpoint == "awaiting_approval":
        require(payload.get("activity") == "awaiting_user", "approval is not model waiting")
        require(int(payload.get("pending_approvals") or 0) == 1, "approval count is visible")
        require(live.get("active") is False, "no phantom model estimate during approval")
    elif checkpoint == "patch_completed_next_model":
        require(live.get("active") is True, "third model slice starts after patch")
        require(int(live.get("slice_index") or 0) == 3, "third slice is isolated")
        require(int(live.get("baseline_exact_total_tokens") or 0) == 26_650, "third slice uses exact baseline")
    elif checkpoint == "regression_tool_paused":
        require(payload.get("activity") == "local_tool", "regression command is local_tool")
        require(live.get("paused") is True, "third slice timer pauses for tests")
    elif checkpoint == "final_model_streaming":
        require(payload.get("activity") == "streaming", "final response is streaming")
        require(int(live.get("slice_index") or 0) == 3, "final output belongs to third slice")
        require(int(live.get("output_tokens_observed") or 0) > 0, "third slice output is observed")
    elif checkpoint == "turn_1_complete":
        require(payload.get("activity") == "idle", "completed turn is idle")
        require(live.get("active") is False, "turn completion has no in-flight estimate")
        require(int(total.get("total_tokens") or 0) == 41_850, "turn 1 exact total matches")
        require(int(live.get("reconciliation_count") or 0) == 3, "three model calls reconciled")
        require("~" not in str(payload.get("status_line")), "completed line is exact")
    elif checkpoint == "turn_2_started":
        require(live.get("active") is True, "new turn starts a new estimate")
        require(payload.get("turn_id") == "turn-follow-up", "turn id does not leak from turn 1")
        require(int(live.get("slice_index") or 0) == 4, "slice sequence continues without collision")
        require(int(live.get("output_tokens_observed") or 0) == 0, "new turn output starts at zero")
        require(int(live.get("baseline_exact_total_tokens") or 0) == 41_850, "new turn retains exact session baseline")
    elif checkpoint == "all_complete":
        require(payload.get("activity") == "idle", "session finishes idle")
        require(live.get("active") is False, "no estimate remains")
        require(int(total.get("total_tokens") or 0) == 56_970, "final exact cumulative total matches")
        require(int(live.get("reconciliation_count") or 0) == 4, "all four model calls reconciled")
        require(live.get("estimate_not_billable") is True, "estimate remains non-billable metadata")
    else:
        raise KeyError(f"unknown formal checkpoint: {checkpoint}")
    return passed


CheckpointCallback = Callable[[str, Mapping[str, Any]], None]


def run_formal_scenario(
    run_dir: Path,
    *,
    delay_scale: float = 1.0,
    checkpoint_callback: CheckpointCallback | None = None,
) -> dict[str, Any]:
    """Execute the formal scenario and write live status plus an audit report."""

    if delay_scale < 0:
        raise ValueError("delay_scale cannot be negative")
    root = run_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    status_path = root / "live_status.json"
    result_path = root / "formal_scenario_result.json"
    status = LiveSessionStatus()
    history: dict[str, Mapping[str, Any]] = {}
    checkpoint_results: list[dict[str, Any]] = []
    started = time.monotonic()
    sequence = 0

    for step in formal_scenario_steps():
        if step.wait_s and delay_scale:
            time.sleep(step.wait_s * delay_scale)
        sequence += 1
        envelope = step.envelope(sequence)
        if envelope is not None:
            consume_envelope(status, envelope)
        payload = status.to_dict()
        payload.update(
            {
                "schema_version": "1.0",
                "run_id": f"formal-{SCENARIO_NAME}",
                "run_dir": os.fspath(root),
                "updated_at": now_iso(),
                "scenario_phase": step.name,
            }
        )
        atomic_json_dump(status_path, payload)
        if step.checkpoint is None:
            continue
        assertions = validate_checkpoint(
            step.checkpoint,
            payload,
            history,
            minimum_silent_elapsed_s=min(0.45, 0.5 * delay_scale),
        )
        history[step.checkpoint] = payload
        checkpoint_results.append(
            {
                "checkpoint": step.checkpoint,
                "description": step.description,
                "passed_assertions": assertions,
                "status_line": payload.get("status_line"),
                "activity": payload.get("activity"),
            }
        )
        if checkpoint_callback is not None:
            checkpoint_callback(step.checkpoint, payload)

    report = {
        "schema_version": "1.0",
        "scenario": SCENARIO_NAME,
        "status": "passed",
        "checkpoint_count": len(checkpoint_results),
        "assertion_count": sum(
            len(result["passed_assertions"]) for result in checkpoint_results
        ),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "live_status_path": os.fspath(status_path),
        "checkpoints": checkpoint_results,
    }
    atomic_json_dump(result_path, report)
    return report


def _tcp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m codexscope.live_status_scenario",
        description="Run the formal multi-call live-token acceptance scenario.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="scenario output directory (default: a new temporary directory)",
    )
    parser.add_argument(
        "--delay-scale",
        type=float,
        default=1.0,
        help="multiply phase delays (default: 1.0; use 0 for a fast test)",
    )
    parser.add_argument("--web", action="store_true", help="serve the live dashboard")
    parser.add_argument("--host", default=DEFAULT_LIVE_HOST)
    parser.add_argument("--port", type=_tcp_port, default=8765)
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="open the dashboard (implies --web)",
    )
    parser.add_argument(
        "--no-hold",
        action="store_true",
        help="stop the demo web server immediately after the scenario",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = (
        args.out.expanduser().resolve()
        if args.out is not None
        else Path(tempfile.mkdtemp(prefix="codexscope-formal-live-"))
    )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    status_path = root / "live_status.json"
    server = None
    server_thread = None
    if args.web or args.open_browser:
        server = create_live_status_server(
            status_path,
            host=args.host,
            port=args.port,
            frontend="token",
        )
        server_thread = threading.Thread(
            target=server.serve_forever,
            name="codexscope-formal-live-server",
            daemon=True,
        )
        server_thread.start()
        actual_port = int(server.server_address[1])
        display_host = "127.0.0.1" if args.host in {"0.0.0.0", "::", ""} else args.host
        url_host = f"[{display_host}]" if ":" in display_host else display_host
        url = f"http://{url_host}:{actual_port}/live"
        print(f"dashboard: {url}", flush=True)
        if args.open_browser:
            webbrowser.open(url)
        time.sleep(0.35)

    try:
        report = run_formal_scenario(root, delay_scale=args.delay_scale)
        print(
            f"scenario: {report['status']} | checkpoints={report['checkpoint_count']} "
            f"assertions={report['assertion_count']} | {root}",
            flush=True,
        )
        for checkpoint in report["checkpoints"]:
            print(
                f"  PASS {checkpoint['checkpoint']:<30} "
                f"{checkpoint['activity']:<14} {checkpoint['status_line']}",
                flush=True,
            )
        if server is not None and not args.no_hold:
            print("Scenario complete; dashboard remains available. Press Ctrl-C to stop.")
            try:
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                pass
        return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
