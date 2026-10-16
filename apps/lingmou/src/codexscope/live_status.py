"""Real-time Codex session activity and token usage.

Consumed by the interactive monitor to classify silence (waiting on the remote
model vs running a local tool) and to render a compact status line. Protocol
shapes follow app-server ``thread/tokenUsage/updated`` notifications.
"""

from __future__ import annotations

import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .media_token_task import MediaTokenTaskTracker
from .proxy_usage import ProxyUsageMeter, ResidualCalibrator, default_token_counter
from .redaction import redact_event, redact_text
from .runtime_policy import merge_policy_decisions

Activity = str  # idle | waiting_model | streaming | local_tool | awaiting_user | stalled


MODEL_TEXT_OUTPUT_DELTA_METHODS = frozenset(
    {
        "item/agentMessage/delta",
        "item/plan/delta",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
    }
)
MODEL_TOOL_ARGUMENT_DELTA_METHODS = frozenset(
    {"response.function_call_arguments.delta"}
)
MODEL_OUTPUT_DELTA_METHODS = (
    MODEL_TEXT_OUTPUT_DELTA_METHODS | MODEL_TOOL_ARGUMENT_DELTA_METHODS
)

_INPUT_ESTIMATE_SOURCE_PRIORITY = {
    "request_body_heuristic": 10,
    "request_body_partial": 10,
    "codex_preflight": 20,
    "request_body_tokenized": 30,
    "provider_preflight_exact": 40,
}


_TOKEN_FIELDS = (
    ("inputTokens", "input_tokens"),
    ("cachedInputTokens", "cached_input_tokens"),
    ("outputTokens", "output_tokens"),
    ("reasoningOutputTokens", "reasoning_output_tokens"),
    ("totalTokens", "total_tokens"),
)

_LOCAL_ITEM_TYPES = frozenset(
    {
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "collabToolCall",
        "collabAgentToolCall",
        "webSearch",
        "imageView",
        "imageGeneration",
        "dynamicToolCall",
        "functionCall",
        "sleep",
    }
)

# These are lifecycle / presentation items, not local tool executions.  Keep
# this list explicit so a newly introduced app-server item is not silently
# counted as a tool before CodexScope understands its semantics.
_NON_TOOL_ITEM_TYPES = frozenset(
    {
        "userMessage",
        "agentMessage",
        "reasoning",
        "todoList",
        "plan",
        "contextCompaction",
        "enteredReviewMode",
        "exitedReviewMode",
        "subAgentActivity",
    }
)

_APPROVAL_METHODS = frozenset(
    {
        "item/commandExecution/requestApproval",
        "item/fileChange/requestApproval",
        "item/permissions/requestApproval",
        "item/tool/requestUserInput",
        "execCommandApproval",
        "applyPatchApproval",
    }
)


def _as_int(value: object) -> int | None:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and value >= 0 and value == int(value):
        return int(value)
    return None


def _input_text_fragments(value: object) -> list[str]:
    """Extract user-visible turn input without retaining it in status JSON."""

    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(_input_text_fragments(item))
        return result
    if not isinstance(value, Mapping):
        return []

    result = []
    text = value.get("text")
    if isinstance(text, str):
        result.append(text)
    content = value.get("content")
    if content is not None and content != text:
        result.extend(_input_text_fragments(content))
    return result


def _nearest_rank_value(samples: list[int], quantile: float) -> int:
    if not samples:
        return 0
    ordered = sorted(samples)
    rank = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[rank]


def _tool_context_payload(
    item: Mapping[str, Any], item_type: str
) -> Mapping[str, Any] | None:
    """Select model-visible tool output without retaining the underlying text."""

    if item_type == "webSearch" and "results" in item:
        return {"results": item["results"]}

    if item_type == "commandExecution":
        for key in ("aggregatedOutput", "aggregated_output", "output"):
            if key in item:
                return {key: item[key], "exitCode": _item_exit_code(item)}
        streams = {
            key: item[key]
            for key in ("stdout", "stderr")
            if key in item
        }
        if streams:
            streams["exitCode"] = _item_exit_code(item)
            return streams

    context_keys = (
        "result",
        "results",
        "output",
        "content",
        "changes",
        "response",
        "error",
    )
    selected = {key: item[key] for key in context_keys if key in item}
    return selected or None


def _model_tool_argument_payload(
    item: Mapping[str, Any], item_type: str
) -> object | None:
    """Select model-authored invocation arguments, never local tool output."""

    # userShell items are initiated by the user rather than generated by the
    # model, even though app-server represents them as command executions.
    if item_type == "commandExecution":
        if item.get("source") == "userShell":
            return None
        if "command" in item:
            return {"command": item["command"]}
        return None

    # MCP, dynamic, and generic function-call items preserve the original
    # argument object.  Serialize that object directly: the raw Responses
    # delta contains the argument JSON, not an additional `arguments` wrapper.
    if "arguments" in item:
        return item["arguments"]

    argument_keys_by_type = {
        "fileChange": ("changes",),
        "collabToolCall": ("prompt", "model", "reasoningEffort"),
        "collabAgentToolCall": ("prompt", "model", "reasoningEffort"),
        "webSearch": ("query",),
        "imageView": ("path",),
        "sleep": ("durationMs",),
    }
    keys = argument_keys_by_type.get(item_type, ())
    selected = {key: item[key] for key in keys if key in item}
    return selected or None


def _serialize_model_tool_arguments(value: object) -> str | None:
    """Return the complete argument prefix used only by the in-memory meter."""

    if isinstance(value, str):
        return value
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        return None


def normalize_token_breakdown(value: object) -> dict[str, int] | None:
    """Normalize one ``last`` / ``total`` token object to snake_case ints."""

    if not isinstance(value, Mapping):
        return None
    result: dict[str, int] = {}
    for camel, snake in _TOKEN_FIELDS:
        # Accept either protocol camelCase or already-normalized snake_case.
        count = _as_int(value.get(camel))
        if count is None:
            count = _as_int(value.get(snake))
        if count is None:
            return None
        result[snake] = count
    return result


def normalize_token_usage(value: object) -> dict[str, Any] | None:
    """Normalize a full tokenUsage payload from app-server."""

    if not isinstance(value, Mapping):
        return None
    last = normalize_token_breakdown(value.get("last"))
    total = normalize_token_breakdown(value.get("total"))
    if last is None or total is None:
        return None
    result: dict[str, Any] = {"last": last, "total": total}
    window = value.get("modelContextWindow")
    if window is None:
        window = value.get("model_context_window")
    if window is not None:
        parsed = _as_int(window)
        if parsed is None:
            return None
        result["model_context_window"] = parsed
    return result


def format_token_counts(total: Mapping[str, int], *, last: Mapping[str, int] | None = None) -> str:
    """Verbose one-line token summary (all fields)."""

    parts = [
        f"in={total.get('input_tokens', 0):,}",
        f"out={total.get('output_tokens', 0):,}",
        f"cache={total.get('cached_input_tokens', 0):,}",
        f"total={total.get('total_tokens', 0):,}",
    ]
    reasoning = int(total.get("reasoning_output_tokens") or 0)
    if reasoning:
        parts.insert(2, f"reason={reasoning:,}")
    line = " ".join(parts)
    if last is not None:
        delta_out = int(last.get("output_tokens") or 0)
        delta_in = int(last.get("input_tokens") or 0)
        line += f" | turn +in={delta_in:,} +out={delta_out:,}"
    return line


def format_count_k(value: int | float) -> str:
    """Format a token count in thousands, e.g. ``14.4k``."""

    number = float(value)
    if number < 0:
        number = 0.0
    if number < 1000:
        # Keep small values readable without a trailing .0k.
        if number == int(number):
            return str(int(number))
        return f"{number:.1f}"
    scaled = number / 1000.0
    # One decimal is enough for a status bar (14.4k, 1.0k).
    text = f"{scaled:.1f}".rstrip("0").rstrip(".")
    return f"{text}k"


def format_tokens_simple(total: Mapping[str, int] | None) -> str:
    """User-facing short line: just how many tokens were used (in k)."""

    if not total:
        return "tokens: n/a"
    total_n = int(total.get("total_tokens") or 0)
    in_n = int(total.get("input_tokens") or 0)
    out_n = int(total.get("output_tokens") or 0)
    return (
        f"tokens: {format_count_k(total_n)}  "
        f"(in {format_count_k(in_n)} / out {format_count_k(out_n)})"
    )


def format_tokens_live(
    total: Mapping[str, int] | None,
    inflight: Mapping[str, Any] | None,
) -> str:
    """Combine the last exact total with an explicitly estimated live slice."""

    if not inflight or not inflight.get("active"):
        return format_tokens_simple(total)
    likely_p50 = _as_int(inflight.get("session_tokens_likely_p50"))
    likely_p90 = _as_int(inflight.get("session_tokens_likely_p90"))
    observed_out = _as_int(inflight.get("output_tokens_observed")) or 0
    exact_total = _as_int(inflight.get("baseline_exact_total_tokens"))

    if likely_p50 is None or likely_p90 is None:
        return (
            f"tokens: live out>={format_count_k(observed_out)} "
            f"({inflight.get('output_source') or 'estimated'})"
        )
    likely = (
        format_count_k(likely_p50)
        if likely_p50 == likely_p90
        else f"{format_count_k(likely_p50)}-{format_count_k(likely_p90)}"
    )
    exact = (
        f"exact {format_count_k(exact_total)}; "
        if exact_total is not None
        else ""
    )
    return (
        f"tokens: ~{likely} live  "
        f"({exact}out>={format_count_k(observed_out)})"
    )


def _short_id(value: object, *, width: int = 8) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    return text if len(text) <= width else text[:width]


def _is_local_item_type(item_type: object) -> bool:
    """Return whether one app-server item represents user-observable work."""

    if item_type in _NON_TOOL_ITEM_TYPES:
        return False
    return item_type in _LOCAL_ITEM_TYPES


def _approval_decision(value: object) -> str | None:
    """Normalize only the decision label from a server-request response."""

    if not isinstance(value, Mapping):
        return None
    result = value.get("result")
    result = result if isinstance(result, Mapping) else {}
    raw = result.get("decision") or result.get("status")
    if isinstance(raw, Mapping) and raw:
        # Newer protocol variants use a tagged decision object, for example
        # {"acceptWithExecpolicyAmendment": {...}}.
        raw = next(iter(raw))
    if not isinstance(raw, str) or not raw.strip():
        if value.get("error") is not None:
            return "error"
        return None
    decision = raw.strip().replace("_", "").replace("-", "").lower()
    if decision in {
        "accept",
        "accepted",
        "approve",
        "approved",
        "allow",
        "allowed",
    } or decision.startswith("acceptwith"):
        return "accepted"
    if decision in {"decline", "declined", "deny", "denied", "reject", "rejected"}:
        return "declined"
    if decision in {"cancel", "cancelled", "canceled", "abort", "aborted"}:
        return "cancelled"
    return _display_text(decision, limit=64)


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[rank]


def _display_text(value: object, *, limit: int = 4_096) -> str | None:
    """Bound and credential-redact text before exposing it on the live API."""

    if isinstance(value, (list, tuple)) and all(
        isinstance(part, str) for part in value
    ):
        value = " ".join(value)
    if not isinstance(value, str):
        return None
    cleaned = redact_text(value).strip()
    if not cleaned:
        return None
    if len(cleaned) > limit:
        return f"{cleaned[:limit]}…"
    return cleaned


def _approval_policy_metadata(value: object) -> dict[str, Any] | None:
    """Keep only bounded, display-safe fields from an internal policy decision."""

    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    for key in (
        "policy_id",
        "mode",
        "action",
        "decision",
        "stage",
        "blocking_rule",
        "asset",
        "channel",
        "policy_name",
        "business_summary",
    ):
        text = _display_text(value.get(key), limit=160)
        if text:
            result[key] = text
    raw_rules = value.get("matched_rules")
    if isinstance(raw_rules, list):
        rules = [
            rule
            for item in raw_rules[:8]
            if (rule := _display_text(item, limit=64))
        ]
        if rules:
            result["matched_rules"] = rules
    raw_decisions = value.get("policy_decisions")
    if isinstance(raw_decisions, list):
        decisions: list[dict[str, Any]] = []
        for raw in raw_decisions[:24]:
            if not isinstance(raw, Mapping):
                continue
            decision: dict[str, Any] = {}
            for key, limit in (
                ("schema_version", 64),
                ("policy_id", 128),
                ("policy_name", 160),
                ("level", 32),
                ("mode", 32),
                ("stage", 64),
                ("action", 160),
                ("result", 64),
                ("reason", 320),
                ("evidence_source", 80),
                ("tested", 32),
            ):
                text = _display_text(raw.get(key), limit=limit)
                if text:
                    decision[key] = text
            for key in ("matched", "blocking", "enforceable_now", "stateful"):
                if isinstance(raw.get(key), bool):
                    decision[key] = bool(raw[key])
            raw_evidence = raw.get("evidence")
            if isinstance(raw_evidence, Mapping):
                decision["evidence"] = redact_event(dict(raw_evidence))
            if decision.get("policy_id"):
                decisions.append(decision)
        if decisions:
            result["policy_decisions"] = decisions
    raw_risk = value.get("risk")
    if isinstance(raw_risk, Mapping):
        level = _display_text(raw_risk.get("level"), limit=32)
        raw_reasons = raw_risk.get("reasons")
        reasons = (
            [
                reason
                for item in raw_reasons[:8]
                if (reason := _display_text(item, limit=160))
            ]
            if isinstance(raw_reasons, list)
            else []
        )
        result["risk"] = {"level": level or "normal", "reasons": reasons}
    raw_impact = value.get("business_impact")
    if isinstance(raw_impact, Mapping):
        impact: dict[str, Any] = {}
        for key in (
            "authorized_order_count",
            "current_order_count",
            "projected_order_count",
            "amount_per_order_yuan",
            "authorized_spend_yuan",
            "current_spend_yuan",
            "projected_spend_yuan",
            "current_extra_spend_yuan",
            "projected_extra_spend_yuan",
        ):
            number = raw_impact.get(key)
            if isinstance(number, (int, float)) and not isinstance(number, bool):
                impact[key] = max(0, number)
        for key in ("currency", "merchant"):
            text = _display_text(raw_impact.get(key), limit=160)
            if text:
                impact[key] = text
        if isinstance(raw_impact.get("simulated"), bool):
            impact["simulated"] = raw_impact["simulated"]
        if impact:
            result["business_impact"] = impact
    return result or None


def _item_exit_code(item: Mapping[str, Any]) -> int | None:
    for key in ("exitCode", "exit_code"):
        value = item.get(key)
        if type(value) is int:
            return value
    return None


def _tool_summary(item: Mapping[str, Any], item_type: str) -> tuple[str, str | None]:
    """Build a compact tool label plus the full redacted command, when present."""

    command = _display_text(item.get("command"), limit=2_048)
    if item_type == "commandExecution":
        return command or "Shell command", command

    if item_type == "fileChange":
        changes = item.get("changes")
        paths: list[str] = []
        if isinstance(changes, list):
            for change in changes:
                if isinstance(change, Mapping):
                    path = _display_text(change.get("path"), limit=512)
                    if path:
                        paths.append(path)
        if paths:
            return f"Files: {', '.join(paths[:6])}", None
        return "Workspace file change", None

    server = _display_text(
        item.get("server") or item.get("serverName"), limit=256
    )
    name = _display_text(
        item.get("tool") or item.get("toolName") or item.get("name"),
        limit=256,
    )
    if server and name:
        return f"{server} / {name}", None
    if name:
        return name, None
    return item_type, None


def _tool_public_metadata(item: Mapping[str, Any], item_type: str) -> dict[str, Any]:
    """Extract bounded, redacted tool metadata without copying tool output."""

    result: dict[str, Any] = {}
    for source_key, target_key, limit in (
        ("cwd", "cwd", 1_024),
        ("server", "server", 256),
        ("serverName", "server", 256),
        ("namespace", "namespace", 256),
        ("tool", "tool_name", 256),
        ("toolName", "tool_name", 256),
        ("agentId", "agent_id", 256),
        ("agent_id", "agent_id", 256),
        ("actor", "agent_id", 256),
    ):
        if target_key in result:
            continue
        text = _display_text(item.get(source_key), limit=limit)
        if text:
            result[target_key] = text

    process_id = item.get("processId", item.get("process_id"))
    if isinstance(process_id, (str, int)) and not isinstance(process_id, bool):
        result["process_id"] = str(process_id)[:128]

    actions = item.get("commandActions") or item.get("command_actions")
    if isinstance(actions, list):
        categories: list[str] = []
        targets: list[str] = []
        for action in actions[:64]:
            if not isinstance(action, Mapping):
                continue
            category = _display_text(action.get("type"), limit=64)
            if category and category not in categories:
                categories.append(category)
            target = _display_text(
                action.get("path") or action.get("name"), limit=512
            )
            if target and target not in targets:
                targets.append(target)
        if categories:
            result["command_categories"] = categories
        if targets:
            result["targets"] = targets[:24]

    if item_type == "fileChange":
        changes = item.get("changes")
        if isinstance(changes, list):
            paths: list[str] = []
            for change in changes[:128]:
                if not isinstance(change, Mapping):
                    continue
                path = _display_text(change.get("path"), limit=512)
                if path and path not in paths:
                    paths.append(path)
            result["change_count"] = len(changes)
            if paths:
                result["targets"] = paths[:24]

    output = None
    for key in ("aggregatedOutput", "aggregated_output", "output"):
        if isinstance(item.get(key), str):
            output = item[key]
            break
    if isinstance(output, str):
        result["output_chars"] = len(output)
        result["output_lines"] = output.count("\n") + (1 if output else 0)

    error = item.get("error")
    if isinstance(error, Mapping):
        error = error.get("message") or error.get("type")
    error_text = _display_text(error, limit=512)
    if error_text:
        result["error"] = error_text
    return result


@dataclass(slots=True)
class LiveSessionStatus:
    """Mutable live view of one interactive Codex monitor session."""

    thread_id: str | None = None
    turn_id: str | None = None
    turn_status: str | None = None
    model: str | None = None
    open_items: dict[str, dict[str, Any]] = field(default_factory=dict)
    recent_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_count: int = 0
    command_call_count: int = 0
    completed_tool_count: int = 0
    failed_tool_count: int = 0
    retry_tool_count: int = 0
    tool_type_counts: dict[str, int] = field(default_factory=dict)
    tool_duration_samples: list[float] = field(default_factory=list)
    max_tool_duration_samples: int = 2_048
    max_recent_tool_calls: int = 200
    pending_approvals: int = 0
    pending_approval_requests: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    approval_history: list[dict[str, Any]] = field(default_factory=list)
    approval_request_count: int = 0
    max_approval_history: int = 200
    token_usage: dict[str, Any] | None = None
    token_update_count: int = 0
    last_event_method: str | None = None
    last_event_at_mono: float | None = None
    last_token_at_mono: float | None = None
    turn_started_at_mono: float | None = None
    message_count: int = 0
    # One meter represents one provider model call.  Official app-server
    # usage closes it; a later post-tool model call starts a fresh slice.
    inflight_calibrator: ResidualCalibrator = field(
        default_factory=ResidualCalibrator,
        repr=False,
    )
    inflight_meter: ProxyUsageMeter | None = field(default=None, repr=False)
    inflight_sequence_number: int = 0
    inflight_slice_index: int = 0
    inflight_prompt_parts: list[str] = field(default_factory=list, repr=False)
    pending_prompt_parts: list[str] = field(default_factory=list, repr=False)
    inflight_prompt_tokens: int = 0
    inflight_input_estimate: int = 0
    inflight_input_estimate_p90: int = 0
    inflight_input_source: str = "unknown"
    inflight_preflight_input_tokens: int | None = None
    inflight_preflight_source: str | None = None
    inflight_preflight_tokenizer_source: str | None = None
    inflight_preflight_component_tokens: dict[str, int] = field(
        default_factory=dict,
        repr=False,
    )
    inflight_preflight_context_complete: bool | None = None
    inflight_preflight_request_id: str | None = None
    inflight_preflight_modality_counts: dict[str, int] = field(
        default_factory=dict,
        repr=False,
    )
    inflight_preflight_text_tokens: int | None = None
    inflight_preflight_multimodal_tokens: int | None = None
    inflight_preflight_multimodal_quality: str | None = None
    inflight_preflight_provider_latency_ms: float | None = None
    inflight_preflight_provider_status: str | None = None
    retired_preflight_request_ids: list[str] = field(
        default_factory=list,
        repr=False,
    )
    max_retired_preflight_request_ids: int = 256
    inflight_tool_context_tokens: int = 0
    pending_tool_context_tokens: int = 0
    input_estimate_residual_samples: list[int] = field(
        default_factory=list,
        repr=False,
    )
    request_input_estimate_residual_samples: dict[str, list[int]] = field(
        default_factory=dict,
        repr=False,
    )
    max_input_estimate_samples: int = 128
    inflight_delta_count: int = 0
    inflight_tool_argument_delta_count: int = 0
    inflight_tool_argument_stream_items: set[str] = field(
        default_factory=set,
        repr=False,
    )
    inflight_tool_argument_stream_sources: dict[str, str] = field(
        default_factory=dict,
        repr=False,
    )
    inflight_tool_argument_snapshot_items: set[str] = field(
        default_factory=set,
        repr=False,
    )
    inflight_active_elapsed_s: float = 0.0
    inflight_running_since_mono: float | None = None
    inflight_paused: bool = False
    inflight_reconciliation_count: int = 0
    inflight_last_reconciliation: dict[str, Any] | None = None
    reconciliation_history: list[dict[str, Any]] = field(default_factory=list)
    max_live_reconciliation_history: int = 512
    media_token_task: MediaTokenTaskTracker = field(
        default_factory=MediaTokenTaskTracker,
        repr=False,
    )
    token_trend: list[dict[str, Any]] = field(default_factory=list)
    max_token_trend_points: int = 3_600
    _last_token_trend_signature: tuple[object, ...] | None = field(
        default=None,
        repr=False,
    )
    # Thresholds (seconds) for silence classification.
    waiting_model_after_s: float = 2.0
    stalled_after_s: float = 60.0

    def _turn_is_active(self) -> bool:
        terminal = {"completed", "failed", "interrupted", "cancelled"}
        return self.turn_id is not None and self.turn_status not in terminal

    def _inflight_elapsed(self, now: float) -> float:
        elapsed = self.inflight_active_elapsed_s
        if self.inflight_running_since_mono is not None:
            elapsed += max(0.0, now - self.inflight_running_since_mono)
        return elapsed

    def _input_residual_samples(self) -> list[int]:
        source = self.inflight_preflight_source or ""
        if source == "provider_preflight_exact":
            return []
        if source.startswith("request_body"):
            # Keep complete/tokenized, partial, and heuristic request-body
            # residuals in separate calibration cohorts.
            return self.request_input_estimate_residual_samples.setdefault(
                source,
                [],
            )
        return self.input_estimate_residual_samples

    def _retire_preflight_request_id(self) -> None:
        request_id = self.inflight_preflight_request_id
        if request_id and (
            not self.retired_preflight_request_ids
            or self.retired_preflight_request_ids[-1] != request_id
        ):
            self.retired_preflight_request_ids.append(request_id)
            overflow = (
                len(self.retired_preflight_request_ids)
                - self.max_retired_preflight_request_ids
            )
            if overflow > 0:
                del self.retired_preflight_request_ids[:overflow]

    def _refresh_inflight_input_estimate(self) -> None:
        meter = self.inflight_meter
        if meter is None:
            return
        prompt = "".join(self.inflight_prompt_parts)
        counter = meter.token_counter
        prompt_tokens = counter(prompt) if counter is not None and prompt else 0
        self.inflight_prompt_tokens = max(0, int(prompt_tokens))

        # Fall back to the preceding exact context plus locally observed new
        # content. A custom Codex build can replace this with a request-boundary
        # estimate that includes instructions, prior items, and tool schemas.
        previous_last = (self.token_usage or {}).get("last")
        if isinstance(previous_last, Mapping):
            previous_context = int(previous_last.get("input_tokens") or 0) + int(
                previous_last.get("output_tokens") or 0
            )
            fallback = (
                previous_context
                + self.inflight_tool_context_tokens
                + self.inflight_prompt_tokens
            )
            fallback_source = "previous_exact_context"
            if self.inflight_tool_context_tokens:
                fallback_source += "+tool_context"
            fallback_source += "+visible_input"
        else:
            fallback = self.inflight_tool_context_tokens + self.inflight_prompt_tokens
            fallback_source = (
                "tool_context+visible_input"
                if self.inflight_tool_context_tokens
                else "visible_input_lower_bound"
            )

        if self.inflight_preflight_input_tokens is None:
            self.inflight_input_estimate = fallback
            self.inflight_input_estimate_p90 = fallback
            self.inflight_input_source = fallback_source
            return

        source = self.inflight_preflight_source or "codex_preflight"
        if source == "provider_preflight_exact":
            self.inflight_input_estimate = self.inflight_preflight_input_tokens
            self.inflight_input_estimate_p90 = self.inflight_preflight_input_tokens
            self.inflight_input_source = source
            return

        input_residual_samples = self._input_residual_samples()
        residual_p50 = _nearest_rank_value(input_residual_samples, 0.50)
        residual_p90 = _nearest_rank_value(input_residual_samples, 0.90)
        calibrated_p50 = max(
            0, self.inflight_preflight_input_tokens + residual_p50
        )
        calibrated_p90 = max(
            calibrated_p50,
            self.inflight_preflight_input_tokens + residual_p90,
        )
        self.inflight_input_estimate = calibrated_p50
        self.inflight_input_estimate_p90 = calibrated_p90
        if source == "codex_preflight":
            self.inflight_input_source = (
                "codex_preflight_calibrated"
                if input_residual_samples
                else "codex_preflight_estimate"
            )
        else:
            self.inflight_input_source = (
                f"{source}_calibrated" if input_residual_samples else source
            )

    def set_model(self, model: str) -> bool:
        """Set the active model and select its tokenizer when available."""

        normalized = model.strip()
        if not normalized:
            return False
        changed = normalized != self.model
        self.model = normalized
        if changed:
            self.input_estimate_residual_samples.clear()
            self.request_input_estimate_residual_samples.clear()
        if self.inflight_meter is not None:
            changed = self.inflight_meter.set_model(normalized) or changed
            self._refresh_inflight_input_estimate()
        return changed

    def _start_inflight_slice(
        self,
        *,
        mono: float | None = None,
        include_pending_prompt: bool = True,
    ) -> bool:
        if self.inflight_meter is not None or not self._turn_is_active():
            return False
        now = mono if mono is not None else time.monotonic()
        self.inflight_slice_index += 1
        meter = ProxyUsageMeter(
            model=self.model or "unknown-model",
            calibrator=self.inflight_calibrator,
        )
        meter.consume(
            "response.created",
            {
                "type": "response.created",
                "sequence_number": 0,
                "response": {
                    "id": f"live:{self.turn_id}:{self.inflight_slice_index}",
                    "model": self.model or "unknown-model",
                },
            },
            elapsed_s=0.0,
        )
        self.inflight_meter = meter
        self.inflight_sequence_number = 1
        self.inflight_prompt_parts = []
        self.inflight_preflight_input_tokens = None
        self.inflight_preflight_source = None
        self.inflight_preflight_tokenizer_source = None
        self.inflight_preflight_component_tokens.clear()
        self.inflight_preflight_context_complete = None
        self.inflight_preflight_request_id = None
        self.inflight_preflight_modality_counts.clear()
        self.inflight_preflight_text_tokens = None
        self.inflight_preflight_multimodal_tokens = None
        self.inflight_preflight_multimodal_quality = None
        self.inflight_preflight_provider_latency_ms = None
        self.inflight_preflight_provider_status = None
        self.inflight_tool_context_tokens = self.pending_tool_context_tokens
        self.pending_tool_context_tokens = 0
        if include_pending_prompt and self.pending_prompt_parts:
            self.inflight_prompt_parts.extend(self.pending_prompt_parts)
            self.pending_prompt_parts.clear()
        self.inflight_delta_count = 0
        self.inflight_tool_argument_delta_count = 0
        self.inflight_tool_argument_stream_items.clear()
        self.inflight_tool_argument_stream_sources.clear()
        self.inflight_tool_argument_snapshot_items.clear()
        self.inflight_active_elapsed_s = 0.0
        self.inflight_running_since_mono = now
        self.inflight_paused = False
        self._refresh_inflight_input_estimate()
        return True

    def observe_preflight_input_estimate(
        self,
        value: object,
        *,
        turn_id: str | None = None,
        model: str | None = None,
        source: str = "codex_preflight",
        tokenizer_source: str | None = None,
        component_tokens: Mapping[str, object] | None = None,
        context_complete: bool | None = None,
        request_id: str | None = None,
        modality_counts: Mapping[str, object] | None = None,
        text_input_tokens: object = None,
        multimodal_input_tokens: object = None,
        multimodal_input_quality: str | None = None,
        provider_count_latency_ms: object = None,
        provider_count_status: str | None = None,
        mono: float | None = None,
    ) -> bool:
        """Apply the highest-quality request-boundary estimate seen so far."""

        estimate = _as_int(value)
        if estimate is None:
            return False
        source = source.strip() or "codex_preflight"
        if turn_id and self.turn_id and turn_id != self.turn_id:
            return False
        if model:
            self.set_model(model)
        now = mono if mono is not None else time.monotonic()
        normalized_request_id = (
            request_id.strip()[:128]
            if isinstance(request_id, str) and request_id.strip()
            else None
        )
        normalized_provider_status = (
            provider_count_status
            if provider_count_status
            in {
                "pending",
                "unsupported",
                "unavailable",
                "exact",
                "exact_with_breakdown",
            }
            else None
        )
        if (
            normalized_request_id is not None
            and normalized_request_id in self.retired_preflight_request_ids
        ):
            return False
        if (
            (
                source == "provider_preflight_exact"
                or normalized_provider_status == "unavailable"
            )
            and normalized_request_id is not None
            and self.inflight_meter is None
        ):
            # A parallel provider count may finish after official usage closed
            # the slice. Never let that stale callback create a phantom slice.
            return False
        if self.inflight_meter is None and not self._start_inflight_slice(mono=now):
            return False
        if (
            normalized_request_id is not None
            and self.inflight_preflight_request_id is not None
            and normalized_request_id != self.inflight_preflight_request_id
        ):
            return False

        normalized_modalities: dict[str, int] = {}
        if isinstance(modality_counts, Mapping):
            for key in ("pdf", "file", "image", "audio"):
                count = _as_int(modality_counts.get(key))
                if count:
                    normalized_modalities[key] = count
        effective_modalities = (
            normalized_modalities
            if modality_counts is not None
            else dict(self.inflight_preflight_modality_counts)
        )
        media_task_changed = self.media_token_task.observe_request(
            effective_modalities,
            request_id=normalized_request_id,
            slice_index=self.inflight_slice_index,
            mono=now,
        )
        normalized_text_tokens = _as_int(text_input_tokens)
        normalized_multimodal_tokens = _as_int(multimodal_input_tokens)
        normalized_multimodal_quality = (
            multimodal_input_quality
            if multimodal_input_quality
            in {"local_estimate", "local_estimate_partial", "provider_exact"}
            else None
        )
        normalized_latency: float | None = None
        if (
            type(provider_count_latency_ms) in {int, float}
            and math.isfinite(float(provider_count_latency_ms))
            and float(provider_count_latency_ms) >= 0
        ):
            normalized_latency = round(float(provider_count_latency_ms), 3)

        current_priority = _INPUT_ESTIMATE_SOURCE_PRIORITY.get(
            self.inflight_preflight_source or "",
            0,
        )
        incoming_priority = _INPUT_ESTIMATE_SOURCE_PRIORITY.get(source, 0)
        if (
            self.inflight_preflight_source is not None
            and incoming_priority < current_priority
        ):
            metadata_changed = False
            if normalized_request_id and self.inflight_preflight_request_id is None:
                self.inflight_preflight_request_id = normalized_request_id
                metadata_changed = True
            if (
                normalized_modalities
                and normalized_modalities
                != self.inflight_preflight_modality_counts
            ):
                self.inflight_preflight_modality_counts = normalized_modalities
                metadata_changed = True
            if (
                normalized_provider_status is not None
                and normalized_provider_status
                != self.inflight_preflight_provider_status
            ):
                self.inflight_preflight_provider_status = normalized_provider_status
                self.inflight_preflight_provider_latency_ms = normalized_latency
                metadata_changed = True
            if metadata_changed or media_task_changed:
                self.note_event("codexscope/requestTokenTap", mono=now)
            return metadata_changed or media_task_changed

        normalized_components: dict[str, int] = {}
        if isinstance(component_tokens, Mapping):
            for key, raw_count in component_tokens.items():
                count = _as_int(raw_count)
                if isinstance(key, str) and count is not None:
                    normalized_components[key] = count
        changed = (
            self.inflight_preflight_input_tokens != estimate
            or self.inflight_preflight_source != source
            or self.inflight_preflight_tokenizer_source != tokenizer_source
            or self.inflight_preflight_component_tokens != normalized_components
            or self.inflight_preflight_context_complete != context_complete
            or self.inflight_preflight_request_id != (
                normalized_request_id or self.inflight_preflight_request_id
            )
            or self.inflight_preflight_modality_counts != effective_modalities
            or self.inflight_preflight_text_tokens != normalized_text_tokens
            or self.inflight_preflight_multimodal_tokens
            != normalized_multimodal_tokens
            or self.inflight_preflight_multimodal_quality
            != normalized_multimodal_quality
            or self.inflight_preflight_provider_latency_ms != normalized_latency
            or self.inflight_preflight_provider_status
            != normalized_provider_status
            or media_task_changed
        )
        self.inflight_preflight_input_tokens = estimate
        self.inflight_preflight_source = source
        self.inflight_preflight_tokenizer_source = tokenizer_source
        self.inflight_preflight_component_tokens = normalized_components
        self.inflight_preflight_context_complete = context_complete
        if normalized_request_id is not None:
            self.inflight_preflight_request_id = normalized_request_id
        self.inflight_preflight_modality_counts = effective_modalities
        self.inflight_preflight_text_tokens = normalized_text_tokens
        self.inflight_preflight_multimodal_tokens = normalized_multimodal_tokens
        self.inflight_preflight_multimodal_quality = normalized_multimodal_quality
        self.inflight_preflight_provider_latency_ms = normalized_latency
        self.inflight_preflight_provider_status = normalized_provider_status
        self._refresh_inflight_input_estimate()
        self.note_event(
            (
                "codexscope/requestTokenTap"
                if source.startswith("request_body")
                else (
                    "codexscope/providerInputTokenCount"
                    if source == "provider_preflight_exact"
                    else "codexscope/preflightTokenEstimate"
                )
            ),
            mono=now,
        )
        return changed

    def _count_tool_context(
        self,
        item: Mapping[str, Any],
        item_type: str,
    ) -> int:
        payload = _tool_context_payload(item, item_type)
        if payload is None:
            return 0
        try:
            serialized = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError):
            return 0
        meter = self.inflight_meter
        counter = meter.token_counter if meter is not None else None
        if counter is None:
            counter, _source = default_token_counter(self.model or "unknown-model")
        return max(0, int(counter(serialized)))

    def observe_turn_input(
        self,
        value: object,
        *,
        next_slice: bool = False,
        mono: float | None = None,
    ) -> bool:
        """Count visible input while retaining no prompt text in status JSON."""

        fragments = _input_text_fragments(value)
        if not fragments:
            return False
        if next_slice or self.inflight_meter is None:
            self.pending_prompt_parts.extend(fragments)
        else:
            self.inflight_prompt_parts.extend(fragments)
            self._refresh_inflight_input_estimate()
        self.note_event("turn/input", mono=mono)
        return True

    def _pause_inflight(self, *, mono: float | None = None) -> None:
        if self.inflight_meter is None or self.inflight_running_since_mono is None:
            return
        now = mono if mono is not None else time.monotonic()
        self.inflight_active_elapsed_s = self._inflight_elapsed(now)
        self.inflight_running_since_mono = None
        self.inflight_paused = True

    def _resume_inflight(self, *, mono: float | None = None) -> None:
        if self.inflight_meter is None or self.inflight_running_since_mono is not None:
            return
        now = mono if mono is not None else time.monotonic()
        if self.inflight_meter.phase == "streaming_tool":
            self.inflight_meter.phase = "waiting_model"
        self.inflight_running_since_mono = now
        self.inflight_paused = False

    def observe_model_delta(
        self,
        delta: str,
        *,
        method: str,
        mono: float | None = None,
    ) -> bool:
        """Tokenize the complete observed output prefix for one model call."""

        if not isinstance(delta, str):
            return False
        now = mono if mono is not None else time.monotonic()
        if self.inflight_meter is None and not self._start_inflight_slice(mono=now):
            return False
        self._resume_inflight(mono=now)
        meter = self.inflight_meter
        assert meter is not None
        elapsed = self._inflight_elapsed(now)
        changed = meter.consume(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "sequence_number": self.inflight_sequence_number,
                "delta": delta,
            },
            elapsed_s=elapsed,
        )
        self.inflight_sequence_number += 1
        if changed:
            self.inflight_delta_count += 1
            self.note_event(method, mono=now)
        return changed

    def observe_model_tool_argument_delta(
        self,
        delta: str,
        *,
        item_id: str,
        method: str = "response.function_call_arguments.delta",
        stream_source: str = "appserver",
        mono: float | None = None,
        note_event: bool = True,
    ) -> bool:
        """Count one raw model-authored argument delta for the active call."""

        if not isinstance(delta, str) or not item_id:
            return False
        # Unlike answer text, a tool-argument event cannot safely create a
        # slice: after official usage closes a call, a late item notification
        # must not be attached to the following model call.
        meter = self.inflight_meter
        if meter is None or item_id in self.inflight_tool_argument_snapshot_items:
            return False
        existing_source = self.inflight_tool_argument_stream_sources.get(item_id)
        if existing_source is not None and existing_source != stream_source:
            return False
        now = mono if mono is not None else time.monotonic()
        elapsed = self._inflight_elapsed(now)
        changed = meter.consume(
            "response.function_call_arguments.delta",
            {
                "type": "response.function_call_arguments.delta",
                "sequence_number": self.inflight_sequence_number,
                "item_id": item_id,
                "delta": delta,
            },
            elapsed_s=elapsed,
        )
        self.inflight_sequence_number += 1
        if changed:
            self.inflight_tool_argument_stream_items.add(item_id)
            self.inflight_tool_argument_stream_sources[item_id] = stream_source
            self.inflight_tool_argument_delta_count += 1
            self.inflight_delta_count += 1
            if note_event:
                self.note_event(method, mono=now)
        return changed

    def observe_model_tool_item_arguments(
        self,
        item_id: str,
        item_type: str,
        item: Mapping[str, Any],
        *,
        mono: float | None = None,
    ) -> bool:
        """Fallback to an app-server item snapshot when raw deltas are absent."""

        if (
            self.inflight_meter is None
            or not item_id
            or item_id in self.inflight_tool_argument_stream_items
            or item_id in self.inflight_tool_argument_snapshot_items
        ):
            return False
        payload = _model_tool_argument_payload(item, item_type)
        if payload is None:
            return False
        serialized = _serialize_model_tool_arguments(payload)
        if serialized is None:
            return False
        changed = self.observe_model_tool_argument_delta(
            serialized,
            item_id=item_id,
            method="item/toolArguments/snapshot",
            stream_source="item_snapshot",
            mono=mono,
            note_event=False,
        )
        if changed:
            self.inflight_tool_argument_stream_items.discard(item_id)
            self.inflight_tool_argument_snapshot_items.add(item_id)
        return changed

    def _reconcile_inflight(
        self,
        last: Mapping[str, int],
        *,
        mono: float | None = None,
    ) -> None:
        meter = self.inflight_meter
        if meter is None:
            return
        now = mono if mono is not None else time.monotonic()
        elapsed = self._inflight_elapsed(now)
        estimate = meter.estimate_output(elapsed)
        exact_output = int(last.get("output_tokens") or 0)
        residual = (
            exact_output - estimate.observed_tokens
            if exact_output >= estimate.observed_tokens
            else None
        )
        source = estimate.observed_source
        if residual is not None and (
            "tokenizer" in source or source == "logprobs-observed"
        ):
            self.inflight_calibrator.observe(residual)
        self.inflight_reconciliation_count += 1
        output_error_p50 = estimate.likely_p50_tokens - exact_output
        output_error_p90 = estimate.likely_p90_tokens - exact_output
        official_input = int(last.get("input_tokens") or 0)
        input_error_p50 = self.inflight_input_estimate - official_input
        input_error_p90 = self.inflight_input_estimate_p90 - official_input
        tool_argument_item_count = len(
            self.inflight_tool_argument_stream_items
            | self.inflight_tool_argument_snapshot_items
        )

        def error_pct(error: int, official: int) -> float | None:
            if official <= 0:
                return None
            return round(100.0 * error / official, 2)

        self.inflight_last_reconciliation = {
            "slice_index": self.inflight_slice_index,
            "turn_id": self.turn_id,
            "model": self.model,
            "completed_at": time.time(),
            "active_elapsed_seconds": round(elapsed, 3),
            "observed_output_tokens": estimate.observed_tokens,
            "observed_output_text_tokens": meter.text_tokens,
            "observed_output_tool_argument_tokens": meter.tool_argument_tokens,
            "observed_output_tool_argument_item_count": tool_argument_item_count,
            "observed_output_tool_argument_delta_count": (
                self.inflight_tool_argument_delta_count
            ),
            "observed_output_source": source,
            "estimated_output_tokens_p50": estimate.likely_p50_tokens,
            "estimated_output_tokens_p90": estimate.likely_p90_tokens,
            "output_error_tokens_p50": output_error_p50,
            "output_error_tokens_p90": output_error_p90,
            "output_error_pct_p50": error_pct(output_error_p50, exact_output),
            "output_error_pct_p90": error_pct(output_error_p90, exact_output),
            "p90_interval_covered_official": (
                estimate.observed_tokens
                <= exact_output
                <= estimate.likely_p90_tokens
            ),
            "estimated_input_tokens_p50": self.inflight_input_estimate,
            "estimated_input_tokens_p90": self.inflight_input_estimate_p90,
            "input_error_tokens_p50": input_error_p50,
            "input_error_tokens_p90": input_error_p90,
            "input_error_pct_p50": error_pct(input_error_p50, official_input),
            "input_error_pct_p90": error_pct(input_error_p90, official_input),
            "preflight_input_tokens": self.inflight_preflight_input_tokens,
            "input_estimate_source": self.inflight_preflight_source,
            "input_request_tokenizer_source": (
                self.inflight_preflight_tokenizer_source
            ),
            "input_request_component_tokens": dict(
                self.inflight_preflight_component_tokens
            ),
            "input_request_context_complete": (
                self.inflight_preflight_context_complete
            ),
            "input_request_id": self.inflight_preflight_request_id,
            "input_modality_counts": dict(
                self.inflight_preflight_modality_counts
            ),
            "input_text_tokens_exact": self.inflight_preflight_text_tokens,
            "input_multimodal_tokens_derived": (
                self.inflight_preflight_multimodal_tokens
            ),
            "input_multimodal_tokens_quality": (
                self.inflight_preflight_multimodal_quality
            ),
            "input_provider_count_latency_ms": (
                self.inflight_preflight_provider_latency_ms
            ),
            "input_provider_count_status": (
                self.inflight_preflight_provider_status
            ),
            "tool_context_tokens_estimated": self.inflight_tool_context_tokens,
            "official_input_tokens": official_input,
            "official_output_tokens": exact_output,
            "official_reasoning_output_tokens": int(
                last.get("reasoning_output_tokens") or 0
            ),
            "official_total_tokens": int(last.get("total_tokens") or 0),
            "hidden_or_framing_residual_tokens": residual,
        }
        if self.inflight_preflight_input_tokens is not None:
            input_residual = int(last.get("input_tokens") or 0) - int(
                self.inflight_preflight_input_tokens
            )
            if self.inflight_preflight_source != "provider_preflight_exact":
                input_residual_samples = self._input_residual_samples()
                input_residual_samples.append(input_residual)
                overflow = (
                    len(input_residual_samples) - self.max_input_estimate_samples
                )
                if overflow > 0:
                    del input_residual_samples[:overflow]
            self.inflight_last_reconciliation[
                "preflight_input_residual_tokens"
            ] = input_residual
        self.reconciliation_history.append(dict(self.inflight_last_reconciliation))
        self._retire_preflight_request_id()
        self.inflight_meter = None
        self.inflight_prompt_parts.clear()
        self.inflight_prompt_tokens = 0
        self.inflight_input_estimate = 0
        self.inflight_input_estimate_p90 = 0
        self.inflight_input_source = "unknown"
        self.inflight_preflight_input_tokens = None
        self.inflight_preflight_source = None
        self.inflight_preflight_tokenizer_source = None
        self.inflight_preflight_component_tokens.clear()
        self.inflight_preflight_context_complete = None
        self.inflight_preflight_request_id = None
        self.inflight_preflight_modality_counts.clear()
        self.inflight_preflight_text_tokens = None
        self.inflight_preflight_multimodal_tokens = None
        self.inflight_preflight_multimodal_quality = None
        self.inflight_preflight_provider_latency_ms = None
        self.inflight_preflight_provider_status = None
        self.inflight_tool_context_tokens = 0
        self.inflight_delta_count = 0
        self.inflight_tool_argument_delta_count = 0
        self.inflight_tool_argument_stream_items.clear()
        self.inflight_tool_argument_stream_sources.clear()
        self.inflight_tool_argument_snapshot_items.clear()
        self.inflight_active_elapsed_s = 0.0
        self.inflight_running_since_mono = None
        self.inflight_paused = False

    def has_active_inflight(self) -> bool:
        return self.inflight_meter is not None and self._turn_is_active()

    def note_event(self, method: str | None, *, mono: float | None = None) -> None:
        self.last_event_method = method
        self.last_event_at_mono = mono if mono is not None else time.monotonic()
        self.message_count += 1

    def set_token_usage(self, usage: object, *, mono: float | None = None) -> bool:
        normalized = normalize_token_usage(usage)
        if normalized is None:
            return False
        now = mono if mono is not None else time.monotonic()
        self._reconcile_inflight(normalized["last"], mono=now)
        self.token_usage = normalized
        self.token_update_count += 1
        self.last_token_at_mono = now
        self.note_event("thread/tokenUsage/updated", mono=self.last_token_at_mono)
        return True

    def turn_started(
        self,
        turn_id: str,
        *,
        thread_id: str | None = None,
        mono: float | None = None,
    ) -> None:
        now = mono if mono is not None else time.monotonic()
        self.turn_id = turn_id
        if thread_id:
            self.thread_id = thread_id
        self.turn_status = "inProgress"
        self.turn_started_at_mono = now
        self.media_token_task.start_turn(turn_id)
        self.note_event("turn/started", mono=now)
        self._start_inflight_slice(mono=now)

    def turn_completed(
        self,
        turn_id: str | None = None,
        *,
        status: str | None = None,
        mono: float | None = None,
    ) -> None:
        now = mono if mono is not None else time.monotonic()
        if turn_id:
            self.turn_id = turn_id
        self.turn_status = status or "completed"
        for request_id in list(self.pending_approval_requests):
            self.approval_resolved(
                request_id=request_id,
                decision="interrupted",
                mono=now,
            )
        self.open_items.clear()
        self.pending_approvals = 0
        self._retire_preflight_request_id()
        self.inflight_meter = None
        self.inflight_prompt_parts.clear()
        self.pending_prompt_parts.clear()
        self.pending_tool_context_tokens = 0
        self.inflight_prompt_tokens = 0
        self.inflight_input_estimate = 0
        self.inflight_input_estimate_p90 = 0
        self.inflight_input_source = "unknown"
        self.inflight_preflight_input_tokens = None
        self.inflight_preflight_source = None
        self.inflight_preflight_tokenizer_source = None
        self.inflight_preflight_component_tokens.clear()
        self.inflight_preflight_context_complete = None
        self.inflight_preflight_request_id = None
        self.inflight_preflight_modality_counts.clear()
        self.inflight_preflight_text_tokens = None
        self.inflight_preflight_multimodal_tokens = None
        self.inflight_preflight_multimodal_quality = None
        self.inflight_preflight_provider_latency_ms = None
        self.inflight_preflight_provider_status = None
        self.inflight_tool_context_tokens = 0
        self.inflight_delta_count = 0
        self.inflight_tool_argument_delta_count = 0
        self.inflight_tool_argument_stream_items.clear()
        self.inflight_tool_argument_stream_sources.clear()
        self.inflight_tool_argument_snapshot_items.clear()
        self.inflight_active_elapsed_s = 0.0
        self.inflight_running_since_mono = None
        self.inflight_paused = False
        self.note_event("turn/completed", mono=now)

    def _find_tool_call(self, item_id: str) -> dict[str, Any] | None:
        for action in reversed(self.recent_tool_calls):
            if action.get("id") == item_id:
                return action
        return None

    def _record_tool_started(
        self,
        item_id: str,
        item_type: str,
        item: Mapping[str, Any],
        *,
        mono: float,
        wall_time: float,
        policy_decisions: object = None,
    ) -> None:
        action = self._find_tool_call(item_id)
        summary, command = _tool_summary(item, item_type)
        if action is None:
            action = {
                "id": item_id,
                "type": item_type,
                "turn_id": self.turn_id,
                "status": str(item.get("status") or "inProgress"),
                "summary": summary,
                "started_at": wall_time,
                "_started_at_mono": mono,
            }
            if command is not None:
                action["command"] = command
            action.update(_tool_public_metadata(item, item_type))
            self._attach_tool_policy_decisions(action, policy_decisions)
            previous = self.recent_tool_calls[-1] if self.recent_tool_calls else None
            same_operation = False
            if isinstance(previous, Mapping) and previous.get("type") == item_type:
                if action.get("command") and action.get("command") == previous.get("command"):
                    same_operation = True
                elif (
                    summary not in {item_type, "Shell command", "Workspace file change"}
                    and summary == previous.get("summary")
                ):
                    same_operation = True
                elif action.get("targets") and action.get("targets") == previous.get("targets"):
                    same_operation = True
            if (
                isinstance(previous, Mapping)
                and same_operation
                and str(previous.get("status") or "")
                in {"failed", "declined", "cancelled", "interrupted"}
                and isinstance(previous.get("finished_at"), (int, float))
                and 0 <= wall_time - float(previous["finished_at"]) <= 60
            ):
                action["retry_of"] = previous.get("id")
                action["retry_root_id"] = previous.get("retry_root_id") or previous.get("id")
                action["retry_attempt"] = int(previous.get("retry_attempt") or 1) + 1
                action["retry_evidence"] = "same_operation_after_failure_within_60s"
            self.recent_tool_calls.append(action)
            self.tool_call_count += 1
            self.tool_type_counts[item_type] = (
                self.tool_type_counts.get(item_type, 0) + 1
            )
            if item_type == "commandExecution":
                self.command_call_count += 1
            if action.get("retry_of"):
                self.retry_tool_count += 1
            overflow = len(self.recent_tool_calls) - self.max_recent_tool_calls
            if overflow > 0:
                del self.recent_tool_calls[:overflow]
            return

        action.update({"type": item_type, "summary": summary})
        if command is not None:
            action["command"] = command
        action.update(_tool_public_metadata(item, item_type))
        self._attach_tool_policy_decisions(action, policy_decisions)

    @staticmethod
    def _attach_tool_policy_decisions(
        action: dict[str, Any], decisions: object
    ) -> None:
        if not isinstance(decisions, list):
            return
        current = action.get("policy_decisions")
        current = current if isinstance(current, list) else []
        merged = merge_policy_decisions(
            [value for value in current if isinstance(value, Mapping)],
            [value for value in decisions if isinstance(value, Mapping)],
        )
        if merged:
            action["policy_decisions"] = redact_event(merged)

    def _record_tool_completed(
        self,
        item_id: str,
        item_type: str,
        item: Mapping[str, Any],
        *,
        mono: float,
        wall_time: float,
        policy_decisions: object = None,
    ) -> None:
        action = self._find_tool_call(item_id)
        if action is None:
            self._record_tool_started(
                item_id,
                item_type,
                item,
                mono=mono,
                wall_time=wall_time,
                policy_decisions=policy_decisions,
            )
            action = self._find_tool_call(item_id)
        assert action is not None

        previous_status = str(action.get("status") or "")
        status = str(item.get("status") or "completed")
        exit_code = _item_exit_code(item)
        if exit_code not in {None, 0} and status == "completed":
            status = "failed"
        summary, command = _tool_summary(item, item_type)
        action.update(
            {
                "type": item_type,
                "status": status,
                "summary": summary,
                "finished_at": wall_time,
            }
        )
        if command is not None:
            action["command"] = command
        action.update(_tool_public_metadata(item, item_type))
        self._attach_tool_policy_decisions(action, policy_decisions)
        if exit_code is not None:
            action["exit_code"] = exit_code
        started_mono = action.get("_started_at_mono")
        if isinstance(started_mono, (int, float)):
            action["duration_seconds"] = round(max(0.0, mono - started_mono), 3)

        terminal = {"completed", "failed", "declined", "cancelled", "interrupted"}
        if previous_status not in terminal:
            self.completed_tool_count += 1
            if status != "completed" or exit_code not in {None, 0}:
                self.failed_tool_count += 1
            if isinstance(action.get("duration_seconds"), (int, float)):
                self.tool_duration_samples.append(
                    float(action["duration_seconds"])
                )
                overflow = (
                    len(self.tool_duration_samples) - self.max_tool_duration_samples
                )
                if overflow > 0:
                    del self.tool_duration_samples[:overflow]

    def item_started(
        self,
        item_id: str,
        item_type: str | None,
        *,
        item: Mapping[str, Any] | None = None,
        mono: float | None = None,
        wall_time: float | None = None,
        policy_decisions: object = None,
    ) -> None:
        if not item_id:
            return
        now = mono if mono is not None else time.monotonic()
        wall = wall_time if wall_time is not None else time.time()
        normalized_type = item_type or "unknown"
        self.open_items[item_id] = {
            "id": item_id,
            "type": normalized_type,
            "started_at_mono": now,
        }
        if _is_local_item_type(normalized_type):
            self.media_token_task.observe_tool(
                item_id,
                normalized_type,
                item or {},
                mono=now,
                slice_index=self.inflight_slice_index,
                model=self.model,
            )
            self.observe_model_tool_item_arguments(
                item_id,
                normalized_type,
                item or {},
                mono=now,
            )
            self._record_tool_started(
                item_id,
                normalized_type,
                item or {},
                mono=now,
                wall_time=wall,
                policy_decisions=policy_decisions,
            )
            self._pause_inflight(mono=now)
        elif normalized_type in {"agentMessage", "reasoning", "todoList", "plan"}:
            self._start_inflight_slice(mono=now)
        self.note_event("item/started", mono=now)

    def item_completed(
        self,
        item_id: str | None,
        *,
        item: Mapping[str, Any] | None = None,
        mono: float | None = None,
        wall_time: float | None = None,
        policy_decisions: object = None,
    ) -> None:
        now = mono if mono is not None else time.monotonic()
        wall = wall_time if wall_time is not None else time.time()
        completed = self.open_items.get(item_id) if item_id else None
        if item_id:
            self.open_items.pop(item_id, None)
        payload = item or {}
        completed_type = (
            payload.get("type")
            or (completed.get("type") if isinstance(completed, Mapping) else None)
        )
        if item_id and completed_type is not None and _is_local_item_type(completed_type):
            self.observe_model_tool_item_arguments(
                item_id,
                str(completed_type),
                payload,
                mono=now,
            )
            self._record_tool_completed(
                item_id,
                str(completed_type),
                payload,
                mono=now,
                wall_time=wall,
                policy_decisions=policy_decisions,
            )
            self.pending_tool_context_tokens += self._count_tool_context(
                payload,
                str(completed_type),
            )
        self.note_event("item/completed", mono=now)
        was_local = completed_type is not None and _is_local_item_type(completed_type)
        if was_local and not self.open_local_items() and self.pending_approvals == 0:
            if self.inflight_meter is None:
                self._start_inflight_slice(mono=now)
            else:
                self._resume_inflight(mono=now)

    def approval_requested(
        self,
        *,
        request_id: str | None = None,
        item_id: str | None = None,
        method: str | None = None,
        command: object = None,
        cwd: object = None,
        reason: object = None,
        policy: object = None,
        mono: float | None = None,
        wall_time: float | None = None,
    ) -> None:
        now = mono if mono is not None else time.monotonic()
        wall = wall_time if wall_time is not None else time.time()
        key = request_id or f"legacy:{item_id or method or 'approval'}:{self.approval_request_count + 1}"
        if key in self.pending_approval_requests:
            return
        self.approval_request_count += 1
        approval: dict[str, Any] = {
            "request_id": request_id,
            "item_id": item_id,
            "method": method,
            "turn_id": self.turn_id,
            "status": "pending",
            "started_at": wall,
            "_started_at_mono": now,
        }
        command_text = _display_text(command, limit=2_048)
        cwd_text = _display_text(cwd, limit=1_024)
        reason_text = _display_text(reason, limit=512)
        policy_metadata = _approval_policy_metadata(policy)
        if command_text:
            approval["command"] = command_text
        if cwd_text:
            approval["cwd"] = cwd_text
        if reason_text:
            approval["reason"] = reason_text
        if policy_metadata:
            approval["policy"] = policy_metadata
        self.pending_approval_requests[key] = approval
        self.pending_approvals = len(self.pending_approval_requests)
        if item_id:
            action = self._find_tool_call(item_id)
            if action is not None:
                action["status"] = "awaitingApproval"
                action["approval_request_id"] = request_id
        self._pause_inflight(mono=now)
        self.note_event("approval", mono=now)

    def approval_resolved(
        self,
        *,
        request_id: str | None = None,
        decision: str | None = None,
        decision_source: str | None = None,
        mono: float | None = None,
        wall_time: float | None = None,
    ) -> None:
        now = mono if mono is not None else time.monotonic()
        wall = wall_time if wall_time is not None else time.time()
        key = request_id if request_id in self.pending_approval_requests else None
        if key is None and request_id is None and self.pending_approval_requests:
            key = next(iter(self.pending_approval_requests))
        approval = (
            self.pending_approval_requests.pop(key)
            if key is not None
            else None
        )
        if approval is not None:
            normalized_decision = decision or "resolved"
            approval.update(
                {
                    "status": normalized_decision,
                    "decision": normalized_decision,
                    "finished_at": wall,
                }
            )
            if decision_source:
                approval["decision_source"] = decision_source
            started_mono = approval.pop("_started_at_mono", None)
            if isinstance(started_mono, (int, float)):
                approval["duration_seconds"] = round(
                    max(0.0, now - started_mono), 3
                )
            self.approval_history.append(approval)
            overflow = len(self.approval_history) - self.max_approval_history
            if overflow > 0:
                del self.approval_history[:overflow]
            item_id = approval.get("item_id")
            if isinstance(item_id, str):
                action = self._find_tool_call(item_id)
                if action is not None:
                    action["approval_decision"] = normalized_decision
                    if decision_source:
                        action["approval_source"] = decision_source
                    policy_metadata = approval.get("policy")
                    if isinstance(policy_metadata, Mapping):
                        action["approval_policy"] = dict(policy_metadata)
                    if "duration_seconds" in approval:
                        action["approval_duration_seconds"] = approval[
                            "duration_seconds"
                        ]
                    if action.get("status") == "awaitingApproval":
                        action["status"] = (
                            "declined"
                            if normalized_decision
                            in {"declined", "cancelled", "error", "interrupted"}
                            else "inProgress"
                        )
        self.pending_approvals = len(self.pending_approval_requests)
        self.note_event("approval_resolved", mono=now)
        if self.pending_approvals == 0 and not self.open_local_items():
            if self.inflight_meter is None:
                self._start_inflight_slice(mono=now)
            else:
                self._resume_inflight(mono=now)

    def open_local_items(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.open_items.values()
            if _is_local_item_type(item.get("type"))
        ]

    def activity(self, *, now_mono: float | None = None) -> Activity:
        now = now_mono if now_mono is not None else time.monotonic()
        if self.pending_approvals > 0:
            return "awaiting_user"
        local = self.open_local_items()
        if local:
            return "local_tool"

        if not self._turn_is_active():
            return "idle"

        meter = self.inflight_meter
        if meter is not None:
            elapsed = self._inflight_elapsed(now)
            if (
                meter.phase in {"streaming", "streaming_tool"}
                and meter.last_delta_elapsed_s is not None
            ):
                delta_age = max(0.0, elapsed - meter.last_delta_elapsed_s)
                if delta_age < self.waiting_model_after_s:
                    return "streaming"
            event_age = (
                None
                if self.last_event_at_mono is None
                else max(0.0, now - self.last_event_at_mono)
            )
            if event_age is not None and event_age >= self.stalled_after_s:
                return "stalled"
            return "waiting_model"

        token_age = (
            None
            if self.last_token_at_mono is None
            else max(0.0, now - self.last_token_at_mono)
        )
        event_age = (
            None
            if self.last_event_at_mono is None
            else max(0.0, now - self.last_event_at_mono)
        )

        # Fresh token updates: streaming if the last slice produced output.
        if token_age is not None and token_age < self.waiting_model_after_s:
            last = (self.token_usage or {}).get("last") or {}
            if int(last.get("output_tokens") or 0) > 0 or int(
                last.get("reasoning_output_tokens") or 0
            ) > 0:
                return "streaming"
            return "waiting_model"

        if event_age is not None and event_age >= self.stalled_after_s:
            return "stalled"
        return "waiting_model"

    def reconciliation_summary(self) -> dict[str, Any]:
        rows = self.reconciliation_history

        def numbers(key: str, *, absolute: bool = False) -> list[float]:
            result: list[float] = []
            for row in rows:
                value = row.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    result.append(abs(float(value)) if absolute else float(value))
            return result

        p50_abs = numbers("output_error_tokens_p50", absolute=True)
        p90_abs = numbers("output_error_tokens_p90", absolute=True)
        p50_pct_abs = numbers("output_error_pct_p50", absolute=True)
        p50_bias = numbers("output_error_tokens_p50")
        covered = [
            bool(row.get("p90_interval_covered_official"))
            for row in rows
            if row.get("p90_interval_covered_official") is not None
        ]

        def mean(values: list[float]) -> float | None:
            return None if not values else round(sum(values) / len(values), 2)

        return {
            "count": self.inflight_reconciliation_count,
            "retained_count": len(rows),
            "output_error_sample_count": len(p50_abs),
            "p90_coverage_sample_count": len(covered),
            "output_p50_mae_tokens": mean(p50_abs),
            "output_p90_mae_tokens": mean(p90_abs),
            "output_p50_mape_pct": mean(p50_pct_abs),
            "output_p50_mean_bias_tokens": mean(p50_bias),
            "p90_coverage_pct": (
                None
                if not covered
                else round(100.0 * sum(covered) / len(covered), 2)
            ),
        }

    def approval_to_dict(self, *, now_mono: float) -> dict[str, Any]:
        pending: list[dict[str, Any]] = []
        for approval in self.pending_approval_requests.values():
            public = {
                key: value
                for key, value in approval.items()
                if not key.startswith("_")
            }
            started_mono = approval.get("_started_at_mono")
            if isinstance(started_mono, (int, float)):
                public["duration_seconds"] = round(
                    max(0.0, now_mono - started_mono), 3
                )
            pending.append(public)

        decision_counts: dict[str, int] = {}
        durations: list[float] = []
        for approval in self.approval_history:
            decision = str(approval.get("decision") or "resolved")
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            duration = approval.get("duration_seconds")
            if isinstance(duration, (int, float)):
                durations.append(float(duration))
        return {
            "total_requests": self.approval_request_count,
            "pending_count": len(pending),
            "decision_counts": decision_counts,
            "average_wait_seconds": (
                None if not durations else round(sum(durations) / len(durations), 3)
            ),
            "p95_wait_seconds": _percentile(durations, 0.95),
            "pending": pending,
            "recent": list(self.approval_history),
        }

    def _record_token_trend(
        self,
        *,
        activity: Activity,
        inflight: Mapping[str, Any],
        total: Mapping[str, Any] | None,
    ) -> None:
        active = inflight.get("active") is True
        exact_total = (
            _as_int(total.get("total_tokens"))
            if isinstance(total, Mapping)
            else None
        )
        likely_p50 = (
            _as_int(inflight.get("session_tokens_likely_p50"))
            if active
            else exact_total
        )
        likely_p90 = (
            _as_int(inflight.get("session_tokens_likely_p90"))
            if active
            else exact_total
        )
        lower = (
            _as_int(inflight.get("session_tokens_lower_bound"))
            if active
            else exact_total
        )
        signature = (
            self.turn_id,
            inflight.get("slice_index"),
            activity,
            active,
            exact_total,
            likely_p50,
            likely_p90,
            lower,
            self.token_update_count,
            self.tool_call_count,
            self.pending_approvals,
        )
        # A poll/heartbeat is not a measurement.  Keep only semantic changes so
        # completed sessions do not accumulate an ever-growing flat exact line.
        if signature == self._last_token_trend_signature:
            return
        self.token_trend.append(
            {
                "recorded_at": time.time(),
                "turn_id": self.turn_id,
                "slice_index": inflight.get("slice_index"),
                "activity": activity,
                "quality": "estimated" if active else (
                    "exact" if exact_total is not None else "unavailable"
                ),
                "session_tokens_lower_bound": lower,
                "session_tokens_likely_p50": likely_p50,
                "session_tokens_likely_p90": likely_p90,
                "exact_total_tokens": exact_total,
                "baseline_exact_total_tokens": inflight.get(
                    "baseline_exact_total_tokens"
                ),
                "token_update_count": self.token_update_count,
            }
        )
        overflow = len(self.token_trend) - self.max_token_trend_points
        if overflow > 0:
            del self.token_trend[:overflow]
        self._last_token_trend_signature = signature

    def inflight_to_dict(self, *, now_mono: float | None = None) -> dict[str, Any]:
        """Return an estimate-only slice; it is never folded into exact totals."""

        meter = self.inflight_meter
        if meter is None or not self._turn_is_active():
            return {
                "active": False,
                "quality": "exact_completed" if self.token_usage else "unavailable",
                "estimate_not_billable": True,
                "reconciliation_count": self.inflight_reconciliation_count,
                "last_reconciliation": self.inflight_last_reconciliation,
            }

        now = now_mono if now_mono is not None else time.monotonic()
        elapsed = self._inflight_elapsed(now)
        estimate = meter.estimate_output(elapsed)
        exact_total_map = (self.token_usage or {}).get("total")
        exact_total = (
            int(exact_total_map.get("total_tokens") or 0)
            if isinstance(exact_total_map, Mapping)
            else None
        )
        exact_preflight = (
            self.inflight_preflight_source == "provider_preflight_exact"
            and self.inflight_preflight_input_tokens is not None
        )
        lower_bound_input = (
            self.inflight_preflight_input_tokens
            if exact_preflight
            else self.inflight_prompt_tokens
        )
        live_lower = int(lower_bound_input or 0) + estimate.observed_tokens
        live_p50 = self.inflight_input_estimate + estimate.likely_p50_tokens
        live_p90 = self.inflight_input_estimate_p90 + estimate.likely_p90_tokens
        baseline = exact_total or 0
        last_delta_age = (
            None
            if meter.last_delta_elapsed_s is None
            else max(0.0, elapsed - meter.last_delta_elapsed_s)
        )
        tool_argument_item_count = len(
            self.inflight_tool_argument_stream_items
            | self.inflight_tool_argument_snapshot_items
        )
        return {
            "active": True,
            "paused": self.inflight_paused,
            "quality": "estimated",
            "coverage": (
                "provider_exact_input+tokenized_output+calibrated_hidden_output"
                if exact_preflight
                else (
                    "request_body+tokenized_output+calibrated_hidden_output"
                    if (self.inflight_preflight_source or "").startswith(
                        "request_body"
                    )
                    else (
                        "codex_request_boundary+tokenized_output+calibrated_hidden_output"
                        if self.inflight_preflight_input_tokens is not None
                        else "observed_context+tokenized_output+calibrated_hidden_output"
                    )
                )
            ),
            "estimate_not_billable": True,
            "turn_id": self.turn_id,
            "slice_index": self.inflight_slice_index,
            "model": self.model,
            "input_tokens_observed": self.inflight_prompt_tokens,
            "input_tokens_estimated": self.inflight_input_estimate,
            "input_tokens_estimated_p50": self.inflight_input_estimate,
            "input_tokens_estimated_p90": self.inflight_input_estimate_p90,
            "input_source": self.inflight_input_source,
            "input_tokenizer_source": meter.token_counter_source,
            "input_preflight_tokens_raw": self.inflight_preflight_input_tokens,
            "input_estimate_observation_source": self.inflight_preflight_source,
            "input_request_tokenizer_source": (
                self.inflight_preflight_tokenizer_source
            ),
            "input_request_component_tokens": dict(
                self.inflight_preflight_component_tokens
            ),
            "input_request_context_complete": (
                self.inflight_preflight_context_complete
            ),
            "input_quality": (
                "provider_exact_preflight" if exact_preflight else "estimated"
            ),
            "input_modality_counts": dict(
                self.inflight_preflight_modality_counts
            ),
            "input_text_tokens_exact": self.inflight_preflight_text_tokens,
            "input_multimodal_tokens_derived": (
                self.inflight_preflight_multimodal_tokens
            ),
            "input_multimodal_tokens_quality": (
                self.inflight_preflight_multimodal_quality
            ),
            "input_provider_count_latency_ms": (
                self.inflight_preflight_provider_latency_ms
            ),
            "input_provider_count_status": (
                self.inflight_preflight_provider_status
            ),
            "input_tool_context_tokens": self.inflight_tool_context_tokens,
            "input_calibration_sample_count": len(self._input_residual_samples()),
            "output_tokens_observed": estimate.observed_tokens,
            "output_text_tokens_observed": meter.text_tokens,
            "output_tool_argument_tokens_observed": meter.tool_argument_tokens,
            "output_tool_argument_item_count": tool_argument_item_count,
            "tool_argument_delta_count": self.inflight_tool_argument_delta_count,
            "output_source": estimate.observed_source,
            "output_tokens_likely_p50": estimate.likely_p50_tokens,
            "output_tokens_likely_p90": estimate.likely_p90_tokens,
            "output_confidence": estimate.confidence,
            "live_tokens_lower_bound": live_lower,
            "live_tokens_likely_p50": live_p50,
            "live_tokens_likely_p90": live_p90,
            "baseline_exact_total_tokens": exact_total,
            "session_tokens_lower_bound": baseline + live_lower,
            "session_tokens_likely_p50": baseline + live_p50,
            "session_tokens_likely_p90": baseline + live_p90,
            # Overall confidence is bounded by the output-side residual model.
            # Input precision is exposed independently through ``input_quality``.
            "confidence": estimate.confidence,
            "delta_count": self.inflight_delta_count,
            "active_elapsed_seconds": round(elapsed, 3),
            "seconds_since_delta": (
                None if last_delta_age is None else round(last_delta_age, 3)
            ),
            "calibration_sample_count": len(
                self.inflight_calibrator.residual_samples
            ),
            "reconciliation_count": self.inflight_reconciliation_count,
            "last_reconciliation": self.inflight_last_reconciliation,
        }

    def age_seconds(self, *, now_mono: float | None = None) -> float | None:
        now = now_mono if now_mono is not None else time.monotonic()
        if self.last_event_at_mono is None:
            return None
        return max(0.0, now - self.last_event_at_mono)

    def to_dict(self, *, now_mono: float | None = None) -> dict[str, Any]:
        now = now_mono if now_mono is not None else time.monotonic()
        activity = self.activity(now_mono=now)
        inflight = self.inflight_to_dict(now_mono=now)
        total = (self.token_usage or {}).get("total")
        last = (self.token_usage or {}).get("last")
        local = self.open_local_items()
        context_window = (self.token_usage or {}).get("model_context_window")
        context_used_tokens = None
        context_usage_quality = None
        if inflight.get("active"):
            context_used_tokens = _as_int(inflight.get("live_tokens_likely_p90"))
            if context_used_tokens is not None:
                context_usage_quality = "estimated_p90"
        elif isinstance(last, Mapping):
            context_used_tokens = _as_int(last.get("total_tokens"))
            if context_used_tokens is not None:
                context_usage_quality = "official_last_call"

        context_pct = None
        if (
            context_used_tokens is not None
            and type(context_window) is int
            and context_window > 0
        ):
            context_pct = round(100.0 * context_used_tokens / context_window, 2)

        recent_tools: list[dict[str, Any]] = []
        for action in self.recent_tool_calls:
            public = {
                key: value
                for key, value in action.items()
                if not key.startswith("_")
            }
            started_mono = action.get("_started_at_mono")
            if (
                public.get("status") in {"inProgress", "running", "awaitingApproval"}
                and isinstance(started_mono, (int, float))
            ):
                public["duration_seconds"] = round(
                    max(0.0, now - started_mono), 3
                )
            recent_tools.append(public)

        intervals: list[tuple[float, float]] = []
        for action in recent_tools:
            started_at = action.get("started_at")
            if not isinstance(started_at, (int, float)):
                continue
            finished_at = action.get("finished_at")
            if not isinstance(finished_at, (int, float)):
                duration = action.get("duration_seconds")
                finished_at = (
                    float(started_at) + float(duration)
                    if isinstance(duration, (int, float))
                    else time.time()
                )
            intervals.append((float(started_at), max(float(started_at), float(finished_at))))
        active_ends: list[float] = []
        concurrency_peak = 0
        overlap_pairs = 0
        for started_at, finished_at in sorted(intervals):
            active_ends = [value for value in active_ends if value > started_at]
            overlap_pairs += len(active_ends)
            active_ends.append(finished_at)
            concurrency_peak = max(concurrency_peak, len(active_ends))
        self._record_token_trend(
            activity=activity,
            inflight=inflight,
            total=total if isinstance(total, Mapping) else None,
        )

        successful_tools = max(0, self.completed_tool_count - self.failed_tool_count)
        completed_tools = self.completed_tool_count
        input_tokens = (
            _as_int(total.get("input_tokens"))
            if isinstance(total, Mapping)
            else None
        )
        cached_tokens = (
            _as_int(total.get("cached_input_tokens"))
            if isinstance(total, Mapping)
            else None
        )
        output_tokens = (
            _as_int(total.get("output_tokens"))
            if isinstance(total, Mapping)
            else None
        )
        reasoning_tokens = (
            _as_int(total.get("reasoning_output_tokens"))
            if isinstance(total, Mapping)
            else None
        )
        uncached_input = (
            max(0, input_tokens - cached_tokens)
            if input_tokens is not None and cached_tokens is not None
            else None
        )
        return {
            "activity": activity,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "turn_status": self.turn_status,
            "model": self.model,
            "open_item_count": len(self.open_items),
            "open_local_items": [
                {"id": item.get("id"), "type": item.get("type")} for item in local
            ],
            "tool_usage": {
                "total_calls": self.tool_call_count,
                "command_calls": self.command_call_count,
                "completed_calls": self.completed_tool_count,
                "failed_calls": self.failed_tool_count,
                "successful_calls": successful_tools,
                "active_calls": len(local),
                "retry_calls": self.retry_tool_count,
                "concurrency_peak_retained": concurrency_peak,
                "overlap_pairs_retained": overlap_pairs,
                "success_rate_pct": (
                    None
                    if completed_tools == 0
                    else round(100.0 * successful_tools / completed_tools, 2)
                ),
                "failure_rate_pct": (
                    None
                    if completed_tools == 0
                    else round(100.0 * self.failed_tool_count / completed_tools, 2)
                ),
                "duration_p50_seconds": _percentile(
                    self.tool_duration_samples, 0.50
                ),
                "duration_p95_seconds": _percentile(
                    self.tool_duration_samples, 0.95
                ),
                "type_counts": dict(self.tool_type_counts),
                "retained_calls": len(recent_tools),
                "recent": recent_tools,
            },
            "pending_approvals": self.pending_approvals,
            "approval_usage": self.approval_to_dict(now_mono=now),
            "token_usage": self.token_usage,
            "token_accounting": {
                "provider_total_tokens": (
                    _as_int(total.get("total_tokens"))
                    if isinstance(total, Mapping)
                    else None
                ),
                "uncached_input_tokens": uncached_input,
                "uncached_input_plus_output_tokens": (
                    uncached_input + output_tokens
                    if uncached_input is not None and output_tokens is not None
                    else None
                ),
                "cache_hit_pct": (
                    None
                    if input_tokens in {None, 0} or cached_tokens is None
                    else round(100.0 * cached_tokens / input_tokens, 2)
                ),
                "reasoning_output_pct": (
                    None
                    if output_tokens in {None, 0} or reasoning_tokens is None
                    else round(100.0 * reasoning_tokens / output_tokens, 2)
                ),
            },
            "media_token_task": self.media_token_task.to_dict(
                turn_status=self.turn_status,
                reconciliation_history=self.reconciliation_history,
                inflight=inflight,
            ),
            "inflight_token_estimate": inflight,
            "token_reconciliation": {
                "summary": self.reconciliation_summary(),
                "history": list(
                    self.reconciliation_history[-self.max_live_reconciliation_history :]
                ),
                "history_total_count": len(self.reconciliation_history),
                "history_truncated": (
                    len(self.reconciliation_history)
                    > self.max_live_reconciliation_history
                ),
            },
            "token_trend": list(self.token_trend),
            "token_update_count": self.token_update_count,
            "context_window": context_window,
            "context_used_tokens": context_used_tokens,
            "context_used_pct": context_pct,
            "context_usage_quality": context_usage_quality,
            "last_event_method": self.last_event_method,
            "seconds_since_event": self.age_seconds(now_mono=now),
            "message_count": self.message_count,
            "status_line": self.format_line(now_mono=now, simple=True),
            "status_line_verbose": self.format_line(now_mono=now, simple=False),
        }

    def format_line(
        self,
        *,
        now_mono: float | None = None,
        simple: bool = True,
    ) -> str:
        """Default line is only token totals; set simple=False for activity detail."""

        total = (self.token_usage or {}).get("total")
        inflight = self.inflight_to_dict(now_mono=now_mono)
        if simple:
            return format_tokens_live(
                total if isinstance(total, Mapping) else None,
                inflight,
            )

        now = now_mono if now_mono is not None else time.monotonic()
        activity = self.activity(now_mono=now)
        age = self.age_seconds(now_mono=now)
        age_text = f"{age:.0f}s" if age is not None else "-"
        tokens = format_tokens_live(
            total if isinstance(total, Mapping) else None,
            inflight,
        )
        local = self.open_local_items()
        detail = ""
        if activity == "local_tool" and local:
            detail = f" tool={local[0].get('type')}"
        elif activity == "awaiting_user":
            detail = f" approvals={self.pending_approvals}"
        elif self.model:
            detail = f" model={self.model}"

        return (
            f"{activity:<14} age={age_text:<4} "
            f"turn={_short_id(self.turn_id)} | {tokens}{detail}"
        )


def consume_envelope(
    status: LiveSessionStatus,
    envelope: Mapping[str, Any],
) -> bool:
    """Update live status from one gateway envelope. Returns True if notable."""

    message = envelope.get("message")
    if not isinstance(message, Mapping):
        return False
    direction = envelope.get("direction")
    method = message.get("method")
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    mono = None
    raw_mono = envelope.get("mono_ns")
    if type(raw_mono) is int:
        # Keep relative ages consistent within a process; wall mono is fine.
        mono = time.monotonic()
    wall_time = envelope.get("wall_time")
    wall = float(wall_time) if isinstance(wall_time, (int, float)) else time.time()

    changed = False

    if direction == "client_to_server" and method in {"turn/start", "turn/steer"}:
        observed = status.observe_turn_input(
            params.get("input"),
            next_slice=method == "turn/steer",
            mono=mono,
        )
        if not observed:
            status.note_event(str(method), mono=mono)
        return True

    if direction == "client_to_server" and not isinstance(method, str):
        response_id = message.get("id")
        request_id = str(response_id) if response_id is not None else None
        if request_id and request_id in status.pending_approval_requests:
            status.approval_resolved(
                request_id=request_id,
                decision=_approval_decision(message),
                decision_source=(
                    "codexscope_policy"
                    if isinstance(envelope.get("interception"), Mapping)
                    else "user"
                ),
                mono=mono,
                wall_time=wall,
            )
            return True

    if direction != "server_to_client" or not isinstance(method, str):
        return False

    if method == "thread/started":
        thread = (
            params.get("thread")
            if isinstance(params.get("thread"), Mapping)
            else {}
        )
        if thread.get("id") is not None:
            status.thread_id = str(thread["id"])
            changed = True
        model = thread.get("model") or params.get("model")
        if isinstance(model, str):
            changed = status.set_model(model) or changed
        status.note_event(method, mono=mono)
    elif method == "turn/started":
        turn = (
            params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
        )
        turn_id = turn.get("id") or params.get("turnId")
        if turn_id is not None:
            status.turn_started(
                str(turn_id),
                thread_id=str(params["threadId"])
                if params.get("threadId") is not None
                else None,
                mono=mono,
            )
            changed = True
    elif method == "turn/completed":
        turn = (
            params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
        )
        turn_id = turn.get("id") or params.get("turnId")
        status.turn_completed(
            str(turn_id) if turn_id is not None else None,
            status=str(turn.get("status") or "completed"),
            mono=mono,
        )
        changed = True
    elif method == "item/started":
        item = (
            params.get("item") if isinstance(params.get("item"), Mapping) else {}
        )
        item_id = item.get("id")
        if item_id is not None:
            status.item_started(
                str(item_id),
                str(item.get("type") or "unknown"),
                item=item,
                mono=mono,
                wall_time=wall,
                policy_decisions=envelope.get("runtime_policy_decisions"),
            )
            changed = True
    elif method == "item/completed":
        item = (
            params.get("item") if isinstance(params.get("item"), Mapping) else {}
        )
        item_id = item.get("id")
        status.item_completed(
            str(item_id) if item_id is not None else None,
            item=item,
            mono=mono,
            wall_time=wall,
            policy_decisions=envelope.get("runtime_policy_decisions"),
        )
        changed = True
    elif method == "thread/tokenUsage/updated":
        usage = params.get("tokenUsage")
        if status.set_token_usage(usage, mono=mono):
            if params.get("threadId") is not None:
                status.thread_id = str(params["threadId"])
            if params.get("turnId") is not None:
                status.turn_id = str(params["turnId"])
            changed = True
    elif method in MODEL_TOOL_ARGUMENT_DELTA_METHODS:
        delta = params.get("delta")
        item_id = params.get("itemId") or params.get("item_id")
        if isinstance(delta, str) and item_id is not None:
            changed = status.observe_model_tool_argument_delta(
                delta,
                item_id=str(item_id),
                method=method,
                mono=mono,
            )
            if not changed:
                status.note_event(method, mono=mono)
                changed = True
        else:
            status.note_event(method, mono=mono)
            changed = True
    elif method in MODEL_TEXT_OUTPUT_DELTA_METHODS:
        delta = params.get("delta")
        if isinstance(delta, str):
            changed = status.observe_model_delta(
                delta,
                method=method,
                mono=mono,
            )
        else:
            status.note_event(method, mono=mono)
    elif method in _APPROVAL_METHODS:
        item_id = params.get("itemId") or params.get("callId")
        response_id = message.get("id")
        status.approval_requested(
            request_id=str(response_id) if response_id is not None else None,
            item_id=str(item_id) if item_id is not None else None,
            method=method,
            command=params.get("command"),
            cwd=params.get("cwd"),
            reason=params.get("reason"),
            policy=envelope.get("interception") or envelope.get("policy_observation"),
            mono=mono,
            wall_time=wall,
        )
        changed = True
    elif method == "serverRequest/resolved":
        request_id = params.get("requestId")
        status.approval_resolved(
            request_id=str(request_id) if request_id is not None else None,
            decision="resolved",
            mono=mono,
            wall_time=wall,
        )
        changed = True
    else:
        status.note_event(method, mono=mono)

    return changed


ACTIVITY_LABELS = {
    "idle": "idle",
    "waiting_model": "waiting for model",
    "streaming": "model streaming",
    "local_tool": "local tool",
    "awaiting_user": "awaiting user",
    "stalled": "stalled?",
}
