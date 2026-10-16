"""Shared WorkBuddy transaction-journal to Lingmou event mapping."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from .workbench_store import WorkbenchEventStore
from .workbuddy_actions import WorkBuddyRuntime


def record_workbuddy_runtime_event(
    *,
    store: WorkbenchEventStore,
    runtime: WorkBuddyRuntime,
    event: Mapping[str, Any],
    os_audit: Mapping[str, Any] | None = None,
    thread_id: str | None = None,
    turn_id: str | None = None,
) -> bool:
    """Persist one idempotent event from the WorkBuddy SQLite outbox."""

    event_id = f"workbuddy:{runtime.gateway_status()['sandbox_id']}:{event['id']}"
    if store.contains_event_id(event_id):
        return False
    audit = dict(os_audit or {})
    kind = str(event.get("kind") or "workbuddy_event")
    raw_payload = event.get("payload")
    payload = raw_payload if isinstance(raw_payload, Mapping) else {}
    action_id = str(payload.get("action_id") or "") or None
    titles = {
        "action_prepared": "办公动作已准备，副作用尚未发生",
        "policy_decision": "办公策略已独立判定",
        "approval_required": "办公动作等待一次性确认",
        "approval_decision": "用户已处理办公审批",
        "executor_started": "受控办公执行器已启动",
        "action_result": "办公动作返回结构化结果",
    }
    if runtime.scenario_id == "WB-13":
        titles.update({
            "action_prepared": "模拟委托已准备，尚未成交",
            "policy_decision": "交易风险策略已判定",
            "approval_required": "模拟委托等待一次性确认",
            "approval_decision": "用户已处理模拟交易审批",
            "executor_started": "受控模拟交易执行器已启动",
            "action_result": "模拟交易返回结构化结果",
        })
    status = {
        "approval_required": "pending",
        "executor_started": "running",
        "policy_decision": str(payload.get("mode") or "observed"),
        "action_result": str(payload.get("status") or "completed"),
    }.get(kind, "observed")
    evidence: dict[str, Any] = {}
    if kind == "executor_started":
        os_trace_enabled = bool(audit.get("enabled"))
        trace_prefix = audit.get("trace_prefix")
        evidence = {
            "availability": (
                "controlled_executor_os_evidence"
                if os_trace_enabled
                else "controlled_executor_pid"
            ),
            "scope": "workbuddy_executor_child",
            "correlation": {
                "action_id": action_id,
                "pid": payload.get("pid"),
                "confidence": "exact_pid",
            },
            "os_trace": {
                "status": audit.get("status") or "not_configured",
                "backend": audit.get("backend"),
                "trace_prefix": trace_prefix if os_trace_enabled else None,
                "file_pattern": (
                    f"{trace_prefix}.*"
                    if os_trace_enabled and trace_prefix
                    else None
                ),
            },
        }
    elif action_id:
        evidence = {
            "availability": "transaction_journal",
            "correlation": {
                "action_id": action_id,
                "pid": payload.get("executor_pid"),
                "confidence": "exact_action",
            },
        }
    title = titles.get(kind, "WorkBuddy 状态更新")
    summary = str(payload.get("summary") or payload.get("reason") or kind)
    store.append(
        "policy_decision" if kind == "policy_decision" else kind,
        event_id=event_id,
        occurred_at=float(event.get("created_at") or time.time()),
        title=title,
        summary=summary,
        payload=dict(payload),
        explanation={
            "headline": title,
            "description": summary,
            "risk": {
                "level": (
                    "high"
                    if kind in {"policy_decision", "approval_required"}
                    else "normal"
                ),
                "policy_id": payload.get("policy_id"),
                "policy_mode": payload.get("mode"),
                "matched_rules": (
                    [payload["policy_id"]]
                    if payload.get("policy_id")
                    else payload.get("policy_ids", [])
                ),
            },
            "result": {"status": status, "summary": payload.get("summary")},
            "sources": ["workbuddy_transaction_gateway"],
        },
        evidence=evidence,
        source="lingmou_workbuddy",
        status=status,
        thread_id=thread_id,
        turn_id=turn_id,
        item_id=action_id,
    )
    return True


__all__ = ["record_workbuddy_runtime_event"]
