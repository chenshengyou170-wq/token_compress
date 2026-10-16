"""Local Codex app-server controller used by the Lingmou web workbench."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from websockets.asyncio.client import ClientConnection, unix_connect
from websockets.exceptions import ConnectionClosed

from . import __version__
from .action_result import action_result, request_hash as action_request_hash
from .activity_explainer import (
    collect_command_evidence,
    empty_evidence,
    explain_command,
    explain_file_change,
    explain_tool,
    policy_block_evidence,
)
from .business_policy import (
    BUSINESS_POLICY_ID,
    assess_business_command,
)
from .atomic_policy import load_document, save_document
from .filesystem_guard import guard_status, read_denials
from .live_security import build_live_security_payload, classify_live_command
from .policy_outcome import policy_block_outcome
from .redaction import redact_event, redact_text
from .runtime_policy import (
    RuntimePolicySession,
    assess_file_change_policies,
    decisions_from_rule_ids,
    merge_policy_decisions,
    strongest_policy_decisions,
)
from .security_policy import assess_approval_policies, intercept_dangerous_command_approval
from .storage import atomic_json_dump, json_load
from .workbench_store import WorkbenchEventStore
from .workbuddy_actions import WorkBuddyActionError, WorkBuddyRuntime
from .workbuddy_events import record_workbuddy_runtime_event
from .workbuddy_scenarios import scenario_instruction


class WorkbenchError(RuntimeError):
    """A workbench operation cannot be completed in the current state."""


class WorkbenchRpcError(WorkbenchError):
    def __init__(self, method: str, error: Any) -> None:
        super().__init__(f"{method} failed: {error}")
        self.method = method
        self.error = error


_RISK_RANK = {"normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class PendingInteraction:
    interaction_id: str
    rpc_id: int | str
    method: str
    kind: str
    params: dict[str, Any]
    future: asyncio.Future[Any]
    created_at: float
    risk: dict[str, Any]
    explanation: dict[str, Any]
    evidence: dict[str, Any]

    def public(self) -> dict[str, Any]:
        command = _command_text(self.params.get("command"))
        business_transaction = self.risk.get("policy_id") == BUSINESS_POLICY_ID
        return {
            "id": self.interaction_id,
            "kind": self.kind,
            "method": self.method,
            "created_at": self.created_at,
            "thread_id": self.params.get("threadId")
            or self.params.get("conversationId"),
            "turn_id": self.params.get("turnId"),
            "item_id": self.params.get("itemId") or self.params.get("callId"),
            "command": redact_text(command),
            "cwd": redact_text(str(self.params.get("cwd") or "")),
            "reason": redact_text(str(self.params.get("reason") or "")),
            "file_changes": redact_event(
                self.params.get("changes") or self.params.get("fileChanges") or []
            ),
            "permissions": redact_event(self.params.get("permissions") or {}),
            "questions": redact_event(self.params.get("questions") or []),
            "risk": self.risk,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "choices": (
                (
                    ["accept", "decline", "cancel"]
                    if business_transaction
                    else ["accept", "acceptForSession", "decline", "cancel"]
                )
                if self.kind == "approval"
                else []
            ),
            "action_result": self.risk.get("action_result"),
        }


def _command_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list) and all(isinstance(part, str) for part in value):
        return shlex.join(value)
    return ""


def _identifier(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def _status(value: Any, fallback: str) -> str:
    normalized = str(value or fallback)
    return {
        "inProgress": "running",
        "completed": "completed",
        "failed": "failed",
        "interrupted": "interrupted",
        "declined": "blocked",
    }.get(normalized, normalized)


def _business_risk(
    risk: Mapping[str, Any], business: Mapping[str, Any]
) -> dict[str, Any]:
    """Merge a business decision into the generic command risk contract."""

    result = dict(risk)
    if business.get("decision") in {"review", "decline"}:
        result["level"] = business.get("level") or result.get("level") or "high"
    existing_reasons = result.get("reasons")
    existing_reasons = existing_reasons if isinstance(existing_reasons, list) else []
    business_reasons = business.get("reasons")
    business_reasons = business_reasons if isinstance(business_reasons, list) else []
    result["reasons"] = [
        *[str(value) for value in business_reasons if str(value).strip()],
        *[str(value) for value in existing_reasons if str(value).strip()],
    ][:12]
    existing_rules = result.get("matched_rules")
    existing_rules = existing_rules if isinstance(existing_rules, list) else []
    business_rules = business.get("matched_rules")
    business_rules = business_rules if isinstance(business_rules, list) else []
    result["matched_rules"] = list(
        dict.fromkeys(
            str(value)
            for value in [*business_rules, *existing_rules]
            if str(value).strip()
        )
    )
    result.update(
        {
            "basis": "business_policy",
            "policy_basis": BUSINESS_POLICY_ID,
            "policy_id": business.get("policy_id"),
            "policy_name": business.get("policy_name"),
            "business_decision": business.get("decision"),
            "business_summary": business.get("summary"),
            "business_impact": business.get("business_impact"),
        }
    )
    if business.get("blocking_rule"):
        result["blocking_rule"] = business["blocking_rule"]
    return result


def _business_explanation(
    explanation: Mapping[str, Any],
    risk: Mapping[str, Any],
    business: Mapping[str, Any],
) -> dict[str, Any]:
    result = dict(explanation)
    effects = result.get("effects")
    effects = dict(effects) if isinstance(effects, Mapping) else {}
    effects["external_write"] = True
    result.update(
        {
            "headline": str(business.get("headline") or "提交消费订单"),
            "action": "submit_consumer_order",
            "description": str(business.get("summary") or "Agent 准备提交一笔消费订单。"),
            "effects": effects,
            "risk": dict(risk),
            "business_impact": business.get("business_impact"),
            "recommendation": business.get("recommendation"),
        }
    )
    sources = result.get("sources")
    sources = list(sources) if isinstance(sources, list) else []
    if "business_policy" not in sources:
        sources.append("business_policy")
    result["sources"] = sources
    return result


def _apply_policy_block_outcome(
    explanation: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replace detector-first block copy with one policy-specific conclusion."""

    result = dict(explanation)
    risk = result.get("risk")
    risk = dict(risk) if isinstance(risk, Mapping) else {}
    policy_risk = policy.get("risk")
    policy_risk = dict(policy_risk) if isinstance(policy_risk, Mapping) else {}
    blocking_rule = str(
        policy.get("blocking_rule")
        or policy_risk.get("blocking_rule")
        or policy.get("policy_id")
        or policy_risk.get("policy_id")
        or "UNKNOWN-POLICY"
    )
    policy_name = (
        policy.get("policy_name")
        or policy_risk.get("policy_name")
    )
    impact = policy.get("business_impact")
    impact = impact if isinstance(impact, Mapping) else None
    outcome = policy_block_outcome(
        blocking_rule,
        policy_name=policy_name,
        business_summary=policy.get("business_summary"),
        business_impact=impact,
    )

    raw_reasons = risk.get("reasons")
    raw_reasons = raw_reasons if isinstance(raw_reasons, list) else []
    technical_reasons = list(
        dict.fromkeys(
            str(value).strip()
            for value in raw_reasons
            if str(value).strip() and str(value).strip() != outcome["reason"]
        )
    )[:16]
    risk.update(
        {
            "reasons": [outcome["reason"]],
            "basis": "security_policy",
            "policy_id": blocking_rule,
            "blocking_rule": blocking_rule,
        }
    )
    result.update(
        {
            "headline": outcome["headline"],
            "description": outcome["summary"],
            "risk": risk,
            "result": {
                "status": "blocked",
                "summary": outcome["result_summary"],
            },
            "policy_summary": {
                **outcome,
                "technical_reasons": technical_reasons,
            },
            "conservative_fallback": False,
        }
    )
    if blocking_rule == "LIFE-ORDER-002":
        result["action"] = "block_consumer_order"
        if impact is not None:
            result["business_impact"] = dict(impact)
    sources = result.get("sources")
    sources = list(sources) if isinstance(sources, list) else []
    if "security_policy" not in sources:
        sources.append("security_policy")
    result["sources"] = sources
    return result, outcome


class WorkbenchController:
    """Own one frontend connection to the active CodexScope monitor gateway."""

    _APPROVAL_METHODS = frozenset(
        {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
            "item/permissions/requestApproval",
            "execCommandApproval",
            "applyPatchApproval",
        }
    )
    _USER_INPUT_METHODS = frozenset({"item/tool/requestUserInput"})

    def __init__(
        self,
        *,
        endpoint: str,
        repo: Path | str,
        run_dir: Path | str,
        store: WorkbenchEventStore,
        approval_policy: str = "untrusted",
        sandbox: str = "workspace-write",
        security_mode: str = "observe",
        reconnect_delay: float = 1.0,
        workbuddy_runtime: WorkBuddyRuntime | None = None,
        os_audit: Mapping[str, Any] | None = None,
    ) -> None:
        if not endpoint.startswith("unix://"):
            raise ValueError("workbench endpoint must use unix://")
        if approval_policy not in {"untrusted", "on-request", "never"}:
            raise ValueError("unsupported approval policy")
        if sandbox not in {"read-only", "workspace-write", "danger-full-access"}:
            raise ValueError("unsupported sandbox mode")
        if security_mode not in {"observe", "enforce"}:
            raise ValueError("security_mode must be observe or enforce")
        if (
            security_mode == "enforce"
            and approval_policy == "never"
            and workbuddy_runtime is None
        ):
            raise ValueError("enforce mode requires an interactive approval policy")

        self.socket_path = Path(endpoint.removeprefix("unix://"))
        self.repo = Path(repo).expanduser().resolve()
        self.run_dir = Path(run_dir).expanduser().resolve()
        self.store = store
        self.approval_policy = approval_policy
        self.sandbox = sandbox
        self.security_mode = security_mode
        self.reconnect_delay = reconnect_delay
        self.workbuddy_runtime = workbuddy_runtime
        self.os_audit = dict(os_audit or {})
        self._filesystem_guard = guard_status(self.run_dir, {})
        self._filesystem_audit_offset = 0
        self._policy_transition = False
        self._policy_error: str | None = None
        self._target_policy_request: str | None = None

        self.connected = False
        self.connection_error: str | None = None
        self.thread_id: str | None = _identifier(store.get_state("thread_id"))
        self.active_turn_id: str | None = None
        self.turn_status = "idle"
        self.model: str | None = None
        self._ws: ClientConnection | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._runner_task: asyncio.Task[None] | None = None
        self._security_task: asyncio.Task[None] | None = None
        self._workbuddy_outbox_task: asyncio.Task[None] | None = None
        self._server_request_tasks: set[asyncio.Task[None]] = set()
        self._rpc_pending: dict[int, asyncio.Future[Any]] = {}
        self._interactions: dict[str, PendingInteraction] = {}
        self._next_rpc_id = 1
        self._send_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._closing = False
        self._ready = asyncio.Event()
        self._last_connection_error: str | None = None
        self._policy_seen: set[str] = set()
        self._last_security_revision: tuple[Any, ...] | None = None
        self._task_goal: str | None = None
        self._task_started_at: float | None = None
        policy_not_before = store.get_state("monitor_policy_not_before")
        self._monitor_policy_not_before = (
            float(policy_not_before)
            if isinstance(policy_not_before, (int, float))
            else None
        )
        self._plan_steps: list[dict[str, Any]] = []
        self._item_context: dict[str, tuple[str | None, dict[str, Any]]] = {}
        self._item_started_at: dict[str, float] = {}
        self._active_command: dict[str, Any] | None = None
        self._pending_command_evidence: dict[str, dict[str, Any]] = {}
        self._runtime_policies = RuntimePolicySession(self.repo)
        self._workbuddy_outbox_cursor = 0
        self._workbuddy_summarized_turns: set[str] = set()

    def snapshot(self) -> dict[str, Any]:
        security = self.store.get_state("live_security", {})
        current_step = self._current_step()
        workbuddy = self.workbuddy_runtime
        pending = [
            interaction.public()
            for interaction in self._interactions.values()
        ]
        if workbuddy is not None:
            pending.extend(workbuddy.pending_interactions())
        return {
            "agent_backend": "codex",
            "active_scenario": workbuddy.scenario if workbuddy is not None else None,
            "mcp_gateway_status": (
                workbuddy.gateway_status()
                if workbuddy is not None
                else {"status": "not_configured"}
            ),
            "connected": self.connected,
            "connection_error": self.connection_error,
            "workspace": os.fspath(self.repo),
            "run_dir": os.fspath(self.run_dir),
            "thread_id": self.thread_id,
            "active_turn_id": self.active_turn_id,
            "turn_status": self.turn_status,
            "model": self.model,
            "approval_policy": (
                "one_shot_only" if workbuddy is not None else self.approval_policy
            ),
            "sandbox": self.sandbox,
            "security_mode": self.security_mode,
            "policy_transition": self._policy_transition,
            "policy_error": self._policy_error,
            "policy_constraint": self.store.get_state("policy_constraint"),
            "privacy": {
                "credentials": "always_redacted",
                "conversation_persisted": self.store.persist_conversation,
                "forensic_context_encrypted": self.store.forensic_mode,
                **(
                    {"hidden_reasoning_content": "never_collected"}
                    if workbuddy is not None
                    else {}
                ),
            },
            "history": self.store.history_status(),
            "pending_interactions": sorted(
                pending, key=lambda item: float(item.get("created_at") or 0)
            ),
            "live_security": security,
            "task": {
                "goal": redact_text(self._task_goal) if self._task_goal else None,
                "started_at": self._task_started_at,
                "current_step": current_step,
                "steps": self._plan_steps,
                "active_command": self._active_command,
            },
            "last_seq": self.store.last_seq,
        }

    def _current_step(self) -> dict[str, Any]:
        for step in self._plan_steps:
            if step.get("status") in {"in_progress", "running"}:
                return dict(step)
        for step in self._plan_steps:
            if step.get("status") == "pending":
                return dict(step)
        if self._plan_steps:
            return dict(self._plan_steps[-1])
        return {
            "id": f"{self.active_turn_id or 'task'}:understand",
            "index": 1,
            "title": "理解任务",
            "status": "running" if self.active_turn_id else "pending",
            "source": "workbench_fallback",
        }

    def _event_step(self) -> dict[str, Any]:
        return self._current_step()

    def _purpose(self) -> tuple[str | None, str]:
        step = self._current_step()
        if step.get("source") == "agent_plan" and step.get("title"):
            return f"完成当前计划步骤：{step['title']}", "agent_plan"
        return None, "contextual_inference"

    def _record_policy_decisions(
        self,
        decisions: list[dict[str, Any]],
        *,
        subject_kind: str,
        subject_summary: str,
        thread_id: str | None = None,
        turn_id: str | None = None,
        item_id: str | None = None,
        occurred_at: float | None = None,
        step: Mapping[str, Any] | None = None,
    ) -> None:
        """Persist one replayable journal event per matched policy."""

        for decision in merge_policy_decisions(decisions):
            policy_id = str(decision.get("policy_id") or "").strip()
            if not policy_id:
                continue
            stage = str(decision.get("stage") or "runtime_observation")
            result = str(decision.get("result") or "observed")
            identity = item_id or hashlib.sha256(
                f"{subject_kind}\0{subject_summary}\0{turn_id or ''}".encode(
                    "utf-8", errors="replace"
                )
            ).hexdigest()[:24]
            event_id = f"policy-decision:{identity}:{policy_id}:{stage}:{result}"
            if event_id in self._policy_seen or self.store.contains_event_id(event_id):
                self._policy_seen.add(event_id)
                continue
            self._policy_seen.add(event_id)
            blocking = bool(decision.get("blocking")) or result == "blocked"
            review = result in {"review", "review_required"}
            status = "blocked" if blocking else "review" if review else "observed"
            name = str(decision.get("policy_name") or policy_id)
            detector_reason = str(
                decision.get("reason") or f"事件命中 {policy_id}"
            )
            block_outcome = (
                policy_block_outcome(policy_id, policy_name=name)
                if blocking
                else None
            )
            reason = (
                str(block_outcome["reason"])
                if block_outcome is not None
                else detector_reason
            )
            mode = str(decision.get("mode") or "observe")
            action_summary = (
                str(block_outcome["result_summary"])
                if blocking
                else (
                    "命中结果已附加到原有审批，不新增打断"
                    if stage.startswith("pre_execution")
                    else "已标为工具调用前复核线索，不新增灵眸弹窗"
                    if stage == "tool_before"
                    else "命中结果已保存为复核线索，不新增打断"
                )
                if review
                else "已静默记录，不影响用户继续操作"
            )
            evidence_data = decision.get("evidence")
            evidence_data = (
                dict(evidence_data) if isinstance(evidence_data, Mapping) else {}
            )
            if blocking and detector_reason != reason:
                evidence_data["detector_reason"] = detector_reason[:320]
            evidence = {
                "schema_version": "lingmou.activity-evidence.v1",
                "availability": (
                    "pre_execution"
                    if stage.startswith("pre_execution") or stage == "tool_before"
                    else "available"
                ),
                "completeness": "partial",
                "summary": f"{name} 的独立策略决策与脱敏证据已保存",
                "observations": [
                    {
                        "kind": "policy_decision",
                        "label": reason,
                        "source": "security_policy",
                        "turn_id": turn_id,
                        "item_id": item_id,
                        "policy_id": policy_id,
                        "blocking_rule": policy_id if blocking else None,
                        "matched_rules": [policy_id],
                        "correlation_confidence": "exact_item" if item_id else "exact_event",
                        "decision": result,
                        "stage": stage,
                        "policy_evidence": evidence_data,
                    }
                ],
                "negative_observations": (
                    [
                        {
                            "label": "该策略没有额外阻断或弹窗",
                            "source": "security_policy",
                            "scope": "policy_decision",
                        }
                    ]
                    if not blocking
                    else []
                ),
                "correlation": {
                    "turn_id": turn_id,
                    "item_id": item_id,
                    "pid": None if blocking else None,
                    "source": str(decision.get("evidence_source") or "runtime_event"),
                    "confidence": "exact_item" if item_id else "exact_event",
                },
            }
            explanation = {
                "schema_version": "lingmou.activity-explanation.v1",
                "headline": (
                    str(block_outcome["headline"])
                    if block_outcome is not None
                    else f"{name}：{'需复核' if review else '已记录'}"
                ),
                "action": "policy_decision",
                "description": (
                    str(block_outcome["summary"])
                    if block_outcome is not None
                    else reason
                ),
                "purpose": {
                    "text": "让每条策略命中都能独立核对和回放",
                    "source": "security_policy",
                    "confidence": "observed",
                },
                "effects": {"reads": [], "writes": [], "network": [], "processes": []},
                "risk": {
                    "level": str(decision.get("level") or "warning"),
                    "reasons": [reason],
                    "basis": str(decision.get("evidence_source") or "runtime_event"),
                    "policy_id": policy_id,
                    "blocking_rule": policy_id if blocking else None,
                    "matched_rules": [policy_id],
                    "policy_mode": mode,
                    "policy_stage": stage,
                    "policy_result": result,
                },
                "result": {"status": status, "summary": action_summary},
                "sources": ["security_policy"],
                "conservative_fallback": False,
            }
            if block_outcome is not None:
                explanation["policy_summary"] = {
                    **block_outcome,
                    "technical_reasons": [detector_reason],
                }
            self.store.append(
                "policy_decision",
                event_id=event_id,
                title=explanation["headline"],
                summary=reason,
                payload={
                    "schema_version": "lingmou.policy-event.v1",
                    "decision": decision,
                    "subject": {
                        "kind": subject_kind,
                        "summary": redact_text(subject_summary)[:2_048],
                        "item_id": item_id,
                    },
                },
                explanation=explanation,
                evidence=evidence,
                source="codexscope_policy",
                status=status,
                thread_id=thread_id,
                turn_id=turn_id,
                item_id=item_id,
                occurred_at=occurred_at,
                step=step or self._event_step(),
            )

    def _update_plan_steps(
        self, plan: list[Any], *, turn_id: str | None
    ) -> None:
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(plan):
            if isinstance(raw, Mapping):
                title = str(
                    raw.get("step")
                    or raw.get("title")
                    or raw.get("description")
                    or f"计划步骤 {index + 1}"
                )
                status = str(raw.get("status") or "pending")
            else:
                title = str(raw)
                status = "pending"
            status = {
                "inProgress": "in_progress",
                "running": "in_progress",
                "complete": "completed",
            }.get(status, status)
            normalized.append(
                {
                    "id": f"{turn_id or self.active_turn_id or 'task'}:step:{index + 1}",
                    "index": index + 1,
                    "title": redact_text(title),
                    "status": status,
                    "source": "agent_plan",
                }
            )
        if normalized:
            self._plan_steps = normalized

    async def start_background(self) -> None:
        if self._runner_task is not None and not self._runner_task.done():
            return
        self._closing = False
        self._security_task = asyncio.create_task(
            self._security_watch_loop(), name="lingmou-security-watch"
        )
        if self.workbuddy_runtime is not None:
            self._workbuddy_outbox_task = asyncio.create_task(
                self._workbuddy_outbox_loop(), name="lingmou-workbuddy-outbox"
            )
        self._runner_task = asyncio.create_task(
            self._connection_loop(), name="lingmou-appserver-connection"
        )

    async def wait_until_ready(self, timeout: float = 10.0) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    async def stop(self) -> None:
        self._closing = True
        for interaction in tuple(self._interactions.values()):
            if not interaction.future.done():
                interaction.future.cancel()
        self._interactions.clear()
        tasks = [
            task
            for task in (
                self._runner_task,
                self._security_task,
                self._workbuddy_outbox_task,
            )
            if task
        ]
        for task in tasks:
            task.cancel()
        if self._ws is not None:
            try:
                await self._ws.close(code=1000, reason="workbench stopped")
            except Exception:
                pass
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.connected = False
        self._ready.clear()

    async def _workbuddy_outbox_loop(self) -> None:
        while not self._closing:
            await self._drain_workbuddy_outbox_once()
            await asyncio.sleep(0.1)

    async def _drain_workbuddy_outbox_once(self) -> None:
        runtime = self.workbuddy_runtime
        if runtime is None:
            return
        page = await asyncio.to_thread(
            runtime.drain_events,
            after_id=self._workbuddy_outbox_cursor,
            limit=500,
        )
        for event in page["events"]:
            record_workbuddy_runtime_event(
                store=self.store,
                runtime=runtime,
                event=event,
                os_audit=self.os_audit,
                thread_id=self.thread_id,
                turn_id=self.active_turn_id,
            )
            self._workbuddy_outbox_cursor = max(
                self._workbuddy_outbox_cursor, int(event["id"])
            )

    async def _connection_loop(self) -> None:
        while not self._closing:
            try:
                await self._connect_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = redact_text(str(exc)) or type(exc).__name__
                self.connection_error = message
                if message != self._last_connection_error:
                    self.store.append(
                        "connection",
                        title="本地 Agent 连接中断",
                        summary=message,
                        source="lingmou_workbench",
                        status="failed",
                    )
                    self._last_connection_error = message
            finally:
                self.connected = False
                self._ready.clear()
                self._ws = None
                self._fail_rpc_pending(WorkbenchError("app-server connection closed"))
                self._cancel_interactions()
            if not self._closing:
                await asyncio.sleep(self.reconnect_delay)

    async def _connect_once(self) -> None:
        if self._target_policy_request:
            current = guard_status(self.run_dir, {})
            if current.get("request_id") != self._target_policy_request or current.get("status") not in {"active", "disabled"}:
                await asyncio.sleep(0.2)
                return
        websocket = await unix_connect(
            path=os.fspath(self.socket_path),
            compression=None,
            max_size=None,
            open_timeout=10,
            close_timeout=2,
        )
        self._ws = websocket
        self._reader_task = asyncio.create_task(
            self._reader_loop(websocket), name="lingmou-appserver-reader"
        )
        try:
            await self.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "codexscope-workbench",
                        "title": "灵眸工作台",
                        "version": __version__,
                    },
                    "capabilities": {"experimentalApi": True},
                },
            )
            await self.notify("initialized", {})
            await self._resume_saved_thread()
            self.connected = True
            self.connection_error = None
            self._last_connection_error = None
            self._ready.set()
            self.store.append(
                "connection",
                title="已连接本地 Agent",
                summary=os.fspath(self.socket_path),
                source="lingmou_workbench",
                status="connected",
            )
            await self._reader_task
        finally:
            if not self._reader_task.done():
                self._reader_task.cancel()
                await asyncio.gather(self._reader_task, return_exceptions=True)
            try:
                await websocket.close()
            except Exception:
                pass

    async def _resume_saved_thread(self) -> None:
        if not self.thread_id:
            return
        saved = self.thread_id
        try:
            response = await self.request(
                "thread/resume",
                {
                    "threadId": saved,
                    "cwd": os.fspath(self.repo),
                    "approvalPolicy": self.approval_policy,
                    "sandbox": self.sandbox,
                },
            )
        except WorkbenchRpcError as exc:
            self.thread_id = None
            self.store.set_state("thread_id", None)
            self.store.append(
                "session",
                title="历史会话无法恢复",
                summary=str(exc),
                source="lingmou_workbench",
                status="warning",
            )
            return
        self._apply_thread_response(response)
        self.store.append(
            "session",
            title="已恢复 Agent 会话",
            summary=saved,
            source="lingmou_workbench",
            status="completed",
            thread_id=self.thread_id,
        )

    async def _reader_loop(self, websocket: ClientConnection) -> None:
        try:
            async for frame in websocket:
                if not isinstance(frame, str):
                    raise WorkbenchError("app-server sent an unsupported binary frame")
                try:
                    message = json.loads(frame)
                except json.JSONDecodeError as exc:
                    raise WorkbenchError("app-server sent invalid JSON") from exc
                if not isinstance(message, dict):
                    raise WorkbenchError("app-server JSON-RPC frame must be an object")
                response_id = message.get("id")
                if (
                    response_id is not None
                    and "method" not in message
                    and type(response_id) is int
                    and response_id in self._rpc_pending
                ):
                    future = self._rpc_pending.pop(response_id)
                    if "error" in message:
                        future.set_exception(WorkbenchRpcError("request", message["error"]))
                    else:
                        future.set_result(message.get("result"))
                    continue
                if isinstance(message.get("method"), str) and response_id is not None:
                    task = asyncio.create_task(
                        self._handle_server_request(message),
                        name=f"lingmou-server-request:{message.get('method')}",
                    )
                    self._server_request_tasks.add(task)
                    task.add_done_callback(self._server_request_tasks.discard)
                    continue
                if isinstance(message.get("method"), str):
                    await self._handle_notification(
                        str(message["method"]),
                        message.get("params") if isinstance(message.get("params"), dict) else {},
                    )
        except ConnectionClosed as exc:
            if not self._closing:
                raise WorkbenchError(
                    f"gateway closed the connection ({exc.code}: {exc.reason})"
                ) from exc

    def _fail_rpc_pending(self, error: BaseException) -> None:
        for future in tuple(self._rpc_pending.values()):
            if not future.done():
                future.set_exception(error)
        self._rpc_pending.clear()

    def _cancel_interactions(self) -> None:
        for interaction in tuple(self._interactions.values()):
            if not interaction.future.done():
                interaction.future.cancel()
        self._interactions.clear()

    async def _send_json(self, value: Mapping[str, Any]) -> None:
        websocket = self._ws
        if websocket is None:
            raise WorkbenchError("本地 Agent 尚未连接")
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        async with self._send_lock:
            await websocket.send(data)

    async def request(
        self, method: str, params: Mapping[str, Any], *, timeout: float = 60.0
    ) -> Any:
        if self._ws is None:
            raise WorkbenchError("本地 Agent 尚未连接")
        request_id = self._next_rpc_id
        self._next_rpc_id += 1
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._rpc_pending[request_id] = future
        try:
            await self._send_json({"id": request_id, "method": method, "params": dict(params)})
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            except WorkbenchRpcError as exc:
                exc.method = method
                exc.args = (f"{method} failed: {exc.error}",)
                raise
        finally:
            self._rpc_pending.pop(request_id, None)

    async def notify(self, method: str, params: Mapping[str, Any]) -> None:
        await self._send_json({"method": method, "params": dict(params)})

    async def _ensure_thread(self) -> str:
        if self.thread_id:
            return self.thread_id
        response = await self.request(
            "thread/start",
            {
                "cwd": os.fspath(self.repo),
                "approvalPolicy": self.approval_policy,
                "sandbox": self.sandbox,
                "serviceName": (
                    "codexscope-lingmou-workbuddy"
                    if self.workbuddy_runtime is not None
                    else "codexscope-lingmou-workbench"
                ),
            },
        )
        self._apply_thread_response(response)
        if not self.thread_id:
            raise WorkbenchError("thread/start returned no thread id")
        self.store.append(
            "session",
            title="已创建 Agent 会话",
            summary=self.thread_id,
            source="lingmou_workbench",
            status="completed",
            thread_id=self.thread_id,
        )
        return self.thread_id

    def _apply_thread_response(self, response: Any) -> None:
        value = response if isinstance(response, Mapping) else {}
        thread = value.get("thread")
        thread = thread if isinstance(thread, Mapping) else {}
        thread_id = _identifier(thread.get("id"))
        if thread_id:
            self.thread_id = thread_id
            self.store.set_state("thread_id", thread_id)
        model = value.get("model") or thread.get("model")
        if isinstance(model, str):
            self.model = model
        turns = thread.get("turns")
        if isinstance(turns, list):
            active = next(
                (
                    turn
                    for turn in reversed(turns)
                    if isinstance(turn, Mapping)
                    and turn.get("status") in {"inProgress", "running"}
                ),
                None,
            )
            if isinstance(active, Mapping):
                self.active_turn_id = _identifier(active.get("id"))
                self.turn_status = "running"

    async def send_prompt(
        self, text: str, *, scenario_id: str | None = None
    ) -> dict[str, Any]:
        runtime = self.workbuddy_runtime
        if runtime is None and scenario_id is not None:
            raise WorkbenchError(
                "WorkBuddy 场景只能通过 `codexscope workbuddy` 启动"
            )
        requested_scenario: str | None = None
        if runtime is not None:
            requested_scenario = str(scenario_id or runtime.scenario_id).upper()
            if requested_scenario != runtime.scenario_id:
                raise WorkbenchError(
                    f"当前独立沙箱属于 {runtime.scenario_id}；切换场景需要干净重启"
                )
        prompt = text.strip()
        if not prompt:
            raise WorkbenchError("提示词不能为空")
        if len(prompt.encode("utf-8")) > 128_000:
            raise WorkbenchError("提示词超过 128 KB 限制")
        async with self._operation_lock:
            if self._policy_transition or self._policy_error:
                raise WorkbenchError(self._policy_error or "策略正在启用，请稍候")
            document, _ = load_document(self.repo)
            if guard_status(self.run_dir, document).get("restart_required"):
                raise WorkbenchError("目录策略尚未启用，请先在策略中心启用，再提交任务")
            if not self.connected:
                raise WorkbenchError("本地 Agent 尚未连接")
            if self.active_turn_id:
                raise WorkbenchError("当前回合仍在运行，请使用 steer 实时补充")
            thread_id = await self._ensure_thread()
            self._task_goal = prompt
            self._task_started_at = time.time()
            if self._monitor_policy_not_before is None:
                self._monitor_policy_not_before = self._task_started_at
                self.store.set_state(
                    "monitor_policy_not_before", self._monitor_policy_not_before
                )
            self._plan_steps = [
                {
                    "id": "task:understand",
                    "index": 1,
                    "title": "理解任务",
                    "status": "in_progress",
                    "source": "workbench_fallback",
                }
            ]
            self._item_context.clear()
            self._item_started_at.clear()
            self._pending_command_evidence.clear()
            self._active_command = None
            client_message_id = str(uuid.uuid4())
            self.store.append(
                "user_prompt",
                title=(
                    "你提交了 WorkBuddy 任务"
                    if runtime is not None
                    else "你提交了任务"
                ),
                summary=prompt,
                payload={
                    "text": prompt,
                    "client_message_id": client_message_id,
                    **(
                        {"scenario_id": requested_scenario}
                        if requested_scenario is not None
                        else {}
                    ),
                },
                source="user",
                status="submitted",
                thread_id=thread_id,
                step=self._event_step(),
            )
            self._record_policy_decisions(
                self._runtime_policies.assess_user_text(prompt),
                subject_kind="user_prompt",
                subject_summary="用户提交的任务文本（正文不随策略事件落盘）",
                thread_id=thread_id,
                item_id=client_message_id,
                step=self._event_step(),
            )
            response = await self.request(
                "turn/start",
                {
                    "threadId": thread_id,
                    "input": [
                        {"type": "text", "text": prompt},
                        *(
                            [
                                {
                                    "type": "text",
                                    "text": scenario_instruction(requested_scenario),
                                }
                            ]
                            if requested_scenario is not None
                            else []
                        ),
                    ],
                    "clientUserMessageId": client_message_id,
                    "cwd": os.fspath(self.repo),
                    "approvalPolicy": self.approval_policy,
                },
            )
            turn = response.get("turn") if isinstance(response, Mapping) else None
            turn = turn if isinstance(turn, Mapping) else {}
            turn_id = _identifier(turn.get("id"))
            if turn_id:
                self.active_turn_id = turn_id
                self.turn_status = "running"
            return {
                "thread_id": thread_id,
                "turn_id": turn_id,
                **(
                    {"scenario_id": requested_scenario}
                    if requested_scenario is not None
                    else {}
                ),
            }

    async def activate_policy(self, document: dict[str, Any], revision: str, summary: str) -> dict[str, Any]:
        """Save a reviewed proposal and wait for a protected fresh Agent."""
        async with self._operation_lock:
            if self.active_turn_id or self._interactions:
                raise WorkbenchError("当前任务仍在运行，请完成或停止任务后启用新策略")
            current = guard_status(self.run_dir, document)
            if not current.get("managed"):
                raise WorkbenchError("当前运行不支持自动启用策略，请启动新版灵眸工作台")
            document, saved_revision = save_document(self.repo, document, revision)
            self._policy_transition = True
            try:
                request_id = uuid.uuid4().hex
                self._target_policy_request = request_id
                self.thread_id = None
                self.store.set_state("thread_id", None)
                self._ready.clear()
                atomic_json_dump(self.run_dir / "agent-control/request.json", {
                    "id": request_id, "revision": saved_revision,
                })
                if self._ws is not None:
                    await self._ws.close()
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    state = guard_status(self.run_dir, document)
                    if state.get("request_id") == request_id:
                        if state.get("status") == "failed":
                            raise WorkbenchError(str(state.get("error") or "策略启用失败"))
                        if state.get("status") in {"active", "disabled"} and self._ready.is_set():
                            break
                    await asyncio.sleep(0.15)
                else:
                    raise WorkbenchError("策略启用超时，任务入口已暂停，请重试启用")
                self._filesystem_guard = state
                await self._ensure_thread()
                self._policy_error = None
                constraint = {"summary": summary, "revision": saved_revision,
                              "denied_paths": state.get("denied_paths", []), "status": "active"}
                self.store.set_state("policy_constraint", constraint)
                self.store.append("policy_activated", title="用户策略已生效", summary=summary,
                                  payload=constraint, source="lingmou_workbench", status="completed")
                return {"document": document, "revision": saved_revision, "constraint": constraint}
            except Exception as exc:
                self._policy_error = f"策略未完成启用：{exc}"
                raise
            finally:
                self._policy_transition = False

    async def steer(self, text: str) -> dict[str, Any]:
        addition = text.strip()
        if not addition:
            raise WorkbenchError("steer 内容不能为空")
        if len(addition.encode("utf-8")) > 64_000:
            raise WorkbenchError("steer 内容超过 64 KB 限制")
        async with self._operation_lock:
            if not self.connected or not self.thread_id or not self.active_turn_id:
                raise WorkbenchError("没有可 steer 的运行中回合")
            expected = self.active_turn_id
            self.store.append(
                "user_prompt",
                title="你实时补充了要求",
                summary=addition,
                payload={"text": addition, "mode": "steer"},
                source="user",
                status="submitted",
                thread_id=self.thread_id,
                turn_id=expected,
                step=self._event_step(),
            )
            self._record_policy_decisions(
                self._runtime_policies.assess_user_text(addition),
                subject_kind="user_prompt",
                subject_summary="用户追加的任务文本（正文不随策略事件落盘）",
                thread_id=self.thread_id,
                turn_id=expected,
                item_id=f"steer:{uuid.uuid4().hex}",
                step=self._event_step(),
            )
            response = await self.request(
                "turn/steer",
                {
                    "threadId": self.thread_id,
                    "expectedTurnId": expected,
                    "input": [{"type": "text", "text": addition}],
                    "clientUserMessageId": str(uuid.uuid4()),
                },
            )
            return {
                "thread_id": self.thread_id,
                "turn_id": (
                    response.get("turnId")
                    if isinstance(response, Mapping)
                    else expected
                ),
            }

    async def interrupt(self) -> dict[str, Any]:
        async with self._operation_lock:
            if not self.connected or not self.thread_id or not self.active_turn_id:
                raise WorkbenchError("没有可停止的运行中回合")
            turn_id = self.active_turn_id
            await self.request(
                "turn/interrupt",
                {"threadId": self.thread_id, "turnId": turn_id},
            )
            self.turn_status = "interrupting"
            self.store.append(
                "turn",
                title="正在停止 Agent",
                summary=turn_id,
                source="user",
                status="interrupting",
                thread_id=self.thread_id,
                turn_id=turn_id,
                step=self._event_step(),
            )
            return {"thread_id": self.thread_id, "turn_id": turn_id}

    async def respond_approval(self, interaction_id: str, decision: str) -> dict[str, Any]:
        if self.workbuddy_runtime is not None and interaction_id.startswith("wb-"):
            try:
                result = await asyncio.to_thread(
                    self.workbuddy_runtime.decide, interaction_id, decision
                )
            except WorkBuddyActionError as exc:
                raise WorkbenchError(str(exc)) from exc
            await self._drain_workbuddy_outbox_once()
            return result
        interaction = self._interactions.get(interaction_id)
        if interaction is None or interaction.kind != "approval":
            raise WorkbenchError("审批请求不存在或已经处理")
        if decision not in {"accept", "acceptForSession", "decline", "cancel"}:
            raise WorkbenchError("不支持的审批决定")
        if (
            decision == "acceptForSession"
            and interaction.risk.get("policy_id") == BUSINESS_POLICY_ID
        ):
            raise WorkbenchError("消费交易只能逐次批准，不能在本会话永久放行")
        if interaction.method == "item/permissions/requestApproval":
            result: dict[str, Any] = {
                "permissions": (
                    interaction.params.get("permissions", {})
                    if decision.startswith("accept")
                    else {}
                ),
                "scope": "session" if decision == "acceptForSession" else "turn",
            }
        elif interaction.method in {"execCommandApproval", "applyPatchApproval"}:
            legacy = {
                "accept": "approved",
                "acceptForSession": "approved_for_session",
                "decline": {"denied": {"rejection": "用户在灵眸工作台中拒绝"}},
                "cancel": "abort",
            }[decision]
            result = {"decision": legacy}
        else:
            result = {"decision": decision}
        if not interaction.future.done():
            interaction.future.set_result(result)
        self._interactions.pop(interaction_id, None)
        status = "approved" if decision.startswith("accept") else "blocked"
        decision_label = "用户已允许该操作" if status == "approved" else "用户已拒绝该操作"
        explanation = {
            **interaction.explanation,
            "headline": "审批已通过" if status == "approved" else "审批已拒绝",
            "result": {
                "status": status,
                "summary": decision_label,
                "decision": decision,
            },
            "sources": [
                *interaction.explanation.get("sources", []),
                "user_decision",
            ],
        }
        evidence = {
            **interaction.evidence,
            "availability": "available",
            "completeness": "complete",
            "summary": decision_label,
            "observations": [
                {
                    "kind": "approval_decision",
                    "label": decision_label,
                    "source": "user_decision",
                    "turn_id": _identifier(interaction.params.get("turnId")),
                    "item_id": _identifier(
                        interaction.params.get("itemId")
                        or interaction.params.get("callId")
                    ),
                    "correlation_confidence": "exact",
                }
            ],
        }
        approval_payload: dict[str, Any] = {
            "interaction_id": interaction_id,
            "decision": decision,
        }
        pending_contract = interaction.risk.get("action_result")
        if status == "blocked" and isinstance(pending_contract, Mapping):
            approval_payload["action_result"] = action_result(
                action_id=str(pending_contract.get("action_id") or interaction_id),
                status="declined",
                summary="用户已拒绝该消费动作，执行进程没有启动。",
                policy_ids=(
                    pending_contract.get("policy_ids")
                    if isinstance(pending_contract.get("policy_ids"), list)
                    else []
                ),
                business_impact=(
                    pending_contract.get("business_impact")
                    if isinstance(pending_contract.get("business_impact"), Mapping)
                    else {}
                ),
                safe_next_step=str(
                    pending_contract.get("safe_next_step")
                    or "先查询已有订单，不要盲目重试。"
                ),
                request_hash_value=str(pending_contract.get("request_hash") or ""),
            )
        self.store.append(
            "approval",
            title="审批已通过" if status == "approved" else "审批已拒绝",
            summary=_command_text(interaction.params.get("command"))
            or str(interaction.params.get("reason") or interaction.method),
            payload=approval_payload,
            explanation=explanation,
            evidence=evidence,
            source="user",
            status=status,
            thread_id=_identifier(interaction.params.get("threadId")),
            turn_id=_identifier(interaction.params.get("turnId")),
            item_id=_identifier(
                interaction.params.get("itemId") or interaction.params.get("callId")
            ),
            step=self._event_step(),
        )
        return {"id": interaction_id, "decision": decision}

    async def respond_user_input(
        self, interaction_id: str, answers: Mapping[str, list[str]]
    ) -> dict[str, Any]:
        interaction = self._interactions.get(interaction_id)
        if interaction is None or interaction.kind != "user_input":
            raise WorkbenchError("问题请求不存在或已经处理")
        result = {
            "answers": {
                str(question_id): {"answers": [str(value) for value in values]}
                for question_id, values in answers.items()
            }
        }
        if not interaction.future.done():
            interaction.future.set_result(result)
        self._interactions.pop(interaction_id, None)
        self.store.append(
            "user_input_response",
            title="已回答 Agent 的问题",
            summary=f"{len(answers)} 个回答",
            source="user",
            status="completed",
            thread_id=_identifier(interaction.params.get("threadId")),
            turn_id=_identifier(interaction.params.get("turnId")),
            item_id=_identifier(interaction.params.get("itemId")),
        )
        return {"id": interaction_id, "answered": True}

    async def _handle_server_request(self, message: Mapping[str, Any]) -> None:
        rpc_id = message.get("id")
        if not isinstance(rpc_id, (str, int)) or isinstance(rpc_id, bool):
            return
        method = str(message.get("method"))
        params = message.get("params")
        safe_params = dict(params) if isinstance(params, Mapping) else {}
        try:
            if method in self._APPROVAL_METHODS:
                result = await self._approval_request(rpc_id, method, safe_params)
            elif method in self._USER_INPUT_METHODS:
                result = await self._user_input_request(rpc_id, method, safe_params)
            else:
                await self._send_json(
                    {
                        "id": rpc_id,
                        "error": {
                            "code": -32601,
                            "message": f"unsupported app-server request: {method}",
                        },
                    }
                )
                self.store.append(
                    "error",
                    title="遇到暂不支持的 Agent 交互",
                    summary=method,
                    source="lingmou_workbench",
                    status="failed",
                )
                return
            await self._send_json({"id": rpc_id, "result": result})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            try:
                await self._send_json(
                    {
                        "id": rpc_id,
                        "error": {"code": -32603, "message": redact_text(str(exc))},
                    }
                )
            except Exception:
                pass

    @staticmethod
    def _interaction_id() -> str:
        # Keep this URL-safe and opaque. Protocol methods contain slashes and
        # request/item identifiers must never become routing authority.
        return f"interaction-{uuid.uuid4().hex}"

    async def _approval_request(
        self, rpc_id: int | str, method: str, params: dict[str, Any]
    ) -> Any:
        command = _command_text(params.get("command"))
        assessment = (
            classify_live_command(
                command,
                status="review",
                cwd=str(params.get("cwd")) if params.get("cwd") else None,
            )
            if command
            else {
                "risk": {
                    "level": "warning",
                    "reasons": ["Agent 请求修改文件"],
                    "basis": "codex_approval",
                },
                "matched_rules": [],
            }
        )
        risk = assessment.get("risk") if isinstance(assessment, Mapping) else {}
        risk = dict(risk) if isinstance(risk, Mapping) else {}
        changes = params.get("changes") or params.get("fileChanges") or []
        safe_changes = (
            [value for value in changes if isinstance(value, Mapping)]
            if isinstance(changes, list)
            else []
        )
        assessment_rules = (
            [
                str(value)
                for value in assessment.get("matched_rules", [])
                if str(value).strip()
            ]
            if isinstance(assessment, Mapping)
            else []
        )
        runtime_decisions = (
            self._runtime_policies.assess_command(
                command,
                cwd=str(params.get("cwd") or "") or None,
                principal=params,
            )
            if command
            else assess_file_change_policies(safe_changes)
        )
        policy_decisions = merge_policy_decisions(
            assessment.get("policy_decisions", [])
            if isinstance(assessment, Mapping)
            else [],
            runtime_decisions,
            decisions_from_rule_ids(
                assessment_rules,
                reasons=[str(value) for value in risk.get("reasons", [])]
                if isinstance(risk.get("reasons"), list)
                else [],
                stage=(
                    "pre_execution_approval"
                    if command
                    else "pre_execution_file_approval"
                ),
            ),
        )
        for decision in policy_decisions:
            policy_id = str(decision.get("policy_id") or "")
            if policy_id and policy_id not in assessment_rules:
                assessment_rules.append(policy_id)
        risk["matched_rules"] = redact_event(assessment_rules)
        risk["policy_decisions"] = redact_event(policy_decisions)
        decision_reasons = [
            str(decision.get("reason") or "")
            for decision in policy_decisions
            if str(decision.get("reason") or "").strip()
        ]
        existing_reasons = risk.get("reasons")
        existing_reasons = existing_reasons if isinstance(existing_reasons, list) else []
        risk["reasons"] = list(
            dict.fromkeys([*map(str, existing_reasons), *decision_reasons])
        )[:16]
        strongest = max(
            [str(risk.get("level") or "normal")]
            + [str(decision.get("level") or "warning") for decision in policy_decisions],
            key=lambda value: _RISK_RANK.get(value, 0),
        )
        risk["level"] = strongest
        business = (
            assess_business_command(command, self.repo)
            if command
            else None
        )
        if business is not None:
            risk = _business_risk(risk, business)

        if command:
            # Preserve the fast deterministic path; only semantic configurations
            # can perform network I/O and need the worker thread.
            try:
                config_snapshot = load_document(self.repo)
                semantic_enabled = bool(config_snapshot[0].get("semantic_atoms"))
            except ValueError:
                config_snapshot = None
                semantic_enabled = False
            assessment_args = dict(
                config_snapshot=config_snapshot,
                workspace=self.repo,
                cwd=params.get("cwd"),
                runtime_session=self._runtime_policies,
                assessment=assessment,
                principal=params,
            )
            assessment = (await asyncio.to_thread(assess_approval_policies, command, **assessment_args)
                          if semantic_enabled else assess_approval_policies(command, **assessment_args))
            self.store.append(
                "policy_evaluation", event_id=f"policy-evaluation:{params.get('itemId') or params.get('callId')}" if params.get("itemId") or params.get("callId") else None, title="执行前条件判断", summary="展开查看命中、未命中和证据不足的条件",
                payload={"traces": assessment["policy_traces"], "command": command},
                source="atomic_policy", status="observed",
                thread_id=_identifier(params.get("threadId")), turn_id=_identifier(params.get("turnId")),
                item_id=_identifier(params.get("itemId") or params.get("callId")),
            )
            policy_decisions = assessment["policy_decisions"]
            if self.security_mode != "enforce":
                policy_decisions = [
                    {
                        **d,
                        "blocking": False,
                        "result": "detected" if d["mode"] == "deny" else d["result"],
                    }
                    for d in policy_decisions
                ]
            risk.update(assessment["risk"])
            risk["matched_rules"] = assessment["matched_rules"]
            risk["policy_decisions"] = policy_decisions
            risk["blocking_rule"] = next(
                (d["policy_id"] for d in policy_decisions if d["blocking"]), None
            )
            if (
                business is not None
                and business.get("decision") == "decline"
                and not risk["blocking_rule"]
            ):
                business = {
                    **business,
                    "decision": "review",
                    "headline": "订单可能超出授权，等待执行前确认",
                    "blocking_rule": None,
                }
                risk["business_decision"] = "review"

        purpose, purpose_source = self._purpose()
        if command:
            explanation = explain_command(
                command,
                cwd=str(params.get("cwd") or "") or None,
                purpose=purpose,
                purpose_source=purpose_source,
                status="pending",
                policy_risk=risk,
            )
            if business is not None:
                explanation = _business_explanation(explanation, risk, business)
        else:
            explanation = explain_file_change(
                safe_changes,
                status="pending",
                purpose=purpose,
            )
            explanation["risk"] = risk
        evidence = empty_evidence(
            turn_id=_identifier(params.get("turnId")),
            item_id=_identifier(params.get("itemId") or params.get("callId")),
            reason="操作尚未执行，暂无 OS 级证据",
        )

        if self.security_mode == "enforce" and command:
            interception = intercept_dangerous_command_approval(
                {
                    "direction": "server_to_client",
                    "message": {"id": rpc_id, "method": method, "params": params},
                },
                workspace=self.repo,
                runtime_session=self._runtime_policies,
                assessment=assessment if isinstance(assessment, Mapping) else None,
            )
            if interception is not None:
                interaction_id = self._interaction_id()
                blocked_decisions = interception.metadata.get("policy_decisions")
                self._record_policy_decisions(
                    merge_policy_decisions(
                        policy_decisions,
                        (
                            [
                                dict(value)
                                for value in blocked_decisions
                                if isinstance(value, Mapping)
                            ]
                            if isinstance(blocked_decisions, list)
                            else []
                        ),
                    ),
                    subject_kind="command",
                    subject_summary=command,
                    thread_id=_identifier(
                        params.get("threadId") or params.get("conversationId")
                    ),
                    turn_id=_identifier(params.get("turnId")),
                    item_id=_identifier(params.get("itemId") or params.get("callId")),
                    step=self._event_step(),
                )
                self._record_policy_block(
                    interaction_id=interaction_id,
                    method=method,
                    params=params,
                    metadata=interception.metadata,
                )
                return interception.response.get("result", {"decision": "decline"})

        self._record_policy_decisions(
            policy_decisions,
            subject_kind="command" if command else "file_change",
            subject_summary=command or str(params.get("reason") or method),
            thread_id=_identifier(params.get("threadId") or params.get("conversationId")),
            turn_id=_identifier(params.get("turnId")),
            item_id=_identifier(params.get("itemId") or params.get("callId")),
            step=self._event_step(),
        )

        interaction_id = self._interaction_id()
        if business is not None and business.get("decision") == "review":
            business_rules = business.get("matched_rules")
            business_rules = business_rules if isinstance(business_rules, list) else []
            contract = action_result(
                action_id=_identifier(params.get("itemId") or params.get("callId"))
                or interaction_id,
                status="review_required",
                summary=str(business.get("summary") or "消费动作需要逐次确认。"),
                policy_ids=map(str, business_rules),
                business_impact=(
                    business.get("business_impact")
                    if isinstance(business.get("business_impact"), Mapping)
                    else {}
                ),
                safe_next_step=str(
                    business.get("recommendation")
                    or "先核对业务状态，再决定是否允许一次。"
                ),
                request_hash_value=action_request_hash(
                    {
                        "command": command,
                        "cwd": str(params.get("cwd") or ""),
                        "item_id": params.get("itemId") or params.get("callId"),
                    }
                ),
            )
            risk["action_result"] = contract
            explanation["action_result"] = contract
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        interaction = PendingInteraction(
            interaction_id=interaction_id,
            rpc_id=rpc_id,
            method=method,
            kind="approval",
            params=params,
            future=future,
            created_at=time.time(),
            risk=risk,
            explanation=explanation,
            evidence=evidence,
        )
        self._interactions[interaction_id] = interaction
        self.store.append(
            "approval_request",
            title="Agent 请求执行前批准",
            summary=command or str(params.get("reason") or method),
            payload=interaction.public(),
            explanation=explanation,
            evidence=evidence,
            source="codex_app_server",
            status="pending",
            thread_id=_identifier(params.get("threadId") or params.get("conversationId")),
            turn_id=_identifier(params.get("turnId")),
            item_id=_identifier(params.get("itemId") or params.get("callId")),
            step=self._event_step(),
        )
        try:
            return await future
        finally:
            self._interactions.pop(interaction_id, None)

    def _record_policy_block(
        self,
        *,
        interaction_id: str,
        method: str,
        params: Mapping[str, Any],
        metadata: Mapping[str, Any],
    ) -> None:
        command = _command_text(params.get("command"))
        policy_risk = metadata.get("risk")
        policy_risk = dict(policy_risk) if isinstance(policy_risk, Mapping) else {}
        for key in ("matched_rules", "blocking_rule", "policy_id"):
            if metadata.get(key) is not None:
                policy_risk[key] = metadata.get(key)
        if metadata.get("business_impact") is not None:
            policy_risk["business_impact"] = metadata.get("business_impact")
        if metadata.get("business_summary") is not None:
            policy_risk["business_summary"] = metadata.get("business_summary")
        purpose, purpose_source = self._purpose()
        explanation = explain_command(
            command,
            cwd=str(params.get("cwd") or "") or None,
            purpose=purpose,
            purpose_source=purpose_source,
            status="blocked",
            policy_risk=policy_risk,
        )
        explanation, outcome = _apply_policy_block_outcome(explanation, metadata)
        is_business = outcome["policy_id"] == "LIFE-ORDER-002"
        turn_id = _identifier(params.get("turnId"))
        item_id = _identifier(params.get("itemId") or params.get("callId"))
        policy_ids = metadata.get("matched_rules")
        policy_ids = policy_ids if isinstance(policy_ids, list) else []
        contract_impact = (
            dict(metadata.get("business_impact"))
            if isinstance(metadata.get("business_impact"), Mapping)
            else {}
        )
        contract_impact["executor_started"] = False
        action_contract = action_result(
            action_id=item_id or interaction_id,
            status="blocked",
            summary=str(outcome["result_summary"]),
            policy_ids=[*map(str, policy_ids), str(outcome["policy_id"])],
            business_impact=contract_impact,
            safe_next_step=str(outcome["next_step"]),
            request_hash_value=action_request_hash(
                {
                    "command": command,
                    "cwd": str(params.get("cwd") or ""),
                    "item_id": item_id,
                }
            ),
        )
        self.store.append(
            "policy_block",
            title=outcome["headline"],
            summary=(
                str(metadata.get("business_summary") or command or method)
                if is_business
                else command or method
            ),
            payload={
                "interaction_id": interaction_id,
                "command": command,
                "cwd": params.get("cwd"),
                "hard_block": True,
                "action_result": action_contract,
                "policy": dict(metadata),
            },
            explanation=explanation,
            evidence=policy_block_evidence(
                turn_id=turn_id,
                item_id=item_id,
                policy=metadata,
            ),
            source="codexscope_policy",
            status="blocked",
            thread_id=_identifier(params.get("threadId") or params.get("conversationId")),
            turn_id=turn_id,
            item_id=item_id,
            step=self._event_step(),
        )

    async def _user_input_request(
        self, rpc_id: int | str, method: str, params: dict[str, Any]
    ) -> Any:
        interaction_id = self._interaction_id()
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        interaction = PendingInteraction(
            interaction_id=interaction_id,
            rpc_id=rpc_id,
            method=method,
            kind="user_input",
            params=params,
            future=future,
            created_at=time.time(),
            risk={"level": "normal", "reasons": []},
            explanation={
                "schema_version": "lingmou.activity-explanation.v1",
                "headline": "Agent 需要补充信息",
                "action": "request_user_input",
                "description": "Agent 暂停当前步骤并等待你的回答。",
                "purpose": {
                    "text": "补齐继续执行所需的信息",
                    "source": "codex_app_server",
                    "confidence": "declared",
                },
                "effects": {"reads": [], "writes": [], "network": [], "processes": []},
                "risk": {"level": "low", "reasons": [], "basis": "interaction_type"},
                "sources": ["codex_app_server"],
                "conservative_fallback": False,
            },
            evidence=empty_evidence(
                turn_id=_identifier(params.get("turnId")),
                item_id=_identifier(params.get("itemId")),
                reason="该交互不执行系统操作",
            ),
        )
        self._interactions[interaction_id] = interaction
        self.store.append(
            "user_input_request",
            title="Agent 需要你的补充",
            summary=f"{len(params.get('questions') or [])} 个问题",
            payload=interaction.public(),
            explanation=interaction.explanation,
            evidence=interaction.evidence,
            source="codex_app_server",
            status="pending",
            thread_id=_identifier(params.get("threadId")),
            turn_id=_identifier(params.get("turnId")),
            item_id=_identifier(params.get("itemId")),
            step=self._event_step(),
        )
        try:
            return await future
        finally:
            self._interactions.pop(interaction_id, None)

    async def _handle_notification(self, method: str, params: Mapping[str, Any]) -> None:
        if method == 'thread/tokenUsage/updated':
            from .live_status import normalize_token_usage
            usage = normalize_token_usage(params.get('tokenUsage'))
            if usage is not None:
                try:
                    atomic_json_dump(self.run_dir / 'workbench_token_usage.json', usage)
                except OSError:
                    pass  # Optional metering cannot break the Agent notification loop.
            return
        thread_id = _identifier(params.get("threadId")) or self.thread_id
        turn_id = _identifier(params.get("turnId"))
        if method == "thread/started":
            thread = params.get("thread")
            thread = thread if isinstance(thread, Mapping) else {}
            value = _identifier(thread.get("id"))
            if value:
                self.thread_id = value
                self.store.set_state("thread_id", value)
            return
        if method == "turn/started":
            turn = params.get("turn")
            turn = turn if isinstance(turn, Mapping) else {}
            turn_id = _identifier(turn.get("id")) or turn_id
            self.active_turn_id = turn_id
            self.turn_status = "running"
            if self._plan_steps and self._plan_steps[0].get("source") == "workbench_fallback":
                self._plan_steps[0]["id"] = f"{turn_id or 'task'}:understand"
            self.store.append(
                "turn",
                title="Agent 开始处理",
                summary=turn_id or "新回合",
                status="running",
                thread_id=thread_id,
                turn_id=turn_id,
                step=self._event_step(),
            )
            return
        if method == "turn/completed":
            turn = params.get("turn")
            turn = turn if isinstance(turn, Mapping) else {}
            turn_id = _identifier(turn.get("id")) or turn_id
            completed_status = _status(turn.get("status"), "completed")
            await self._drain_workbuddy_outbox_once()
            self.turn_status = completed_status
            if completed_status == "completed":
                for step in self._plan_steps:
                    if step.get("status") in {"running", "in_progress"}:
                        step["status"] = "completed"
            if turn_id == self.active_turn_id or self.active_turn_id is None:
                self.active_turn_id = None
            self.store.append(
                "turn",
                title="Agent 已结束本回合",
                summary=str(turn.get("error") or completed_status),
                payload={"turn": dict(turn)},
                status=completed_status,
                thread_id=thread_id,
                turn_id=turn_id,
                step=self._event_step(),
            )
            if (
                self.workbuddy_runtime is not None
                and turn_id is not None
                and turn_id not in self._workbuddy_summarized_turns
            ):
                self._workbuddy_summarized_turns.add(turn_id)
                summary = await asyncio.to_thread(
                    self.workbuddy_runtime.scenario_result_summary
                )
                self.store.append(
                    "scenario_summary",
                    event_id=f"workbuddy-summary:{turn_id}",
                    title="本次业务结果",
                    summary=summary,
                    payload={
                        "scenario_id": self.workbuddy_runtime.scenario_id,
                        "summary": summary,
                    },
                    source="lingmou_workbuddy",
                    status=(
                        "completed"
                        if completed_status == "completed"
                        else completed_status
                    ),
                    thread_id=thread_id,
                    turn_id=turn_id,
                )
            self._active_command = None
            return
        if method in {"item/started", "item/completed"}:
            item = params.get("item")
            if isinstance(item, Mapping):
                self._record_item(
                    item,
                    lifecycle="started" if method.endswith("started") else "completed",
                    thread_id=thread_id,
                    turn_id=turn_id,
                    occurred_at=(
                        float(params.get("startedAtMs")) / 1000
                        if isinstance(params.get("startedAtMs"), (int, float))
                        else float(params.get("completedAtMs")) / 1000
                        if isinstance(params.get("completedAtMs"), (int, float))
                        else time.time()
                    ),
                )
            return
        delta_kinds = {
            "item/agentMessage/delta": ("agent_delta", "Agent 正在回复"),
            "item/plan/delta": ("plan_delta", "Agent 正在规划"),
            "item/commandExecution/outputDelta": ("command_output", "命令正在输出"),
        }
        if method in delta_kinds:
            kind, title = delta_kinds[method]
            delta = str(params.get("delta") or "")
            if delta:
                self.store.append(
                    kind,
                    title=title,
                    summary=delta[:16_384],
                    payload={"delta": delta[:16_384]},
                    status="streaming",
                    thread_id=thread_id,
                    turn_id=turn_id,
                    item_id=_identifier(params.get("itemId")),
                    step=self._event_step(),
                )
            return
        if method == "turn/plan/updated":
            plan = params.get("plan") if isinstance(params.get("plan"), list) else []
            self._update_plan_steps(plan, turn_id=turn_id)
            self.store.append(
                "plan",
                title="计划已更新",
                summary=str(params.get("explanation") or "Agent 调整了执行计划"),
                payload={"plan": plan, "explanation": params.get("explanation")},
                status="updated",
                thread_id=thread_id,
                turn_id=turn_id,
                item_id=f"plan:{turn_id}" if turn_id else None,
                step=self._event_step(),
            )
            return
        if method == "turn/diff/updated":
            diff = str(params.get("diff") or "")
            paths = [
                {"path": match, "kind": "modify"}
                for match in re.findall(r"^\+\+\+\s+b/(.+)$", diff, re.MULTILINE)
            ]
            purpose, _purpose_source = self._purpose()
            self.store.append(
                "diff",
                title="工作区修改预览",
                summary=diff[:2_000],
                payload={"diff": diff[:128_000]},
                explanation=explain_file_change(
                    paths,
                    status="updated",
                    purpose=purpose,
                ),
                evidence=empty_evidence(
                    turn_id=turn_id,
                    item_id=f"diff:{turn_id}" if turn_id else None,
                    reason="该 diff 来自 app-server；OS 证据请在关联命令中查看",
                ),
                status="updated",
                thread_id=thread_id,
                turn_id=turn_id,
                item_id=f"diff:{turn_id}" if turn_id else None,
                step=self._event_step(),
            )
            return
        if method in {"error", "warning"}:
            self.store.append(
                "error" if method == "error" else "warning",
                title="Agent 运行异常" if method == "error" else "Agent 运行警告",
                summary=str(params.get("message") or params.get("error") or params),
                payload=dict(params),
                status="failed" if method == "error" else "warning",
                thread_id=thread_id,
                turn_id=turn_id,
                step=self._event_step(),
            )

    def _record_item(
        self,
        item: Mapping[str, Any],
        *,
        lifecycle: str,
        thread_id: str | None,
        turn_id: str | None,
        occurred_at: float,
    ) -> None:
        item_type = str(item.get("type") or "tool")
        item_id = _identifier(item.get("id"))
        if item_type == "userMessage":
            return
        status = _status(item.get("status"), lifecycle)
        if item_id and lifecycle == "started":
            purpose, _purpose_source = self._purpose()
            self._item_context[item_id] = (purpose, self._event_step())
            self._item_started_at[item_id] = occurred_at
        context = self._item_context.get(item_id or "")
        if context is None:
            purpose = self._purpose()[0]
            step = self._event_step()
        else:
            purpose, step = context
        purpose_source = "agent_plan" if purpose else "contextual_inference"
        titles = {
            "agentMessage": "Agent 回复",
            "plan": "Agent 计划",
            "reasoning": "Agent 公开推理摘要",
            "commandExecution": "执行命令",
            "fileChange": "修改文件",
            "mcpToolCall": "调用 MCP 工具",
            "dynamicToolCall": "调用工具",
            "collabAgentToolCall": "协作 Agent 调用",
            "subAgentActivity": "子 Agent 活动",
            "webSearch": "搜索网络",
            "imageView": "查看图片",
            "imageGeneration": "生成图片",
            "contextCompaction": "压缩会话上下文",
        }
        kinds = {
            "agentMessage": "agent_message",
            "plan": "plan",
            "reasoning": "reasoning_summary",
            "commandExecution": "command",
            "fileChange": "file_change",
            "mcpToolCall": "tool",
            "dynamicToolCall": "tool",
            "collabAgentToolCall": "agent_tool",
            "subAgentActivity": "agent_tool",
            "webSearch": "web_search",
            "imageView": "tool",
            "imageGeneration": "tool",
            "contextCompaction": "system",
        }
        explanation: dict[str, Any] = {}
        evidence = empty_evidence(
            turn_id=turn_id,
            item_id=item_id,
            reason="该活动暂无 OS 级证据",
        )
        policy_decisions: list[dict[str, Any]] = []
        if item_type == "reasoning":
            summary_value = item.get("summary") or []
            if isinstance(summary_value, list):
                summary = "\n".join(str(value) for value in summary_value)
            else:
                summary = str(summary_value or "")
            payload: dict[str, Any] = {"summary": summary_value}
        elif item_type in {"agentMessage", "plan"}:
            summary = str(item.get("text") or "")
            payload = {"text": summary, "phase": item.get("phase")}
        elif item_type == "commandExecution":
            summary = str(item.get("command") or "")
            payload = dict(item)
            assessment = classify_live_command(
                summary,
                status=status,
                cwd=str(item.get("cwd") or "") or None,
            )
            assessment_risk = assessment.get("risk")
            assessment_risk = (
                dict(assessment_risk) if isinstance(assessment_risk, Mapping) else {}
            )
            matched_rules = [
                str(value)
                for value in assessment.get("matched_rules", [])
                if str(value).strip()
            ]
            assessment_risk["matched_rules"] = matched_rules
            if lifecycle == "completed":
                runtime_decisions = self._runtime_policies.assess_command(
                    summary,
                    cwd=str(item.get("cwd") or "") or None,
                    principal=item,
                )
                policy_decisions = merge_policy_decisions(
                    assessment.get("policy_decisions", []),
                    runtime_decisions,
                    decisions_from_rule_ids(
                        matched_rules,
                        reasons=(
                            [str(value) for value in assessment_risk.get("reasons", [])]
                            if isinstance(assessment_risk.get("reasons"), list)
                            else []
                        ),
                        stage="command_lifecycle",
                    ),
                )
            result = {
                "status": status,
                "exit_code": item.get("exitCode", item.get("exit_code")),
                "duration_ms": item.get("durationMs", item.get("duration_ms")),
                "output": item.get("aggregatedOutput", item.get("output")),
            }
            explanation = explain_command(
                summary,
                cwd=str(item.get("cwd") or "") or None,
                purpose=purpose,
                purpose_source=purpose_source,
                status=status,
                result=result,
                policy_risk=assessment_risk,
            )
            titles[item_type] = str(explanation["headline"])
            process_id = item.get("processId", item.get("process_id"))
            if lifecycle == "started":
                self._active_command = {
                    "item_id": item_id,
                    "headline": explanation["headline"],
                    "command": redact_text(summary),
                    "started_at": occurred_at,
                }
                evidence = empty_evidence(
                    turn_id=turn_id,
                    item_id=item_id,
                    reason="命令正在运行，OS 证据将在命令结束后聚合",
                )
            else:
                self._runtime_policies.observe_command(
                    summary,
                    cwd=str(item.get("cwd") or "") or None,
                    status=status,
                    exit_code=(
                        int(item.get("exitCode"))
                        if isinstance(item.get("exitCode"), int)
                        else None
                    ),
                    observed_at=occurred_at,
                    turn_id=turn_id,
                    item_id=item_id,
                )
                started_at = self._item_started_at.pop(item_id or "", None)
                duration_ms = item.get("durationMs", item.get("duration_ms"))
                if started_at is None and isinstance(duration_ms, (int, float)):
                    started_at = occurred_at - float(duration_ms) / 1000
                evidence = collect_command_evidence(
                    self.run_dir,
                    turn_id=turn_id,
                    item_id=item_id,
                    process_id=process_id,
                    started_at=started_at,
                    ended_at=occurred_at,
                    exit_code=(
                        int(item.get("exitCode"))
                        if isinstance(item.get("exitCode"), int)
                        else None
                    ),
                )
                if item_id and process_id is not None:
                    self._pending_command_evidence[item_id] = {
                        "thread_id": thread_id,
                        "turn_id": turn_id,
                        "item_id": item_id,
                        "process_id": process_id,
                        "started_at": started_at,
                        "ended_at": occurred_at,
                        "exit_code": (
                            int(item.get("exitCode"))
                            if isinstance(item.get("exitCode"), int)
                            else None
                        ),
                        "step": step,
                        "retry_after": time.time() + 0.35,
                        "deadline": time.time() + 4.0,
                    }
                if self._active_command and self._active_command.get("item_id") == item_id:
                    self._active_command = None
        elif item_type == "fileChange":
            changes = item.get("changes") if isinstance(item.get("changes"), list) else []
            paths = [str(change.get("path")) for change in changes if isinstance(change, Mapping)]
            summary = "、".join(paths) or "文件变更"
            payload = dict(item)
            safe_changes = [change for change in changes if isinstance(change, Mapping)]
            if lifecycle == "completed":
                policy_decisions = assess_file_change_policies(safe_changes)
            explanation = explain_file_change(
                safe_changes,
                status=status,
                purpose=purpose,
            )
            titles[item_type] = str(explanation["headline"])
            evidence = {
                **evidence,
                "availability": "available",
                "completeness": "partial",
                "summary": "文件变更由 Codex app-server 报告",
                "observations": [
                    {
                        "kind": "file_change",
                        "label": f"{change.get('kind') or '修改'} {change.get('path')}",
                        "source": "codex_app_server",
                        "turn_id": turn_id,
                        "item_id": item_id,
                        "file_path": change.get("path"),
                        "correlation_confidence": "exact_item",
                    }
                    for change in safe_changes
                ],
            }
        elif item_type == "mcpToolCall":
            summary = f"{item.get('server') or 'MCP'} / {item.get('tool') or 'tool'}"
            payload = dict(item)
        elif item_type in {"dynamicToolCall", "collabAgentToolCall"}:
            summary = str(item.get("tool") or item_type)
            payload = dict(item)
        elif item_type == "webSearch":
            summary = str(item.get("query") or "")
            payload = dict(item)
        else:
            summary = str(item.get("path") or item.get("kind") or item_type)
            payload = dict(item)
        if item_type in {
            "mcpToolCall",
            "dynamicToolCall",
            "collabAgentToolCall",
            "subAgentActivity",
        }:
            policy_decisions = merge_policy_decisions(
                policy_decisions,
                self._runtime_policies.assess_tool_item(item, lifecycle=lifecycle),
            )
        if item_type in {
            "mcpToolCall",
            "dynamicToolCall",
            "collabAgentToolCall",
            "subAgentActivity",
            "webSearch",
            "imageView",
            "imageGeneration",
        }:
            explanation = explain_tool(
                item,
                item_type=item_type,
                status=status,
                purpose=purpose,
            )
            titles[item_type] = str(explanation["headline"])
            evidence = {
                **evidence,
                "availability": "available",
                "completeness": "partial",
                "summary": "工具调用与返回状态来自 Codex app-server",
                "observations": [
                    {
                        "kind": "tool_lifecycle",
                        "label": f"工具状态：{status}",
                        "source": "codex_app_server",
                        "turn_id": turn_id,
                        "item_id": item_id,
                        "correlation_confidence": "exact_item",
                    }
                ],
            }
        self.store.append(
            kinds.get(item_type, "tool"),
            title=titles.get(item_type, f"Agent 活动 · {item_type}"),
            summary=summary,
            payload={"lifecycle": lifecycle, "item": payload},
            explanation=explanation,
            evidence=evidence,
            status=status,
            thread_id=thread_id,
            turn_id=turn_id,
            item_id=item_id,
            occurred_at=occurred_at,
            step=step,
        )
        self._record_policy_decisions(
            policy_decisions,
            subject_kind=item_type,
            subject_summary=summary,
            thread_id=thread_id,
            turn_id=turn_id,
            item_id=item_id,
            occurred_at=occurred_at,
            step=step,
        )
        if lifecycle == "completed" and item_id:
            self._item_context.pop(item_id, None)

    async def _security_watch_loop(self) -> None:
        status_path = self.run_dir / "live_status.json"
        while not self._closing:
            try:
                if self._filesystem_guard.get("status") == "active":
                    rows, self._filesystem_audit_offset = await asyncio.to_thread(
                        read_denials, self.run_dir, self.repo,
                        self._filesystem_guard.get("denied_paths", []),
                        self._filesystem_audit_offset,
                    )
                    for row in rows:
                        self._record_policy_decisions(
                            [{"policy_id": "USER-FILESYSTEM-DENY", "policy_name": "用户禁止访问目录",
                              "mode": "deny", "blocking": True, "result": "blocked", "level": "high",
                              "stage": "kernel_filesystem", "evidence_source": "linux_strace",
                              "reason": f"{row['syscall']}({row['path']}) → {row['errno']}",
                              "evidence": row}],
                            subject_kind="filesystem_access", subject_summary=str(row["path"]),
                            item_id=f"os-audit:{row['seq']}",
                            occurred_at=row["wall_time_ns"] / 1_000_000_000,
                        )
                if status_path.exists():
                    payload = await asyncio.to_thread(
                        self._load_security_payload, status_path
                    )
                    if payload:
                        summary = payload.get("summary")
                        enforcement = payload.get("enforcement")
                        revision = (
                            payload.get("updated_at"),
                            tuple(sorted(summary.items()))
                            if isinstance(summary, Mapping)
                            else None,
                            tuple(sorted(enforcement.items()))
                            if isinstance(enforcement, Mapping)
                            else None,
                        )
                        if revision != self._last_security_revision:
                            self.store.set_state("live_security", payload)
                            self._last_security_revision = revision
                        for event in payload.get("events", []):
                            if not isinstance(event, Mapping):
                                continue
                            event_kind = str(event.get("kind") or "runtime_event")
                            event_timestamp = (
                                float(event.get("timestamp"))
                                if isinstance(event.get("timestamp"), (int, float))
                                else None
                            )
                            if event_kind in {"syscall", "file", "network"} and (
                                self._monitor_policy_not_before is None
                                or event_timestamp is None
                                or event_timestamp <= self._monitor_policy_not_before
                            ):
                                # App-server startup legitimately performs cache,
                                # configuration and process-tree syscalls before a
                                # user submits the first task.  Keep those rows in
                                # the syscall baseline, but do not manufacture
                                # policy decisions or investigation anchors for a
                                # task that does not exist yet.
                                continue
                            technical = event.get("technical")
                            technical = technical if isinstance(technical, Mapping) else {}
                            gateway_traces = technical.get("policy_traces")
                            gateway_item = _identifier(technical.get("item_id"))
                            trace_event_id = f"policy-evaluation:{gateway_item or event.get('id')}"
                            if isinstance(gateway_traces, list) and gateway_traces and not self.store.contains_event_id(trace_event_id):
                                self.store.append(
                                    "policy_evaluation", event_id=trace_event_id,
                                    title="网关执行前条件判断", summary="原始拦截判断，未重新调用模型",
                                    payload={"traces": gateway_traces, "command": event.get("detail")},
                                    source="atomic_policy", status="observed", item_id=gateway_item,
                                    occurred_at=event_timestamp,
                                )
                            raw_policy_decisions = technical.get("policy_decisions")
                            selected_decisions = strongest_policy_decisions(
                                [
                                    dict(value)
                                    for value in raw_policy_decisions
                                    if isinstance(value, Mapping)
                                ]
                                if isinstance(raw_policy_decisions, list)
                                else []
                            )
                            decision_by_id = {
                                str(value.get("policy_id")): dict(value)
                                for value in selected_decisions
                                if value.get("policy_id")
                            }
                            policy_hits = event.get("policy_hits")
                            event_decisions: list[dict[str, Any]] = list(
                                decision_by_id.values()
                            )
                            if isinstance(policy_hits, list):
                                for hit in policy_hits:
                                    if not isinstance(hit, Mapping):
                                        continue
                                    policy_id = str(hit.get("id") or "").strip()
                                    if not policy_id:
                                        continue
                                    existing = decision_by_id.get(policy_id)
                                    is_actual_blocker = bool(
                                        event.get("blocked")
                                        and technical.get("blocking_rule") == policy_id
                                    )
                                    if existing is not None and (
                                        not is_actual_blocker
                                        or bool(existing.get("blocking"))
                                        or existing.get("result") == "blocked"
                                    ):
                                        continue
                                    risk = event.get("risk")
                                    risk = risk if isinstance(risk, Mapping) else {}
                                    reasons = risk.get("reasons")
                                    reasons = reasons if isinstance(reasons, list) else []
                                    event_decisions.extend(
                                        decisions_from_rule_ids(
                                            [policy_id],
                                            reasons=[str(value) for value in reasons],
                                            blocking_rule=(
                                                policy_id
                                                if is_actual_blocker
                                                else None
                                            ),
                                            stage=str(
                                                technical.get("enforcement_stage")
                                                or (
                                                    "post_execution_observation"
                                                    if event.get("kind") in {"syscall", "file"}
                                                    else "runtime_observation"
                                                )
                                            ),
                                            result=str(
                                                hit.get("result")
                                                or ("blocked" if event.get("blocked") else "observed")
                                            ),
                                        )
                                    )
                            event_decisions = strongest_policy_decisions(event_decisions)
                            source_id = str(event.get("id") or "unknown")
                            monitor_item_id = _identifier(technical.get("item_id"))
                            self._record_policy_decisions(
                                event_decisions,
                                subject_kind=event_kind,
                                subject_summary=str(event.get("detail") or event.get("action") or "策略事件"),
                                thread_id=_identifier(payload.get("thread_id")),
                                turn_id=_identifier(payload.get("turn_id")),
                                item_id=monitor_item_id or f"monitor:{source_id}",
                                occurred_at=event_timestamp,
                                step=self._event_step(),
                            )
                            if not event.get("blocked"):
                                continue
                            if technical.get("decision_source") != "codexscope_policy":
                                continue
                            event_id = f"monitor-policy-block:{source_id}"
                            if event_id in self._policy_seen or self.store.contains_event_id(event_id):
                                self._policy_seen.add(event_id)
                                continue
                            if monitor_item_id and any(
                                row.get("kind") == "policy_block"
                                and row.get("item_id") == monitor_item_id
                                for row in self.store.events(
                                    after_seq=max(0, self.store.last_seq - 5_000),
                                    limit=5_000,
                                )
                            ):
                                self._policy_seen.add(event_id)
                                continue
                            self._policy_seen.add(event_id)
                            monitor_command = str(event.get("detail") or "")
                            policy_data = {
                                "policy_id": technical.get("policy_id"),
                                "blocking_rule": technical.get("blocking_rule"),
                                "matched_rules": technical.get("matched_rules") or [],
                                "risk": event.get("risk") or {},
                                "policy_name": technical.get("policy_name"),
                                "business_summary": technical.get("business_summary"),
                                "business_impact": technical.get("business_impact"),
                            }
                            monitor_turn_id = _identifier(payload.get("turn_id"))
                            monitor_explanation = explain_command(
                                monitor_command,
                                purpose=self._purpose()[0],
                                purpose_source=self._purpose()[1],
                                status="blocked",
                                policy_risk={
                                    **(
                                        dict(event.get("risk"))
                                        if isinstance(event.get("risk"), Mapping)
                                        else {}
                                    ),
                                    **policy_data,
                                },
                            )
                            monitor_explanation, outcome = _apply_policy_block_outcome(
                                monitor_explanation,
                                policy_data,
                            )
                            is_business = outcome["policy_id"] == "LIFE-ORDER-002"
                            monitor_impact = (
                                dict(technical.get("business_impact"))
                                if isinstance(technical.get("business_impact"), Mapping)
                                else {}
                            )
                            monitor_impact["executor_started"] = False
                            monitor_action_result = action_result(
                                action_id=monitor_item_id or f"monitor:{source_id}",
                                status="blocked",
                                summary=str(outcome["result_summary"]),
                                policy_ids=[
                                    *map(str, technical.get("matched_rules") or []),
                                    str(outcome["policy_id"]),
                                ],
                                business_impact=monitor_impact,
                                safe_next_step=str(outcome["next_step"]),
                                request_hash_value=action_request_hash(
                                    {
                                        "command": monitor_command,
                                        "item_id": monitor_item_id,
                                        "source_event_id": source_id,
                                    }
                                ),
                            )
                            self.store.append(
                                "policy_block",
                                event_id=event_id,
                                title=outcome["headline"],
                                summary=str(
                                    (
                                        technical.get("business_summary")
                                        or event.get("detail")
                                        or "重复下单"
                                    )
                                    if is_business
                                    else event.get("detail") or "高风险命令"
                                ),
                                payload={
                                    "hard_block": True,
                                    "business_impact": technical.get("business_impact"),
                                    "action_result": monitor_action_result,
                                    "security_event": dict(event),
                                },
                                explanation=monitor_explanation,
                                evidence=policy_block_evidence(
                                    turn_id=monitor_turn_id,
                                    item_id=monitor_item_id,
                                    policy=policy_data,
                                ),
                                source="codexscope_policy",
                                status="blocked",
                                thread_id=_identifier(payload.get("thread_id")),
                                turn_id=monitor_turn_id,
                                item_id=monitor_item_id,
                                step=self._event_step(),
                            )
                await self._refresh_pending_command_evidence()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(0.25)

    async def _refresh_pending_command_evidence(self) -> None:
        now = time.time()
        for item_id, context in tuple(self._pending_command_evidence.items()):
            if now < float(context.get("retry_after") or 0.0):
                continue
            evidence = await asyncio.to_thread(
                collect_command_evidence,
                self.run_dir,
                turn_id=_identifier(context.get("turn_id")),
                item_id=item_id,
                process_id=context.get("process_id"),
                started_at=context.get("started_at"),
                ended_at=context.get("ended_at"),
                exit_code=context.get("exit_code"),
            )
            if evidence.get("availability") == "available":
                self.store.append(
                    "command_evidence",
                    title="命令的系统证据已聚合",
                    summary=str(evidence.get("summary") or "OS 证据已更新"),
                    payload={"evidence_update": True},
                    evidence=evidence,
                    source="os_observation",
                    status="completed",
                    thread_id=_identifier(context.get("thread_id")) or self.thread_id,
                    turn_id=_identifier(context.get("turn_id")),
                    item_id=item_id,
                    step=(
                        context.get("step")
                        if isinstance(context.get("step"), Mapping)
                        else self._event_step()
                    ),
                )
                self._pending_command_evidence.pop(item_id, None)
            elif now >= float(context.get("deadline") or 0.0):
                self._pending_command_evidence.pop(item_id, None)
            else:
                context["retry_after"] = now + 0.25

    def _load_security_payload(self, status_path: Path) -> dict[str, Any]:
        try:
            status = json_load(status_path)
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(status, Mapping):
            return {}
        return build_live_security_payload(status, run_dir=self.run_dir)


__all__ = [
    "PendingInteraction",
    "WorkbenchController",
    "WorkbenchError",
    "WorkbenchRpcError",
]
