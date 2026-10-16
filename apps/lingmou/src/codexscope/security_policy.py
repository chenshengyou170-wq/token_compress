"""Pre-execution command approval policy for interactive Codex monitoring."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .atomic_policy import PolicyConfigError, evaluate, load_document
from .business_policy import assess_business_command
from .gateway import GatewayInterception
from .live_security import classify_live_command
from .payment_security import PAYMENT_POLICY_ID, assess_payment_command
from .policy_facts import command_facts
from .runtime_policy import (
    RuntimePolicySession,
    _egress_hosts,
    merge_policy_decisions,
)

RUNTIME_POLICY_ID = "lingmou.runtime-enforcement.v1"
POLICY_ID = RUNTIME_POLICY_ID
ENFORCEMENT_STAGE = "pre_execution_approval"
_COMMAND_APPROVAL_DECISIONS = {
    "item/commandExecution/requestApproval": "decline",
    "execCommandApproval": "denied",
}


def _command_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list) and all(isinstance(part, str) for part in value):
        return shlex.join(value)
    return ""


def intercept_dangerous_command_approval(
    envelope: Mapping[str, Any],
    *,
    workspace: Path | str | None = None,
    runtime_session: RuntimePolicySession | None = None,
    assessment: Mapping[str, Any] | None = None,
) -> GatewayInterception | None:
    """Decline configured high-impact commands at the approval gate."""

    if envelope.get("direction") != "server_to_client":
        return None
    message = envelope.get("message")
    if not isinstance(message, Mapping):
        return None
    method = message.get("method")
    if method not in _COMMAND_APPROVAL_DECISIONS:
        return None
    request_id = message.get("id")
    if request_id is None:
        return None
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    command = _command_text(params.get("command"))
    if not command:
        return None
    evaluated = (
        dict(assessment)
        if assessment is not None and "policy_revision" in assessment
        else assess_approval_policies(
            command,
            workspace=workspace,
            cwd=params.get("cwd"),
            runtime_session=runtime_session,
            assessment=assessment,
            principal=params,
        )
    )
    decisions = evaluated["policy_decisions"]
    blocker = next((d for d in decisions if d["blocking"]), None)
    if blocker is None:
        return None
    blocking_rule = blocker["policy_id"]
    business = evaluated.get("business")
    payment_block = blocking_rule == "PAY-EXFIL-004"
    business_block = blocking_rule == "LIFE-ORDER-002" and business is not None
    response_decision = _COMMAND_APPROVAL_DECISIONS[str(method)]
    reasons = list(evaluated["risk"].get("reasons", []))
    matched_rules = [d["policy_id"] for d in decisions]
    if payment_block:
        # Preserve the stable payment evidence contract for existing consumers.
        reasons = [
            "PAY-KEY-001：命令引用支付密钥资产",
            "PAY-EGRESS-003：命令包含外部文件上传通道",
            "PAY-EXFIL-004：支付密钥可能离开工作区",
        ]
        matched_rules = [
            r
            for r in ("PAY-KEY-001", "PAY-EGRESS-003", "PAY-EXFIL-004")
            if r in matched_rules
        ] + [r for r in matched_rules if not r.startswith(("PAY-", "LING-"))]
    metadata = {
        "policy_id": business["policy_id"]
        if business_block
        else PAYMENT_POLICY_ID
        if payment_block
        else RUNTIME_POLICY_ID,
        "mode": "enforce",
        "action": "decline",
        "decision": response_decision,
        "stage": ENFORCEMENT_STAGE,
        "risk": {"level": blocker["level"], "reasons": reasons},
        "matched_rules": matched_rules,
        "blocking_rule": blocking_rule,
        "policy_decisions": decisions,
        "policy_revision": evaluated["policy_revision"],
        "policy_traces": evaluated.get("policy_traces", []),
        "asset": "consumer_order"
        if business_block
        else "payment_secret"
        if payment_block
        else "generic_command",
        "channel": "takeaway_order"
        if business_block
        else "external_upload"
        if payment_block
        else "command",
    }
    if business_block:
        metadata.update(
            policy_name=business["policy_name"],
            business_summary=business["summary"],
            business_impact=business["business_impact"],
        )
    return GatewayInterception(
        response={"id": request_id, "result": {"decision": response_decision}},
        metadata=metadata,
    )


def assess_approval_policies(
    command: str,
    *,
    workspace: Path | str | None = None,
    cwd: Any = None,
    runtime_session: RuntimePolicySession | None = None,
    assessment: Mapping[str, Any] | None = None,
    principal: Mapping[str, Any] | None = None,
    document: Mapping[str, Any] | None = None,
    config_snapshot: tuple[Mapping[str, Any], str] | None = None,
) -> dict[str, Any]:
    """Collect detector facts, then apply the configured rules (also used by preview)."""
    raw = (
        dict(assessment)
        if isinstance(assessment, Mapping)
        else classify_live_command(
            command, status="pending", cwd=str(cwd) if cwd else None
        )
    )
    payment = assess_payment_command(command)
    business = (
        assess_business_command(command, workspace) if workspace is not None else None
    )
    session = runtime_session or RuntimePolicySession(workspace or cwd or Path.cwd())
    detected = merge_policy_decisions(
        raw.get("policy_decisions", []),
        session.assess_command(command, cwd=cwd, principal=principal),
    )
    ids = list(
        dict.fromkeys(
            [
                *raw.get("matched_rules", []),
                *payment.get("matched_rules", []),
                *(business.get("matched_rules", []) if business else []),
                *[d["policy_id"] for d in detected],
            ]
        )
    )
    extracted = command_facts(command, workspace=workspace or cwd or Path.cwd(), cwd=cwd)
    facts = {
        **{key: value for key, value in extracted.items() if key != "parse_warnings"},
        "command": {
            **extracted["command"],
            "text": command,
            "cwd": str(cwd or workspace or ""),
            "hosts": _egress_hosts(command),
        },
        "detector": {
            "ids": ids,
            "blocking_ids": [business["blocking_rule"]]
            if business and business.get("blocking_rule")
            else [],
        },
        "action": {"family": "takeaway", "impact": business["business_impact"]}
        if business
        else {},
        "principal": {
            "role": str((principal or {}).get("role") or ""),
            "agent_id": str(
                (principal or {}).get("agentId")
                or (principal or {}).get("agent_id")
                or ""
            ),
        },
    }
    traces: list[dict[str, Any]] = []
    try:
        config, revision = (
            (document, "preview") if document is not None else config_snapshot if config_snapshot is not None else load_document(workspace)
        )
        decisions = evaluate(config, "command.approval", facts, revision=revision, traces=traces)
    except PolicyConfigError as exc:
        revision = "invalid"
        decisions = [
            {
                "schema_version": "lingmou.policy-decision.v1",
                "policy_id": "LING-POLICY-CONFIG-ERROR",
                "policy_name": "策略配置无效",
                "level": "high",
                "mode": "deny",
                "stage": ENFORCEMENT_STAGE,
                "action": "修复策略配置后重试",
                "result": "blocked",
                "blocking": True,
                "matched": True,
                "reason": str(exc),
                "evidence_source": "atomic_policy",
                "enforceable_now": True,
                "stateful": False,
                "tested": "local",
                "evidence": {"policy_revision": revision},
            }
        ]
    winner = next((d for d in decisions if d["blocking"]), None)
    for d in decisions:
        if d["blocking"] and d is not winner:
            d["blocking"] = False
            d["result"] = "detected"
    # Keep detector evidence while the effect is entirely selected by configuration.
    by_id = {d["policy_id"]: d for d in detected}
    for d in decisions:
        original = by_id.get(d["policy_id"])
        if original:
            d["evidence"] = {**original.get("evidence", {}), **d["evidence"]}
            d["stateful"] = original.get("stateful", False)
            d["reason"] = original.get("reason", d["reason"])
    risk = dict(raw.get("risk", {}))
    risk["reasons"] = list(
        dict.fromkeys([*risk.get("reasons", []), *[d["reason"] for d in decisions]])
    )
    risk["level"] = max(
        [d["level"] for d in decisions] or ["normal"],
        key=lambda v: {
            "normal": 0,
            "notice": 1,
            "warning": 2,
            "high": 3,
            "critical": 4,
        }.get(v, 0),
    )
    return {
        **raw,
        "risk": risk,
        "policy_decisions": decisions,
        "matched_rules": [d["policy_id"] for d in decisions],
        "policy_revision": revision,
        "business": business,
        "policy_facts": facts,
        "policy_traces": traces,
        "parse_warnings": extracted["parse_warnings"],
    }
