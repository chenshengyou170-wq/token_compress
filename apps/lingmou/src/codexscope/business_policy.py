"""Business-impact policies for relatable Lingmou experience workspaces.

The policy in this module is intentionally scoped to an explicitly configured
demo workspace.  It turns a shell-level approval (``python ... submit``) into
the business question a person actually cares about: how many orders and how
much money the action would create.
"""

from __future__ import annotations

import json
import os
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

BUSINESS_POLICY_ID = "lingmou.consumer-order.v1"
BUSINESS_EXPERIENCE_SCHEMA = "lingmou.business-experience.v1"
TAKEAWAY_PROFILE = "takeaway_duplicate_order_v1"
RETRY_RULE = "LIFE-RETRY-001"
DUPLICATE_RULE = "LIFE-ORDER-002"
SPEND_RULE = "LIFE-SPEND-003"

_SCENARIO_SCHEMA = "codexscope.demo-scenario.v1"
_STATE_SCHEMA = "lingmou.takeaway-demo.v2"
_MAX_JSON_BYTES = 1_000_000
_CHARGED_STATUSES = frozenset({"paid_simulated", "kept_paid_simulated"})


def _read_json(path: Path) -> Mapping[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


@lru_cache(maxsize=1)
def load_business_policy_catalog() -> dict[str, dict[str, Any]]:
    """Load the bundled, display-safe business policy definitions."""

    resource = Path(__file__).resolve().parent / "policies" / "lingmou_business_policies.json"
    try:
        value = json.loads(resource.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, Mapping) or value.get("schema_version") != "lingmou.business-policy-catalog.v1":
        return {}
    policies = value.get("policies")
    if not isinstance(policies, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for raw in policies:
        if not isinstance(raw, Mapping) or raw.get("enabled") is not True:
            continue
        policy_id = str(raw.get("id") or "").strip()
        if not policy_id:
            continue
        result[policy_id[:128]] = {
            "id": policy_id[:128],
            "name": str(raw.get("name") or policy_id)[:160],
            "condition": str(raw.get("condition") or "")[:240],
            "action": str(raw.get("action") or "")[:160],
        }
    return result


def _experience_config(workspace: Path | str) -> tuple[Path, Mapping[str, Any]] | None:
    try:
        root = Path(workspace).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    scenario = _read_json(root / "scenario.json")
    if not scenario or scenario.get("schema_version") != _SCENARIO_SCHEMA:
        return None
    experience = scenario.get("experience")
    if not isinstance(experience, Mapping):
        return None
    if (
        experience.get("schema_version") != BUSINESS_EXPERIENCE_SCHEMA
        or experience.get("kind") != "takeaway_duplicate_order"
        or experience.get("policy_profile") != TAKEAWAY_PROFILE
    ):
        return None
    return root, experience


def _state_path(root: Path, experience: Mapping[str, Any]) -> Path | None:
    relative = experience.get("state_path")
    if not isinstance(relative, str) or not relative.strip():
        return None
    candidate = Path(relative)
    if candidate.is_absolute():
        return None
    try:
        resolved = (root / candidate).resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved


def _money(value: object, fallback: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return round(fallback, 2)
    return round(max(0.0, float(value)), 2)


def _count(value: object, fallback: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return max(0, value)


def _safe_text(value: object, *, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _configured_state(
    workspace: Path | str,
) -> tuple[Path, Mapping[str, Any], Mapping[str, Any]] | None:
    configured = _experience_config(workspace)
    if configured is None:
        return None
    root, experience = configured
    state_path = _state_path(root, experience)
    if state_path is None:
        return None
    state = _read_json(state_path)
    if not state or state.get("schema_version") != _STATE_SCHEMA:
        return None
    return root, experience, state


def _charged_orders(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw_orders = state.get("orders")
    if not isinstance(raw_orders, list):
        return []
    return [
        order
        for order in raw_orders[:100]
        if isinstance(order, Mapping)
        and str(order.get("status") or "") in _CHARGED_STATUSES
    ]


def _all_orders(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw_orders = state.get("orders")
    if not isinstance(raw_orders, list):
        return []
    return [order for order in raw_orders[:100] if isinstance(order, Mapping)]


def _order_amount(experience: Mapping[str, Any], state: Mapping[str, Any]) -> float:
    cart = state.get("cart")
    if isinstance(cart, Mapping):
        amount = _money(cart.get("amount_yuan"))
        if amount:
            return amount
    intent = state.get("intent")
    if isinstance(intent, Mapping):
        amount = _money(intent.get("amount_per_order_yuan"))
        if amount:
            return amount
    return _money(experience.get("amount_per_order_yuan"), 58.0)


def _intent(state: Mapping[str, Any], experience: Mapping[str, Any]) -> tuple[int, float]:
    raw = state.get("intent")
    raw = raw if isinstance(raw, Mapping) else {}
    order_count = _count(
        raw.get("authorized_order_count"),
        _count(experience.get("authorized_order_count"), 1),
    )
    authorized_amount = _money(raw.get("authorized_amount_yuan"))
    if not authorized_amount:
        authorized_amount = _money(
            experience.get("authorized_amount_yuan"),
            _order_amount(experience, state) * order_count,
        )
    return order_count, authorized_amount


def _status_label(active_count: int, extra_spend: float, resolution: object) -> tuple[str, str]:
    if resolution and active_count <= 1 and extra_spend <= 0:
        return "resolved", "重复订单已处理"
    if active_count >= 2 or extra_spend > 0:
        return "danger", "已发生重复扣款"
    if active_count == 1:
        return "warning", "回执超时，重试前应先查单"
    return "ready", "策略正在保护本次下单"


def _order_view(order: Mapping[str, Any]) -> dict[str, Any]:
    items = order.get("items")
    return {
        "order_id": _safe_text(order.get("order_id"), limit=64),
        "merchant": _safe_text(order.get("merchant")),
        "items": [
            _safe_text(item, limit=80)
            for item in items[:12]
            if _safe_text(item, limit=80)
        ] if isinstance(items, list) else [],
        "amount_yuan": _money(order.get("amount_yuan")),
        "status": _safe_text(order.get("status"), limit=64),
        "attempt": _count(order.get("attempt"), 0),
        "created_at": _safe_text(order.get("created_at"), limit=64),
    }


def load_business_experience(workspace: Path | str) -> dict[str, Any] | None:
    """Return a bounded business-impact snapshot for an opted-in workspace."""

    configured = _configured_state(workspace)
    if configured is None:
        return None
    _root, experience, state = configured
    charged = _charged_orders(state)
    all_orders = _all_orders(state)
    intended_count, authorized_amount = _intent(state, experience)
    amount_each = _order_amount(experience, state)
    current_spend = round(
        sum(_money(order.get("amount_yuan")) for order in charged), 2
    )
    extra_spend = round(max(0.0, current_spend - authorized_amount), 2)
    status, status_label = _status_label(
        len(charged), extra_spend, state.get("resolution")
    )
    policies = load_business_policy_catalog()
    matched_rules: list[str] = []
    if not state.get("resolution"):
        if len(charged) >= 1 and state.get("last_client_result") == "timeout":
            matched_rules.append(RETRY_RULE)
        if len(charged) > intended_count:
            matched_rules.append(DUPLICATE_RULE)
        if extra_spend > 0:
            matched_rules.append(SPEND_RULE)

    default_prompt = _safe_text(experience.get("default_prompt"), limit=2_000)
    return {
        "schema_version": BUSINESS_EXPERIENCE_SCHEMA,
        "id": _safe_text(experience.get("id") or "takeaway-duplicate-order", limit=96),
        "kind": "takeaway_duplicate_order",
        "title": _safe_text(experience.get("title") or "外卖重复下单保护"),
        "summary": _safe_text(experience.get("summary"), limit=360),
        "safety_notice": _safe_text(
            experience.get("safety_notice")
            or "本页面只操作本地模拟订单，不连接真实外卖平台。",
            limit=240,
        ),
        "default_prompt": default_prompt,
        "status": status,
        "status_label": status_label,
        "intent": {
            "authorized_order_count": intended_count,
            "authorized_amount_yuan": authorized_amount,
            "merchant": _safe_text(
                (state.get("cart") or {}).get("merchant")
                if isinstance(state.get("cart"), Mapping)
                else experience.get("merchant")
            ),
        },
        "metrics": {
            "actual_order_count": len(charged),
            "recorded_order_count": len(all_orders),
            "duplicate_order_count": max(0, len(charged) - intended_count),
            "amount_per_order_yuan": amount_each,
            "total_spend_yuan": current_spend,
            "extra_spend_yuan": extra_spend,
            "next_order_count": len(charged) + 1,
            "next_total_spend_yuan": round(current_spend + amount_each, 2),
            "next_extra_spend_yuan": round(
                max(0.0, current_spend + amount_each - authorized_amount), 2
            ),
        },
        "orders": [_order_view(order) for order in all_orders],
        "last_client_result": _safe_text(state.get("last_client_result"), limit=64),
        "resolution": state.get("resolution") if isinstance(state.get("resolution"), Mapping) else None,
        "policy": {
            "policy_id": BUSINESS_POLICY_ID,
            "matched_rules": matched_rules,
            "rules": [
                policies[rule]
                for rule in (RETRY_RULE, DUPLICATE_RULE, SPEND_RULE)
                if rule in policies
            ],
        },
    }


def _command_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    # App-server commonly wraps commands in ``shell -lc '<command>'``.
    for index, token in enumerate(tokens[:-1]):
        if token in {"-c", "-lc"}:
            nested = _command_tokens(tokens[index + 1])
            if nested:
                return nested
    return tokens


def _is_takeaway_submit(command: str, root: Path) -> bool:
    tokens = _command_tokens(command)
    for index, token in enumerate(tokens[:-1]):
        if os.path.basename(token) != "takeaway_demo.py" or tokens[index + 1] != "submit":
            continue
        candidate = Path(token)
        if candidate.is_absolute():
            try:
                if candidate.resolve() != (root / "takeaway_demo.py").resolve():
                    continue
            except (OSError, RuntimeError):
                continue
        elif token not in {"takeaway_demo.py", "./takeaway_demo.py"}:
            continue
        return (root / "takeaway_demo.py").is_file()
    return False


def assess_business_command(
    command: str,
    workspace: Path | str,
) -> dict[str, Any] | None:
    """Assess the next configured transaction before its process starts."""

    configured = _configured_state(workspace)
    if configured is None:
        return None
    root, experience, state = configured
    if not _is_takeaway_submit(command, root):
        return None

    charged = _charged_orders(state)
    intended_count, authorized_amount = _intent(state, experience)
    amount_each = _order_amount(experience, state)
    current_count = len(charged)
    projected_count = current_count + 1
    current_spend = round(
        sum(_money(order.get("amount_yuan")) for order in charged), 2
    )
    projected_spend = round(current_spend + amount_each, 2)
    current_extra = round(max(0.0, current_spend - authorized_amount), 2)
    projected_extra = round(max(0.0, projected_spend - authorized_amount), 2)

    if current_count >= max(2, intended_count + 1):
        decision = "decline"
        level = "critical"
        headline = f"已阻止第 3 次下单：预计再扣 {amount_each:.0f} 元"
        summary = (
            f"你只授权 {intended_count} 单；当前已有 {current_count} 单、累计 ¥{current_spend:.0f}，"
            f"本次执行会变成 {projected_count} 单、累计 ¥{projected_spend:.0f}。"
        )
        recommendation = "停止重试，先查询订单并处理已经产生的重复订单。"
        blocking_rule: str | None = DUPLICATE_RULE
    elif current_count >= intended_count:
        decision = "review"
        level = "high"
        headline = "可能重复下单并再次扣款"
        summary = (
            f"你只想买 {intended_count} 单；当前已有 {current_count} 单。允许本次操作后将变成 "
            f"{projected_count} 单，预计累计 ¥{projected_spend:.0f}，多花 ¥{projected_extra:.0f}。"
        )
        recommendation = "建议拒绝本次重试，先查询平台是否已经生成订单。"
        blocking_rule = None
    else:
        decision = "allow"
        level = "normal"
        headline = f"准备提交 1 单 ¥{amount_each:.0f} 的模拟外卖"
        summary = (
            f"本次执行后预计有 {projected_count} 单、累计 ¥{projected_spend:.0f}，"
            "仍在用户授权范围内。"
        )
        recommendation = "可以继续；如果回执超时，下一步应先查单。"
        blocking_rule = None

    matched_rules = (
        [RETRY_RULE, DUPLICATE_RULE, SPEND_RULE]
        if current_count >= intended_count
        else []
    )
    impact = {
        "currency": "CNY",
        "authorized_order_count": intended_count,
        "current_order_count": current_count,
        "projected_order_count": projected_count,
        "amount_per_order_yuan": amount_each,
        "authorized_spend_yuan": authorized_amount,
        "current_spend_yuan": current_spend,
        "projected_spend_yuan": projected_spend,
        "current_extra_spend_yuan": current_extra,
        "projected_extra_spend_yuan": projected_extra,
        "merchant": _safe_text(
            (state.get("cart") or {}).get("merchant")
            if isinstance(state.get("cart"), Mapping)
            else experience.get("merchant")
        ),
        "simulated": True,
    }
    reasons = []
    if current_count >= intended_count:
        reasons = [
            f"{RETRY_RULE}：上次回执超时不等于下单失败，重试前应先查单",
            f"{DUPLICATE_RULE}：相同商家、商品、金额的订单将超过用户授权数量",
            f"{SPEND_RULE}：预计累计支出 ¥{projected_spend:.0f}，超出授权 ¥{projected_extra:.0f}",
        ]
    return {
        "policy_id": BUSINESS_POLICY_ID,
        "policy_name": "外卖重复下单与超额消费保护",
        "decision": decision,
        "level": level,
        "headline": headline,
        "summary": summary,
        "recommendation": recommendation,
        "reasons": reasons,
        "matched_rules": matched_rules,
        "blocking_rule": blocking_rule,
        "business_impact": impact,
    }


__all__ = [
    "BUSINESS_EXPERIENCE_SCHEMA",
    "BUSINESS_POLICY_ID",
    "DUPLICATE_RULE",
    "RETRY_RULE",
    "SPEND_RULE",
    "assess_business_command",
    "load_business_experience",
    "load_business_policy_catalog",
]
