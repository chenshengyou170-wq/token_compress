"""Load local Lingmou policy definitions and match normalized live events."""

from __future__ import annotations

import importlib.resources
import json
from functools import lru_cache
from typing import Any, Mapping

_LEVEL_RANK = {"normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}
_SCHEMA_VERSION = "lingmou.policy-catalog.v1"
_POLICY_MODES = {"observe", "review", "deny"}


@lru_cache(maxsize=1)
def load_local_policies() -> tuple[dict[str, Any], ...]:
    """Return validated policy records bundled with CodexScope."""

    resource = importlib.resources.files("codexscope").joinpath(
        "policies/lingmou_policies.json"
    )
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ()
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        return ()
    raw_policies = payload.get("policies")
    if not isinstance(raw_policies, list):
        return ()

    policies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_policies:
        if not isinstance(raw, dict) or raw.get("enabled") is not True:
            continue
        policy_id = str(raw.get("id") or "").strip()
        name = str(raw.get("name") or "").strip()
        level = str(raw.get("risk_level") or "warning").strip().lower()
        action = str(raw.get("action") or "记录").strip()
        mode = str(raw.get("mode") or "observe").strip().lower()
        stage = str(raw.get("stage") or "runtime_observation").strip()
        evidence_source = str(
            raw.get("evidence_source") or "runtime_event"
        ).strip()
        tested = str(raw.get("tested") or "unverified").strip().lower()
        match = raw.get("match")
        if (
            not policy_id
            or policy_id in seen
            or not name
            or level not in _LEVEL_RANK
            or mode not in _POLICY_MODES
            or not stage
            or not evidence_source
            or not isinstance(match, dict)
        ):
            continue
        seen.add(policy_id)
        policies.append(
            {
                "id": policy_id[:128],
                "name": name[:160],
                "risk_level": level,
                "action": action[:160],
                "mode": mode,
                "stage": stage[:64],
                "evidence_source": evidence_source[:80],
                "enforceable_now": bool(raw.get("enforceable_now")),
                "stateful": bool(raw.get("stateful")),
                "tested": tested[:32],
                "match": match,
            }
        )
    return tuple(policies)


def _event_haystack(event: Mapping[str, Any]) -> str:
    risk = event.get("risk")
    risk = risk if isinstance(risk, Mapping) else {}
    technical = event.get("technical")
    technical = technical if isinstance(technical, Mapping) else {}
    reasons = risk.get("reasons")
    reasons = reasons if isinstance(reasons, list) else []
    matched_rules = technical.get("matched_rules")
    matched_rules = matched_rules if isinstance(matched_rules, list) else []
    values = [
        event.get("kind"),
        event.get("action"),
        event.get("detail"),
        event.get("target"),
        technical.get("syscall"),
        technical.get("policy_id"),
        technical.get("blocking_rule"),
        *matched_rules,
        *reasons,
    ]
    return " ".join(str(value) for value in values if value is not None).casefold()


def _matches(event: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    match = policy.get("match")
    if not isinstance(match, Mapping):
        return False
    risk = event.get("risk")
    risk = risk if isinstance(risk, Mapping) else {}
    level = str(risk.get("level") or "normal").lower()
    minimum = str(match.get("min_risk") or "normal").lower()
    if _LEVEL_RANK.get(level, 0) < _LEVEL_RANK.get(minimum, 0):
        return False
    if "blocked" in match and bool(event.get("blocked")) is not bool(match["blocked"]):
        return False
    kinds = match.get("kinds")
    if isinstance(kinds, list) and str(event.get("kind") or "") not in {
        str(value) for value in kinds
    }:
        return False
    sources = match.get("sources")
    if isinstance(sources, list) and str(event.get("source") or "") not in {
        str(value) for value in sources
    }:
        return False
    contains = match.get("contains_any")
    if isinstance(contains, list):
        needles = [str(value).casefold() for value in contains if str(value).strip()]
        if needles and not any(needle in _event_haystack(event) for needle in needles):
            return False
    return True


def match_local_policies(event: Mapping[str, Any]) -> list[dict[str, str]]:
    """Return only policies actually matched by one normalized event."""

    return [
        {
            "id": str(policy["id"]),
            "name": str(policy["name"]),
            "level": str(policy["risk_level"]),
            "action": str(policy["action"]),
            "origin": "local",
            "mode": str(policy["mode"]),
            "stage": str(policy["stage"]),
            "evidence_source": str(policy["evidence_source"]),
            "enforceable_now": str(bool(policy["enforceable_now"])).lower(),
            "stateful": str(bool(policy["stateful"])).lower(),
            "tested": str(policy["tested"]),
        }
        for policy in load_local_policies()
        if _matches(event, policy)
    ]


__all__ = ["load_local_policies", "match_local_policies"]
