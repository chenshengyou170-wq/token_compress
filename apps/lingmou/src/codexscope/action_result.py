"""Shared Lingmou action result contract for business side effects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any


ACTION_RESULT_SCHEMA_VERSION = "lingmou.action-result.v1"
ACTION_RESULT_STATUSES = frozenset(
    {
        "executed",
        "transformed",
        "review_required",
        "blocked",
        "declined",
        "failed",
        "expired",
    }
)


def request_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def action_result(
    *,
    action_id: str,
    status: str,
    summary: str,
    policy_ids: Iterable[str],
    business_impact: Mapping[str, Any] | None,
    safe_next_step: str,
    request_hash_value: str,
    **extra: Any,
) -> dict[str, Any]:
    if status not in ACTION_RESULT_STATUSES:
        raise ValueError(f"unsupported Lingmou action result status: {status}")
    result = {
        "schema_version": ACTION_RESULT_SCHEMA_VERSION,
        "action_id": str(action_id),
        "status": status,
        "summary": str(summary),
        "policy_ids": list(dict.fromkeys(str(item) for item in policy_ids if item)),
        "business_impact": dict(business_impact or {}),
        "safe_next_step": str(safe_next_step),
        "request_hash": str(request_hash_value),
    }
    result.update(extra)
    return result


__all__ = [
    "ACTION_RESULT_SCHEMA_VERSION",
    "ACTION_RESULT_STATUSES",
    "action_result",
    "request_hash",
]
