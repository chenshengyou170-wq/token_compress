"""Stateful, replayable Lingmou runtime policy decisions.

The command classifier remains intentionally conservative.  This module adds
the pieces that need session context (lineage, rate windows and MCP baselines)
and exposes one stable decision contract that the monitor and workbench can
persist independently for every matched policy.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import time
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .business_policy import load_business_policy_catalog
from .commands import unwrap_shell_command
from .local_policies import load_local_policies
from .payment_security import PAYMENT_POLICY_RULES

POLICY_DECISION_SCHEMA_VERSION = "lingmou.policy-decision.v1"

_POLICY_BY_ID = {policy["id"]: policy for policy in load_local_policies()}
_PAYMENT_BY_ID = {rule["id"]: rule for rule in PAYMENT_POLICY_RULES}
_BUSINESS_BY_ID = load_business_policy_catalog()

_LEVEL_RANK = {"normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}
_RESULT_RANK = {
    "baseline_created": 0,
    "observed": 1,
    "detected": 1,
    "review": 2,
    "review_required": 2,
    "blocked": 3,
}

_OBFUSCATED_EXECUTION = re.compile(
    r"(?:base64\b[^\n;&|]*(?:-d|--decode)[^\n;&|]*\|\s*"
    r"(?:(?:/usr)?/bin/)?(?:"
    r"(?:sh|bash|dash|zsh)(?:\s+-[A-Za-z0-9-]+)*|"
    r"(?:python(?:3)?|node)(?:\s+-[A-Za-z0-9-]+)*"
    r")\s*(?=$|[;&]))|"
    # A normal shell wrapper around a decode-to-file command is not execution
    # of decoded content. This branch requires command substitution; pipes
    # into an interpreter and eval are covered by the other branches.
    r"(?:\b(?:sh|bash|dash|zsh)\s+-[A-Za-z]*c[A-Za-z]*\s+"
    r"[^\n]*(?:\$\(|`)[^\n]*(?:base64\s+(?:-d|--decode)))|"
    r"(?:\b(?:python|python3)\b[^\n]*(?:exec|eval)\s*\([^\n]*"
    r"base64\.(?:b64decode|decodebytes)\s*\()|"
    r"(?:\bpowershell(?:\.exe)?\b[^\n]*(?:-(?:e|enc|encodedcommand)\b|"
    r"\bIEX\b[^\n]*\bDownloadString\b))|"
    r"(?:\beval\b[^\n]*(?:base64\s+(?:-d|--decode)|openssl\s+base64\s+-d))",
    re.IGNORECASE,
)

_ENV_SECRET_WORDS = r"(?:token|api[_-]?key|secret|password|passwd|credential|private[_-]?key)"
_ENV_HARVEST = re.compile(
    rf"(?:\b(?:env|printenv|set)\b[^\n]*(?:grep|rg|awk)[^\n]*{_ENV_SECRET_WORDS})|"
    rf"(?:\b(?:env|printenv)\b\s+(?:[A-Z0-9_]*{_ENV_SECRET_WORDS}[A-Z0-9_]*\s+){{2,}})|"
    r"(?:/proc/(?:self|\d+|\*)/environ\b)|"
    r"(?:\b(?:find|fd|rg)\b[^\n]*(?:\.aws|\.ssh|\.kube|credentials?|secrets?)[^\n]*"
    r"(?:-print|--files|--hidden))",
    re.IGNORECASE,
)

_CONTROL_PLANE_TARGET = re.compile(
    r"(?:^|[/\\\s'\"])(?:AGENTS\.md|CLAUDE\.md|SOUL\.md|MEMORY\.md|"
    r"\.codex[/\\]config\.toml|\.mcp\.json|mcp(?:_servers?|Servers?)\.json|"
    r"skills?[/\\][^\s'\"]*SKILL\.md)(?:$|[\s'\";&|])",
    re.IGNORECASE,
)
_WRITE_INTENT = re.compile(
    r"(?:>>?|\btee\b|\bsed\s+-i\b|\b(?:cp|mv|install|touch)\b|"
    r"\bpython(?:3)?\b[^\n]*(?:write_text|write_bytes|open\s*\([^\n]*['\"]w)|"
    r"\b(?:jq|yq)\b[^\n]*>\s*)",
    re.IGNORECASE,
)

_REMOTE_INSTALL = re.compile(
    r"(?:\b(?:pip|pip3|uv)\b\s+(?:install|add)\b[^\n]*(?:git\+https?://|https?://))|"
    r"(?:\b(?:npm|pnpm|yarn|bun)\b\s+(?:install|add)\b[^\n]*(?:git\+https?://|"
    r"github:|https?://))|"
    r"(?:\bcargo\s+install\b[^\n]*--git\s+https?://)|"
    r"(?:\bgo\s+install\b[^\n]*@(?:latest|master|main)\b)",
    re.IGNORECASE,
)
_PINNED_GIT_COMMIT = re.compile(r"@[0-9a-f]{40}(?:\b|[#?])", re.IGNORECASE)
_INTEGRITY_CHECK = re.compile(
    r"(?:sha256sum\s+-c|shasum\s+-a\s+256|cosign\s+verify|gpg\s+--verify|"
    r"npm\s+(?:ci|install)\b[^\n]*--ignore-scripts)",
    re.IGNORECASE,
)

_SENSITIVE_PATH = re.compile(
    r"(?:^|[\s@/\\])(?:\.env(?:\.|$)|secrets?(?:[/\\]|$)|"
    r"credentials?(?:[/\\]|$)|id_(?:rsa|ed25519)(?:\.|$)|\.aws[/\\]|"
    r"\.ssh[/\\]|\.kube[/\\]config|\.docker[/\\]config\.json|"
    r"\.config[/\\]gh[/\\]hosts\.yml|shadow$)",
    re.IGNORECASE,
)
_DERIVATION = re.compile(
    r"\b(?:base64|openssl\s+(?:enc|base64)|tar|zip|gzip|bzip2|xz|cp|mv|"
    r"jq|sed|awk|python(?:3)?)\b|(?:>>?|\btee\b)",
    re.IGNORECASE,
)
_REDIRECT_TARGET = re.compile(r"(?:^|[^<>])>{1,2}\s*([^\s;&|]+)")
_TEE_TARGET = re.compile(r"\btee\b(?:\s+-[A-Za-z]+)*\s+([^\s;&|]+)", re.IGNORECASE)
_OUTPUT_TARGET = re.compile(
    r"(?:^|\s)(?:-o|--output|--out|--outfile)(?:=|\s+)([^\s;&|]+)",
    re.IGNORECASE,
)
_TAR_TARGET = re.compile(
    r"\btar\b[^\n;&|]*?(?:-[A-Za-z]*f\s+|--file(?:=|\s+))([^\s;&|]+)",
    re.IGNORECASE,
)
_UPLOAD_FILE = re.compile(
    r"(?:--data(?:-binary|-raw)?|-d)\s+@([^\s;&|]+)|"
    r"--upload-file(?:=|\s+)([^\s;&|]+)",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_NETWORK_COMMAND = re.compile(
    r"(?:^|[;&|]\s*|\s)(?:curl|wget|scp|sftp|rsync|nc|ncat|socat)\b|https?://",
    re.IGNORECASE,
)
_UPLOAD_COMMAND = re.compile(
    r"(?:--data(?:-binary|-raw)?\s+@|-d\s+@|--upload-file\b|\bscp\b|\brsync\b)",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "override_previous_instructions",
        re.compile(
            r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
            r"忽略(?:之前|以上|前面|所有)(?:的)?(?:指令|要求|规则)",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_privileged_role",
        re.compile(
            r"(?:^|\n)\s*(?:system|developer|assistant)\s*(?:message)?\s*:|"
            r"<(?:system|developer|assistant)>|\[\s*(?:system|developer)\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "concealment_request",
        re.compile(
            r"(?:do not|don't|never)\s+(?:tell|show|mention)\s+(?:the\s+)?user|"
            r"不要(?:告诉|提示|展示给)用户|绕过(?:审批|安全|策略)",
            re.IGNORECASE,
        ),
    ),
)
_CONTROL_CHAR = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

_PRIVILEGED_TOOL = re.compile(
    r"(?:shell|terminal|exec|command|delete|remove|secret|credential|upload|"
    r"network|http|write|patch|sudo|docker|kubernetes|kubectl)",
    re.IGNORECASE,
)

_DEFAULT_ALLOWED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "crates.io",
        "static.crates.io",
    }
)


def _catalog_metadata(policy_id: str) -> dict[str, Any]:
    policy = _POLICY_BY_ID.get(policy_id)
    if policy is not None:
        return dict(policy)
    payment = _PAYMENT_BY_ID.get(policy_id)
    if payment is not None:
        effect = str(payment.get("effect") or "detect")
        return {
            "id": policy_id,
            "name": str(payment.get("label") or policy_id),
            "risk_level": "critical" if effect in {"block", "decline"} else "high",
            "action": {
                "track": "持续跟踪关联操作",
                "warn": "告警并跟踪派生内容",
                "detect": "进入执行前审批",
                "decline": "执行前阻断并保全证据",
                "block": "执行前阻断并保全证据",
            }.get(effect, "记录并告警"),
            "mode": (
                "deny"
                if effect in {"block", "decline"}
                else "review"
                if effect == "detect"
                else "observe"
            ),
            "stage": "pre_execution_approval",
            "evidence_source": "deterministic_command_analysis",
            "enforceable_now": effect in {"block", "decline"},
            "stateful": False,
            "tested": "local",
        }
    business = _BUSINESS_BY_ID.get(policy_id)
    if business is not None:
        return {
            "id": policy_id,
            "name": str(business.get("name") or policy_id),
            "risk_level": {
                "LIFE-RETRY-001": "warning",
                "LIFE-ORDER-002": "critical",
                "LIFE-SPEND-003": "high",
            }.get(policy_id, "warning"),
            "action": str(business.get("action") or "记录并告警"),
            "mode": "deny" if policy_id == "LIFE-ORDER-002" else "review",
            "stage": "pre_execution_approval",
            "evidence_source": "deterministic_business_state",
            "enforceable_now": policy_id == "LIFE-ORDER-002",
            "stateful": True,
            "tested": "local",
        }
    return {
        "id": policy_id,
        "name": policy_id,
        "risk_level": "warning",
        "action": "记录并告警",
        "mode": "observe",
        "stage": "runtime_observation",
        "evidence_source": "runtime_event",
        "enforceable_now": False,
        "stateful": False,
        "tested": "unverified",
    }


def policy_decision(
    policy_id: str,
    *,
    reason: str,
    result: str = "observed",
    stage: str | None = None,
    level: str | None = None,
    mode: str | None = None,
    blocking: bool = False,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one bounded, JSON-safe policy decision for durable replay."""

    metadata = _catalog_metadata(policy_id)
    normalized_level = str(level or metadata.get("risk_level") or "warning").lower()
    if normalized_level not in _LEVEL_RANK:
        normalized_level = "warning"
    return {
        "schema_version": POLICY_DECISION_SCHEMA_VERSION,
        "policy_id": policy_id[:128],
        "policy_name": str(metadata.get("name") or policy_id)[:160],
        "level": normalized_level,
        "mode": str(mode or metadata.get("mode") or "observe")[:32],
        "stage": str(stage or metadata.get("stage") or "runtime_observation")[:64],
        "action": str(metadata.get("action") or "记录并告警")[:160],
        "result": result[:64],
        "matched": True,
        "blocking": bool(blocking),
        "reason": reason[:320],
        "evidence_source": str(
            metadata.get("evidence_source") or "runtime_event"
        )[:80],
        "enforceable_now": bool(metadata.get("enforceable_now")),
        "stateful": bool(metadata.get("stateful")),
        "tested": str(metadata.get("tested") or "unverified")[:32],
        "evidence": _bounded_evidence(evidence or {}),
    }


def decisions_from_rule_ids(
    rule_ids: Iterable[str],
    *,
    reasons: Sequence[str] = (),
    blocking_rule: str | None = None,
    stage: str = "pre_execution_approval",
    result: str | None = None,
) -> list[dict[str, Any]]:
    """Turn legacy matched-rule identifiers into explicit decisions."""

    provided_reasons = [
        str(value)[:200] for value in reasons if str(value).strip()
    ][:12]
    decisions: list[dict[str, Any]] = []
    for policy_id in dict.fromkeys(str(value) for value in rule_ids if str(value).strip()):
        metadata = _catalog_metadata(policy_id)
        blocking = policy_id == blocking_rule
        mode = str(metadata.get("mode") or "observe")
        requested_result = str(result or "")
        if blocking:
            actual_result = "blocked"
        elif requested_result == "blocked":
            # A blocked activity can match several precursor policies.  Only
            # the policy named as ``blocking_rule`` made the deny decision.
            actual_result = "review" if mode == "review" else "observed"
        elif requested_result:
            actual_result = requested_result
        else:
            actual_result = "review" if mode == "review" else "observed"
        name = str(metadata.get("name") or policy_id)
        decisions.append(
            policy_decision(
                policy_id,
                reason=(
                    f"{name}：该规则作出执行前拒绝决定"
                    if blocking
                    else f"{name}：事件分类结果命中本策略"
                ),
                result=actual_result,
                stage=stage,
                blocking=blocking,
                evidence={
                    "matched_rule": policy_id,
                    "reported_reasons": provided_reasons,
                },
            )
        )
    return decisions


def merge_policy_decisions(*groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge decisions by policy and stage, preferring stronger outcomes."""

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for group in groups:
        for raw in group:
            if not isinstance(raw, Mapping):
                continue
            decision = dict(raw)
            policy_id = str(decision.get("policy_id") or "")
            stage = str(decision.get("stage") or "runtime_observation")
            if not policy_id:
                continue
            key = (policy_id, stage)
            current = merged.get(key)
            if current is None:
                merged[key] = decision
                continue
            current_rank = _RESULT_RANK.get(str(current.get("result")), 0)
            decision_rank = _RESULT_RANK.get(str(decision.get("result")), 0)
            current_evidence = current.get("evidence")
            decision_evidence = decision.get("evidence")
            current_evidence_size = (
                len(current_evidence) if isinstance(current_evidence, Mapping) else 0
            )
            decision_evidence_size = (
                len(decision_evidence) if isinstance(decision_evidence, Mapping) else 0
            )
            if decision_rank > current_rank or (
                decision_rank == current_rank
                and decision_evidence_size > current_evidence_size
            ):
                selected = decision
                fallback = current
            else:
                selected = current
                fallback = decision
            selected = dict(selected)
            selected["blocking"] = bool(selected.get("blocking")) or bool(
                fallback.get("blocking")
            )
            if selected.get("blocking"):
                selected["result"] = "blocked"
            if not selected.get("evidence") and fallback.get("evidence"):
                selected["evidence"] = fallback["evidence"]
            merged[key] = selected
    return sorted(
        merged.values(),
        key=lambda item: (
            -_LEVEL_RANK.get(str(item.get("level")), 0),
            str(item.get("policy_id")),
        ),
    )


def strongest_policy_decisions(
    decisions: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Select one replay decision per policy, preferring the real blocker.

    The monitor can report the same policy at pre-execution and command
    lifecycle stages.  A dictionary built from arrival order can accidentally
    replace a ``blocked`` decision with a later ``observed`` copy.  This helper
    makes the user-visible replay deterministic and outcome-aware.
    """

    selected: dict[str, dict[str, Any]] = {}
    for decision in merge_policy_decisions(decisions):
        policy_id = str(decision.get("policy_id") or "").strip()
        if not policy_id:
            continue
        current = selected.get(policy_id)
        if current is None:
            selected[policy_id] = decision
            continue
        decision_rank = (
            int(bool(decision.get("blocking"))),
            _RESULT_RANK.get(str(decision.get("result")), 0),
            int(str(decision.get("stage") or "").startswith("pre_execution")),
            len(decision.get("evidence") or {})
            if isinstance(decision.get("evidence"), Mapping)
            else 0,
        )
        current_rank = (
            int(bool(current.get("blocking"))),
            _RESULT_RANK.get(str(current.get("result")), 0),
            int(str(current.get("stage") or "").startswith("pre_execution")),
            len(current.get("evidence") or {})
            if isinstance(current.get("evidence"), Mapping)
            else 0,
        )
        if decision_rank > current_rank:
            selected[policy_id] = decision
    return sorted(
        selected.values(),
        key=lambda item: (
            -int(bool(item.get("blocking"))),
            -_RESULT_RANK.get(str(item.get("result")), 0),
            -_LEVEL_RANK.get(str(item.get("level")), 0),
            str(item.get("policy_id")),
        ),
    )


def _bounded_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, raw in list(value.items())[:24]:
        safe_key = str(key)[:80]
        if isinstance(raw, str):
            result[safe_key] = raw[:512]
        elif isinstance(raw, (int, float, bool)) or raw is None:
            result[safe_key] = raw
        elif isinstance(raw, (list, tuple)):
            result[safe_key] = [
                item[:256] if isinstance(item, str) else item
                for item in list(raw)[:16]
                if isinstance(item, (str, int, float, bool)) or item is None
            ]
        elif isinstance(raw, Mapping):
            result[safe_key] = _bounded_evidence(raw)
    return result


def _strip_token(value: str) -> str:
    return value.strip().strip("'\"").removeprefix("@")


def _normalize_path(value: str, cwd: Path) -> str:
    cleaned = os.path.expandvars(os.path.expanduser(_strip_token(value)))
    if not cleaned:
        return ""
    candidate = Path(cleaned)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        return os.fspath(candidate.resolve(strict=False))
    except OSError:
        return os.fspath(candidate.absolute())


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _command_views(command: str) -> list[str]:
    unwrapped = unwrap_shell_command(command)
    # Prefer the innermost script so path extraction does not mistake the
    # entire quoted ``-c`` payload for one path-like shell argument.
    return list(dict.fromkeys((unwrapped, command)))


def _derived_targets(command: str, cwd: Path) -> list[str]:
    raw: list[str] = []
    for view in _command_views(command):
        for pattern in (_REDIRECT_TARGET, _TEE_TARGET, _OUTPUT_TARGET, _TAR_TARGET):
            raw.extend(match.group(1) for match in pattern.finditer(view) if match.group(1))
        tokens = _command_tokens(view)
        for index, token in enumerate(tokens):
            base = Path(token).name.casefold()
            if base in {"cp", "mv", "install"} and index + 2 < len(tokens):
                operands = [value for value in tokens[index + 1 :] if not value.startswith("-")]
                if len(operands) >= 2:
                    raw.append(operands[-1])
                break
    return list(
        dict.fromkeys(
            path for value in raw if (path := _normalize_path(value, cwd))
        )
    )


def _upload_sources(command: str, cwd: Path) -> list[str]:
    raw: list[str] = []
    for view in _command_views(command):
        for match in _UPLOAD_FILE.finditer(view):
            raw.extend(value for value in match.groups() if value)
        tokens = _command_tokens(view)
        for index, token in enumerate(tokens):
            base = Path(token).name.casefold()
            if base not in {"scp", "rsync", "sftp"}:
                continue
            operands = [
                value
                for value in tokens[index + 1 :]
                if not value.startswith("-") and not re.match(r"^[A-Za-z]+://", value)
            ]
            for operand in operands[:-1]:
                if ":" not in operand or operand.startswith(("./", "../", "/")):
                    raw.append(operand)
            break
    return list(
        dict.fromkeys(
            path for value in raw if (path := _normalize_path(value, cwd))
        )
    )


def _referenced_paths(command: str, cwd: Path) -> list[str]:
    values: list[str] = []
    for view in _command_views(command):
        for token in _command_tokens(view):
            clean = _strip_token(token)
            if not clean or clean.startswith("-") or re.match(r"^[A-Za-z]+://", clean):
                continue
            if any(separator in clean for separator in ("/", "\\")) or clean.startswith("."):
                values.append(_normalize_path(clean, cwd))
    return [value for value in dict.fromkeys(values) if value]


def _host_from_url(value: str) -> str | None:
    try:
        return (urlsplit(value).hostname or "").casefold() or None
    except ValueError:
        return None


def _egress_hosts(command: str) -> list[str]:
    hosts: list[str] = []
    for view in _command_views(command):
        hosts.extend(
            host for value in _URL.findall(view) if (host := _host_from_url(value))
        )
        for token in _command_tokens(view):
            if "@" in token and ":" in token and "://" not in token:
                remote = token.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]")
                if remote:
                    hosts.append(remote.casefold())
    return list(dict.fromkeys(hosts))


def _is_private_host(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def _configured_allowed_hosts(workspace: Path | None) -> set[str]:
    hosts = set(_DEFAULT_ALLOWED_HOSTS)
    environment = os.environ.get("LINGMOU_EGRESS_ALLOWLIST", "")
    hosts.update(value.strip().casefold() for value in environment.split(",") if value.strip())
    if workspace is None:
        return hosts
    path = workspace / ".lingmou-policy.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
            return hosts
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return hosts
    configured = value.get("allowed_egress_hosts") if isinstance(value, Mapping) else None
    if isinstance(configured, list):
        hosts.update(str(item).strip().casefold() for item in configured if str(item).strip())
    return hosts


def _host_allowed(host: str, allowed_hosts: set[str]) -> bool:
    return any(host == value or (value.startswith(".") and host.endswith(value)) for value in allowed_hosts)


def assess_command_policies(
    command: str,
    *,
    cwd: Path | str | None = None,
    workspace: Path | str | None = None,
    principal: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate stateless policies 026-029, 032 and principal context 035."""

    command_text = str(command or "")
    if not command_text.strip():
        return []
    root = Path(workspace).expanduser().resolve() if workspace is not None else None
    command_cwd = Path(cwd).expanduser() if cwd is not None else root or Path.cwd()
    decisions: list[dict[str, Any]] = []

    if any(_OBFUSCATED_EXECUTION.search(view) for view in _command_views(command_text)):
        decisions.append(
            policy_decision(
                "LING-OBFEXEC-026",
                reason="检测到解码、反混淆结果直接进入解释器或动态执行函数",
                result="detected",
                evidence={"detector": "decode_then_execute", "confidence": "high"},
            )
        )
    if _ENV_HARVEST.search(command_text):
        decisions.append(
            policy_decision(
                "LING-ENVHARVEST-027",
                reason="检测到批量枚举环境变量或进程环境中的秘密名称",
                result="review",
                evidence={"detector": "broad_secret_enumeration", "confidence": "high"},
            )
        )
    if _CONTROL_PLANE_TARGET.search(command_text) and _WRITE_INTENT.search(command_text):
        decisions.append(
            policy_decision(
                "LING-CONTROLPLANE-028",
                reason="命令准备修改 Agent 指令、记忆、Skill 或 MCP 配置",
                result="review",
                stage="pre_execution_approval",
                evidence={"detector": "control_plane_write", "confidence": "high"},
            )
        )
    if _REMOTE_INSTALL.search(command_text) and not (
        _PINNED_GIT_COMMIT.search(command_text) or _INTEGRITY_CHECK.search(command_text)
    ):
        decisions.append(
            policy_decision(
                "LING-SUPPLYCHAIN-029",
                reason="依赖来自可变 Git 引用或任意 URL，命令中没有固定提交或完整性校验",
                result="review",
                evidence={"detector": "mutable_remote_dependency", "confidence": "high"},
            )
        )

    allowed_hosts = _configured_allowed_hosts(root)
    for host in _egress_hosts(command_text):
        if _host_allowed(host, allowed_hosts):
            continue
        private = _is_private_host(host)
        decisions.append(
            policy_decision(
                "LING-EGRESS-ALLOWLIST-032",
                reason=(
                    f"出口目标 {host} 属于未登记的本地或私网地址，需确认不是 SSRF"
                    if private
                    else f"出口目标 {host} 尚未登记在工作区允许列表"
                ),
                result="review",
                level="high" if private else "warning",
                evidence={
                    "host": host,
                    "target_class": "private_or_local" if private else "unlisted_external",
                    "allowlist_source": "workspace_and_safe_defaults",
                },
            )
        )

    principal_data = principal if isinstance(principal, Mapping) else {}
    principal_id = str(
        principal_data.get("agentId")
        or principal_data.get("agent_id")
        or principal_data.get("actor")
        or ""
    )
    role = str(principal_data.get("role") or "")
    if principal_id and principal_id not in {"root", "primary"} and (
        _PRIVILEGED_TOOL.search(command_text) or _SENSITIVE_PATH.search(command_text)
    ):
        decisions.append(
            policy_decision(
                "LING-PRINCIPAL-035",
                reason="子 Agent 或非主执行主体请求了高影响能力，需沿用用户审批边界",
                result="review",
                stage="pre_execution_approval",
                evidence={"principal_id": principal_id, "role": role or "unspecified"},
            )
        )
    return merge_policy_decisions(decisions)


def assess_file_change_policies(
    changes: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    targets = [str(change.get("path") or "") for change in changes]
    matched = [target for target in targets if _CONTROL_PLANE_TARGET.search(f" {target} ")]
    if not matched:
        return []
    return [
        policy_decision(
            "LING-CONTROLPLANE-028",
            reason="文件变更将修改 Agent 指令、记忆、Skill 或 MCP 配置",
            result="review",
            stage="pre_execution_file_approval",
            evidence={"targets": matched[:12], "confidence": "exact_path"},
        )
    ]


def _string_content(value: Any, *, limit: int = 128_000) -> str:
    parts: list[str] = []
    remaining = limit

    def visit(item: Any) -> None:
        nonlocal remaining
        if remaining <= 0:
            return
        if isinstance(item, str):
            parts.append(item[:remaining])
            remaining -= len(parts[-1])
        elif isinstance(item, Mapping):
            for key, child in list(item.items())[:64]:
                if str(key).casefold() in {"result", "output", "content", "text", "message"}:
                    visit(child)
        elif isinstance(item, list):
            for child in item[:64]:
                visit(child)

    visit(value)
    return "\n".join(parts)


def assess_text_policies(
    text: str,
    *,
    surface: str,
) -> list[dict[str, Any]]:
    matches = [name for name, pattern in _PROMPT_INJECTION_PATTERNS if pattern.search(text)]
    if not matches and not _CONTROL_CHAR.search(text):
        return []
    content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    policy_id = "LING-MCP-OUTPUT-INJECTION-034" if surface == "tool_output" else "LING-PROMPT-INJECT-036"
    stage = "tool_after" if surface == "tool_output" else "llm_before"
    return [
        policy_decision(
            policy_id,
            reason=(
                "工具结果包含试图覆盖上层指令、隐藏行为或伪造高权限角色的内容"
                if surface == "tool_output"
                else "输入包含提示注入特征；已记录但不会阻止用户提交"
            ),
            result="review" if surface == "tool_output" else "observed",
            stage=stage,
            evidence={
                "surface": surface,
                "patterns": matches,
                "has_invisible_controls": bool(_CONTROL_CHAR.search(text)),
                "content_sha256": content_hash,
                "characters": len(text),
                "content_persisted": False,
            },
        )
    ]


class RuntimePolicySession:
    """Bounded session context for lineage, burst and MCP trust policies."""

    def __init__(
        self,
        workspace: Path | str | None = None,
        *,
        egress_window_seconds: float = 300.0,
        egress_burst_threshold: int = 5,
        max_tainted_paths: int = 512,
        max_mcp_baselines: int = 512,
        max_seen_tool_results: int = 2_048,
    ) -> None:
        if egress_window_seconds <= 0:
            raise ValueError("egress_window_seconds must be positive")
        if egress_burst_threshold < 2:
            raise ValueError("egress_burst_threshold must be at least 2")
        self.workspace = (
            Path(workspace).expanduser().resolve() if workspace is not None else None
        )
        self.egress_window_seconds = float(egress_window_seconds)
        self.egress_burst_threshold = int(egress_burst_threshold)
        self.max_tainted_paths = max(32, int(max_tainted_paths))
        self.max_mcp_baselines = max(32, int(max_mcp_baselines))
        self.max_seen_tool_results = max(64, int(max_seen_tool_results))
        self._tainted_paths: dict[str, dict[str, Any]] = {}
        self._egress_times: deque[float] = deque(maxlen=2_048)
        self._mcp_baselines: dict[tuple[str, str], str] = {}
        self._mcp_seen_results: set[tuple[str, str, str]] = set()
        self._mcp_seen_result_order: deque[tuple[str, str, str]] = deque()

    def _cwd(self, value: Path | str | None) -> Path:
        if value is not None:
            return Path(value).expanduser()
        return self.workspace or Path.cwd()

    def _prune_egress(self, now: float) -> None:
        threshold = now - self.egress_window_seconds
        while self._egress_times and self._egress_times[0] < threshold:
            self._egress_times.popleft()

    def assess_command(
        self,
        command: str,
        *,
        cwd: Path | str | None = None,
        now: float | None = None,
        principal: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        current = time.time() if now is None else float(now)
        command_cwd = self._cwd(cwd)
        decisions = assess_command_policies(
            command,
            cwd=command_cwd,
            workspace=self.workspace,
            principal=principal,
        )

        upload_sources = _upload_sources(command, command_cwd)
        lineages = [self._tainted_paths[source] for source in upload_sources if source in self._tainted_paths]
        if lineages:
            evidence = lineages[0]
            decisions.append(
                policy_decision(
                    "LING-LINEAGE-030",
                    reason="当前外发源是此前由敏感内容生成的派生文件",
                    result="detected",
                    evidence={
                        "derived_path": evidence.get("derived_path"),
                        "source_path": evidence.get("source_path"),
                        "hop_count": evidence.get("hop_count"),
                        "lineage_id": evidence.get("lineage_id"),
                        "confidence": "explicit_command_lineage",
                    },
                )
            )

        if _UPLOAD_COMMAND.search(command) or (_NETWORK_COMMAND.search(command) and _egress_hosts(command)):
            self._prune_egress(current)
            projected = len(self._egress_times) + 1
            if projected >= self.egress_burst_threshold:
                decisions.append(
                    policy_decision(
                        "LING-EGRESS-BURST-031",
                        reason=(
                            f"{self.egress_window_seconds:g} 秒窗口内将出现第 {projected} 次外联或上传"
                        ),
                        result="review",
                        evidence={
                            "window_seconds": self.egress_window_seconds,
                            "previous_events": len(self._egress_times),
                            "projected_events": projected,
                            "threshold": self.egress_burst_threshold,
                        },
                    )
                )
        return merge_policy_decisions(decisions)

    def observe_command(
        self,
        command: str,
        *,
        cwd: Path | str | None = None,
        status: str = "completed",
        exit_code: int | None = None,
        observed_at: float | None = None,
        turn_id: str | None = None,
        item_id: str | None = None,
    ) -> None:
        """Commit state only after an action is known to have completed."""

        normalized_status = str(status).casefold()
        if normalized_status not in {"completed", "success", "succeeded"}:
            return
        if exit_code not in {None, 0}:
            return
        current = time.time() if observed_at is None else float(observed_at)
        command_cwd = self._cwd(cwd)
        if _UPLOAD_COMMAND.search(command) or (_NETWORK_COMMAND.search(command) and _egress_hosts(command)):
            self._prune_egress(current)
            self._egress_times.append(current)

        referenced = _referenced_paths(command, command_cwd)
        inherited = [self._tainted_paths[path] for path in referenced if path in self._tainted_paths]
        sensitive_source = next(
            (path for path in referenced if _SENSITIVE_PATH.search(path)),
            None,
        )
        if not _DERIVATION.search(command) or (sensitive_source is None and not inherited):
            return
        source = inherited[0].get("source_path") if inherited else sensitive_source
        hop = int(inherited[0].get("hop_count") or 0) + 1 if inherited else 1
        for target in _derived_targets(command, command_cwd):
            lineage_id = hashlib.sha256(
                f"{source}\0{target}\0{turn_id or ''}\0{item_id or ''}".encode(
                    "utf-8", errors="replace"
                )
            ).hexdigest()[:24]
            self._tainted_paths[target] = {
                "lineage_id": lineage_id,
                "source_path": source,
                "derived_path": target,
                "hop_count": hop,
                "turn_id": turn_id,
                "item_id": item_id,
                "observed_at": current,
            }
        while len(self._tainted_paths) > self.max_tainted_paths:
            oldest = min(
                self._tainted_paths,
                key=lambda path: float(self._tainted_paths[path].get("observed_at") or 0),
            )
            self._tainted_paths.pop(oldest, None)

    def assess_tool_item(
        self,
        item: Mapping[str, Any],
        *,
        lifecycle: str,
    ) -> list[dict[str, Any]]:
        item_type = str(item.get("type") or "")
        decisions: list[dict[str, Any]] = []
        if item_type == "mcpToolCall" and lifecycle == "started":
            server = str(item.get("server") or item.get("serverName") or "unknown")[:256]
            tool = str(item.get("tool") or item.get("toolName") or "unknown")[:256]
            definition = {
                "description": item.get("description"),
                "input_schema": item.get("inputSchema") or item.get("input_schema") or item.get("schema"),
            }
            definition_present = any(value is not None for value in definition.values())
            canonical = json.dumps(
                {"server": server, "tool": tool, **definition},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            key = (server, tool)
            previous = self._mcp_baselines.get(key)
            if previous is None:
                while len(self._mcp_baselines) >= self.max_mcp_baselines:
                    self._mcp_baselines.pop(next(iter(self._mcp_baselines)))
                self._mcp_baselines[key] = fingerprint
                decisions.append(
                    policy_decision(
                        "LING-MCP-DRIFT-033",
                        reason="首次观察到该 MCP 工具，已建立本会话信任基线",
                        result="baseline_created",
                        stage="tool_before",
                        level="notice",
                        evidence={
                            "server": server,
                            "tool": tool,
                            "definition_fingerprint": fingerprint,
                            "definition_present": definition_present,
                        },
                    )
                )
            elif previous != fingerprint:
                decisions.append(
                    policy_decision(
                        "LING-MCP-DRIFT-033",
                        reason="MCP 工具定义与本会话首次授权时的基线不一致",
                        result="review_required",
                        stage="tool_before",
                        level="high",
                        evidence={
                            "server": server,
                            "tool": tool,
                            "previous_fingerprint": previous,
                            "current_fingerprint": fingerprint,
                            "definition_present": definition_present,
                        },
                    )
                )

        if item_type in {"mcpToolCall", "dynamicToolCall"} and lifecycle == "completed":
            content = _string_content(item)
            if content:
                content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
                key = (str(item.get("id") or ""), item_type, content_hash)
                if key not in self._mcp_seen_results:
                    while len(self._mcp_seen_result_order) >= self.max_seen_tool_results:
                        expired = self._mcp_seen_result_order.popleft()
                        self._mcp_seen_results.discard(expired)
                    self._mcp_seen_results.add(key)
                    self._mcp_seen_result_order.append(key)
                    decisions.extend(assess_text_policies(content, surface="tool_output"))

        if item_type in {"collabAgentToolCall", "subAgentActivity"} and lifecycle == "started":
            principal_id = str(
                item.get("agentId") or item.get("agent_id") or item.get("actor") or "subagent"
            )
            tool = str(item.get("tool") or item.get("name") or item.get("command") or "")
            arguments = item.get("arguments")
            argument_text = json.dumps(arguments, ensure_ascii=False, default=str) if arguments is not None else ""
            if _PRIVILEGED_TOOL.search(f"{tool} {argument_text}"):
                decisions.append(
                    policy_decision(
                        "LING-PRINCIPAL-035",
                        reason="子 Agent 请求调用高影响工具，已保留主体与能力边界供复核",
                        result="review",
                        stage="tool_before",
                        evidence={"principal_id": principal_id, "tool": tool[:256]},
                    )
                )
        return merge_policy_decisions(decisions)

    def assess_user_text(self, text: str) -> list[dict[str, Any]]:
        return assess_text_policies(text, surface="user_input")

    def snapshot(self) -> dict[str, Any]:
        """Expose count-only state for diagnostics without leaking content."""

        return {
            "tainted_path_count": len(self._tainted_paths),
            "egress_events_retained": len(self._egress_times),
            "mcp_baseline_count": len(self._mcp_baselines),
        }


__all__ = [
    "POLICY_DECISION_SCHEMA_VERSION",
    "RuntimePolicySession",
    "assess_command_policies",
    "assess_file_change_policies",
    "assess_text_policies",
    "decisions_from_rule_ids",
    "merge_policy_decisions",
    "policy_decision",
    "strongest_policy_decisions",
]
