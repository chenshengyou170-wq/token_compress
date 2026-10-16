"""Deterministic, user-facing explanations for Lingmou workbench activity.

The explainer deliberately does not call a model and never participates in an
approval decision.  It translates commands and tool metadata into a stable
display contract, while keeping facts, contextual inferences, OS observations,
and security-policy decisions explicitly separated.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .redaction import redact_event, redact_text


EXPLANATION_SCHEMA_VERSION = "lingmou.activity-explanation.v1"

_SHELLS = {"sh", "bash", "zsh", "dash", "fish"}
_CONTROL_OPERATORS = {"|", "||", "&&", ";", "&"}
_WRITE_REDIRECTS = {">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>"}
_READ_REDIRECTS = {"<", "0<"}
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"]+", re.IGNORECASE)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|credential|password|passwd|secret|token|api[_-]?key|cookie)",
    re.IGNORECASE,
)


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = redact_text(str(value).strip())
        if text and text not in result:
            result.append(text)
    return result


def _basename(value: str) -> str:
    return os.path.basename(value.rstrip("/")) or value


def _shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            command,
            posix=True,
            punctuation_chars="|&;<>",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        return []


def _unwrap_shell(command: str) -> str:
    """Return the payload of a conventional ``shell -c`` wrapper."""

    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return command.strip()
    if len(parts) >= 3 and _basename(parts[0]) in _SHELLS:
        option = parts[1]
        if option == "-c" or (option.startswith("-") and "c" in option[1:]):
            return parts[2]
    return command.strip()


def split_shell_operations(command: str) -> list[dict[str, Any]]:
    """Split pipelines and shell control operators without executing them."""

    inner = _unwrap_shell(command)
    tokens = _shell_tokens(inner)
    if not tokens:
        return [{"command": inner, "operator": None, "tokens": []}]
    operations: list[dict[str, Any]] = []
    current: list[str] = []
    preceding: str | None = None
    for token in tokens:
        if token in _CONTROL_OPERATORS:
            if current:
                operations.append(
                    {
                        "command": shlex.join(current),
                        "operator": preceding,
                        "tokens": current,
                    }
                )
                current = []
            preceding = token
            continue
        current.append(token)
    if current:
        operations.append(
            {
                "command": shlex.join(current),
                "operator": preceding,
                "tokens": current,
            }
        )
    return operations or [{"command": inner, "operator": None, "tokens": tokens}]


def _command_start(tokens: Sequence[str]) -> tuple[str, list[str]]:
    values = list(tokens)
    while values and values[0] in {"command", "builtin", "nohup"}:
        values.pop(0)
    if values and values[0] == "env":
        values.pop(0)
        while values and "=" in values[0] and not values[0].startswith(("/", "./")):
            values.pop(0)
    if values and values[0] == "sudo":
        values.pop(0)
        while values and values[0].startswith("-"):
            values.pop(0)
    if not values:
        return "", []
    return _basename(values[0]), values[1:]


def _redirect_effects(tokens: Sequence[str]) -> tuple[list[str], list[str]]:
    reads: list[str] = []
    writes: list[str] = []
    for index, token in enumerate(tokens[:-1]):
        target = tokens[index + 1]
        if token in _WRITE_REDIRECTS and target not in _CONTROL_OPERATORS:
            writes.append(target)
        elif token in _READ_REDIRECTS and target not in _CONTROL_OPERATORS:
            reads.append(target)
    return _unique(reads), _unique(writes)


def _plain_arguments(args: Sequence[str]) -> list[str]:
    result: list[str] = []
    skip_target = False
    for value in args:
        if skip_target:
            skip_target = False
            continue
        if value in _WRITE_REDIRECTS or value in _READ_REDIRECTS:
            skip_target = True
            continue
        if value and not value.startswith("-"):
            result.append(value)
    return result


def _paths_after_pattern(args: Sequence[str]) -> list[str]:
    values = _plain_arguments(args)
    return values[1:] if len(values) > 1 else []


def _network_targets(command: str, tokens: Sequence[str]) -> list[str]:
    urls = _URL_RE.findall(command)
    for value in tokens:
        if re.match(r"^[^@\s]+@[^:\s]+:.+", value):
            urls.append(value.split(":", 1)[0])
        elif re.match(r"^[^:\s]+:.+", value) and not value.startswith(("./", "../", "/")):
            host = value.split(":", 1)[0]
            if "." in host or host == "localhost":
                urls.append(host)
    return _unique(urls)


def _argument_after(args: Sequence[str], *options: str) -> list[str]:
    result: list[str] = []
    for index, value in enumerate(args[:-1]):
        if value in options:
            result.append(args[index + 1].removeprefix("@"))
    return _unique(result)


def _operation_description(action: str, effects: Mapping[str, list[str]]) -> str:
    reads = effects.get("reads", [])
    writes = effects.get("writes", [])
    network = effects.get("network", [])
    target = (reads or writes or network or [""])[0]
    if action == "read_file":
        return f"读取 {target or '指定文件'}，不会修改文件。"
    if action == "search":
        return f"在 {target or '当前工作区'} 中搜索文件或文本，不会主动修改文件。"
    if action == "run_tests":
        return "运行项目测试并收集结果；测试进程本身可能按项目配置创建缓存或临时文件。"
    if action == "inspect_vcs":
        return "查看版本库状态或差异，不会主动修改版本库。"
    if action == "modify_file":
        return f"修改 {target or '由命令指定的文件'}。"
    if action == "network_access":
        return f"访问网络目标 {target or '由命令指定的地址'}；数据可能离开本机。"
    if action == "upload_data":
        return f"读取本地数据并发送到 {network[0] if network else '外部网络目标'}。"
    if action == "delete_file":
        return f"删除 {target or '由命令指定的文件或目录'}，结果可能难以恢复。"
    if action == "change_permissions":
        return f"修改 {target or '指定对象'} 的权限或所有权。"
    if action == "run_process":
        return "启动本地进程执行任务；完整副作用取决于该程序的实现。"
    return "系统暂时无法判断该命令的完整副作用，请查看原始命令和审批范围。"


def _explain_operation(operation: Mapping[str, Any]) -> dict[str, Any]:
    tokens = [str(value) for value in operation.get("tokens", [])]
    executable, args = _command_start(tokens)
    reads, writes = _redirect_effects(tokens)
    network = _network_targets(str(operation.get("command") or ""), tokens)
    action = "unknown"
    risk_level = "warning"
    risk_reasons: list[str] = []

    if executable in {"cat", "head", "tail"}:
        action = "read_file"
        candidates = _plain_arguments(args)
        if executable in {"head", "tail"}:
            candidates = [value for value in candidates if not value.isdigit()]
        reads.extend(candidates)
        risk_level = "low"
    elif executable == "sed":
        if any(value == "-i" or value.startswith("-i") for value in args):
            action = "modify_file"
            candidates = _plain_arguments(args)
            if candidates:
                writes.append(candidates[-1])
            risk_level = "warning"
            risk_reasons.append("命令会原地修改文件")
        else:
            action = "read_file"
            candidates = _plain_arguments(args)
            if candidates:
                reads.append(candidates[-1])
            risk_level = "low"
    elif executable in {"rg", "grep", "find", "fd", "locate"}:
        action = "search"
        if executable == "find":
            values = _plain_arguments(args)
            reads.append(values[0] if values else ".")
        else:
            reads.extend(_paths_after_pattern(args) or ["."])
        risk_level = "low"
    elif executable in {"pytest", "py.test", "unittest"} or (
        executable in {"python", "python3"}
        and len(args) >= 2
        and args[0] == "-m"
        and args[1] in {"pytest", "unittest"}
    ) or (
        executable == "npm"
        and (args[:1] == ["test"] or args[:2] == ["run", "test"])
    ):
        action = "run_tests"
        reads.extend(_plain_arguments(args))
        risk_level = "low"
    elif executable == "git" and args[:1] and args[0] in {"status", "diff", "show", "log"}:
        action = "inspect_vcs"
        reads.append(".git")
        risk_level = "low"
    elif executable == "apply_patch":
        action = "modify_file"
        writes.append("补丁指定的工作区文件")
        risk_level = "warning"
        risk_reasons.append("补丁会修改工作区文件")
    elif executable in {"curl", "wget", "scp"}:
        upload_paths = _argument_after(
            args,
            "--data",
            "--data-binary",
            "--data-raw",
            "--upload-file",
            "-T",
        )
        upload_paths.extend(
            value.removeprefix("@")
            for value in args
            if value.startswith("@") and len(value) > 1
        )
        if executable == "scp":
            plain = _plain_arguments(args)
            remote_indexes = {
                index
                for index, value in enumerate(plain)
                if ":" in value and not value.startswith(("./", "../", "/"))
            }
            if remote_indexes and max(remote_indexes) == len(plain) - 1:
                upload_paths.extend(plain[: max(remote_indexes)])
        reads.extend(upload_paths)
        if upload_paths:
            action = "upload_data"
            risk_level = "high"
            risk_reasons.extend(["命令读取本地数据", "命令向网络目标发送数据"])
        else:
            action = "network_access"
            risk_level = "warning"
            risk_reasons.append("命令访问网络")
            if executable == "wget" or "-o" in [value.lower() for value in args]:
                writes.extend(_argument_after(args, "-O", "--output-document"))
    elif executable in {"rm", "unlink", "rmdir", "shred"}:
        action = "delete_file"
        writes.extend(_plain_arguments(args))
        risk_level = "high"
        risk_reasons.append("命令会删除文件或目录")
    elif executable in {"chmod", "chown", "chgrp"}:
        action = "change_permissions"
        values = _plain_arguments(args)
        writes.extend(values[1:] if len(values) > 1 else values)
        risk_level = "high"
        risk_reasons.append("命令会修改权限或所有权")
    elif executable:
        action = "run_process"
        risk_level = "warning"
        risk_reasons.append("程序副作用尚未登记")
    else:
        risk_reasons.append("命令无法可靠解析")

    if writes:
        if action in {"read_file", "search", "inspect_vcs"}:
            action = "modify_file"
        if risk_level == "low":
            risk_level = "warning"
        risk_reasons.append("命令包含文件写入或输出重定向")
    if network and action not in {"upload_data", "network_access"}:
        risk_level = "warning" if risk_level == "low" else risk_level
        risk_reasons.append("参数包含网络目标")

    effects = {
        "reads": _unique(reads),
        "writes": _unique(writes),
        "network": _unique(network),
        "processes": _unique([executable] if executable else []),
    }
    return {
        "action": action,
        "command": redact_text(str(operation.get("command") or "")),
        "operator": operation.get("operator"),
        "description": _operation_description(action, effects),
        "effects": effects,
        "risk": {
            "level": risk_level,
            "reasons": _unique(risk_reasons),
            "basis": "deterministic_command_analysis",
        },
        "recognized": action not in {"unknown", "run_process"},
    }


def _dominant_operation(operations: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    rank = {
        "upload_data": 90,
        "delete_file": 80,
        "change_permissions": 75,
        "modify_file": 70,
        "network_access": 60,
        "run_tests": 50,
        "search": 40,
        "read_file": 30,
        "inspect_vcs": 25,
        "run_process": 10,
        "unknown": 0,
    }
    return max(operations, key=lambda value: rank.get(str(value.get("action")), 0))


def _headline(action: str, effects: Mapping[str, Sequence[str]]) -> str:
    ordered_targets = (
        effects.get("writes") or effects.get("reads") or effects.get("network") or []
        if action in {"modify_file", "delete_file", "change_permissions"}
        else effects.get("reads") or effects.get("network") or effects.get("writes") or []
    )
    target = next(iter(ordered_targets), "")
    short_target = _basename(str(target)) if target else ""
    labels = {
        "read_file": "读取文件",
        "search": "搜索代码与文件",
        "run_tests": "运行项目测试",
        "inspect_vcs": "查看版本状态",
        "modify_file": "修改文件",
        "network_access": "访问外部网络",
        "upload_data": "向外部服务发送数据",
        "delete_file": "删除文件或目录",
        "change_permissions": "修改权限或所有权",
        "run_process": "运行本地程序",
        "unknown": "执行未登记命令",
    }
    base = labels.get(action, "执行命令")
    if short_target and action in {"read_file", "modify_file", "delete_file"}:
        return f"{base} · {short_target}"
    return base


def _default_purpose(action: str) -> str:
    return {
        "read_file": "核对当前任务涉及的文件内容",
        "search": "定位与当前任务相关的代码或文件",
        "run_tests": "验证当前实现是否符合预期",
        "inspect_vcs": "确认工作区已有修改和影响范围",
        "modify_file": "落实当前任务需要的代码修改",
        "network_access": "获取完成当前任务所需的外部数据",
        "upload_data": "将本地数据发送给命令指定的外部服务",
        "delete_file": "移除命令指定的文件或目录",
        "change_permissions": "调整命令指定对象的访问权限",
        "run_process": "运行完成当前任务所需的本地程序",
        "unknown": "完成当前任务中的一个执行步骤",
    }.get(action, "完成当前任务")


def explain_command(
    command: str,
    *,
    cwd: str | None = None,
    purpose: str | None = None,
    purpose_source: str | None = None,
    status: str | None = None,
    result: Mapping[str, Any] | None = None,
    policy_risk: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the stable explanation contract for one shell command."""

    parsed = [_explain_operation(value) for value in split_shell_operations(command)]
    dominant = _dominant_operation(parsed)
    effects = {
        key: _unique(
            value
            for operation in parsed
            for value in operation.get("effects", {}).get(key, [])
        )
        for key in ("reads", "writes", "network", "processes")
    }
    levels = {"low": 0, "normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}
    risk = max(
        (operation["risk"] for operation in parsed),
        key=lambda value: levels.get(str(value.get("level")), 2),
    )
    risk = {
        "level": risk.get("level", "warning"),
        "reasons": _unique(
            reason
            for operation in parsed
            for reason in operation.get("risk", {}).get("reasons", [])
        ),
        "basis": "deterministic_command_analysis",
    }
    if policy_risk:
        policy_level = str(policy_risk.get("level") or "")
        if levels.get(policy_level, -1) > levels.get(str(risk["level"]), -1):
            risk["level"] = policy_level
        risk["reasons"] = _unique(
            [*risk["reasons"], *[str(value) for value in policy_risk.get("reasons", [])]]
        )
        if policy_risk.get("basis"):
            risk["additional_basis"] = str(policy_risk["basis"])
        for key in ("matched_rules", "blocking_rule", "policy_id"):
            if policy_risk.get(key):
                risk[key] = redact_event(policy_risk[key])

    action = str(dominant.get("action") or "unknown")
    explicit_purpose = redact_text(purpose.strip()) if purpose and purpose.strip() else None
    source = purpose_source or ("agent_plan" if explicit_purpose else "contextual_inference")
    result_value = dict(result or {})
    result_summary = _result_summary(result_value, status=status)
    recognized = all(bool(value.get("recognized")) for value in parsed)
    description = " ".join(str(value["description"]) for value in parsed)
    if len(parsed) > 1:
        description = f"该命令包含 {len(parsed)} 个子操作：{description}"
    policy_decision = bool(
        policy_risk
        and (
            policy_risk.get("blocking_rule")
            or policy_risk.get("policy_id")
            or str(policy_risk.get("basis") or "").startswith("codexscope_policy")
        )
    )
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "headline": _headline(action, effects),
        "action": action,
        "description": description,
        "purpose": {
            "text": explicit_purpose or _default_purpose(action),
            "source": source,
            "confidence": "declared" if source == "agent_plan" else "contextual",
        },
        "effects": effects,
        "risk": risk,
        "result": result_summary,
        "suboperations": parsed,
        "sources": _unique(
            [
                "deterministic_command_analysis",
                source,
                *( ["codex_app_server"] if result_value or status else [] ),
                *( ["security_policy"] if policy_decision else [] ),
            ]
        ),
        "conservative_fallback": not recognized,
        "cwd": redact_text(cwd) if cwd else None,
    }


def _result_summary(result: Mapping[str, Any], *, status: str | None = None) -> dict[str, Any]:
    exit_code = result.get("exit_code", result.get("exitCode"))
    duration_ms = result.get("duration_ms", result.get("durationMs"))
    output = result.get("output", result.get("aggregatedOutput"))
    output_text = str(output or "")
    lines = len(output_text.splitlines()) if output_text else 0
    normalized_status = str(status or result.get("status") or "unknown")
    parts: list[str] = []
    if exit_code is not None:
        parts.append(f"退出码 {exit_code}")
    if isinstance(duration_ms, (int, float)):
        parts.append(f"耗时 {duration_ms:g}ms")
    if lines:
        parts.append(f"输出 {lines} 行")
    if not parts:
        parts.append({"running": "命令正在运行", "started": "命令已启动"}.get(normalized_status, "暂无结果摘要"))
    return {
        "status": normalized_status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "output_lines": lines,
        "summary": " · ".join(parts),
    }


_TOOL_CAPABILITIES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = (
    (
        re.compile(
            r"lingmou[-_]workbuddy.*(?:mail_list|document_get|meeting_list|expense_list|inventory_get|sales_query|action_status)",
            re.IGNORECASE,
        ),
        {
            "headline": "读取 WorkBuddy 业务沙箱",
            "description": "通过本 Run 的本地 MCP 网关读取模拟业务状态，不产生业务副作用。",
            "capability": "workbuddy-read",
            "network": False,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"lingmou[-_]workbuddy.*_prepare", re.IGNORECASE),
        {
            "headline": "准备 WorkBuddy 办公动作",
            "description": "只固化请求并预览后果；真正的业务副作用尚未执行。",
            "capability": "workbuddy-prepare",
            "network": False,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"lingmou[-_]workbuddy.*_commit", re.IGNORECASE),
        {
            "headline": "提交 WorkBuddy 办公动作",
            "description": "由本地事务网关重新判策，并在允许或一次性批准后执行办公副作用。",
            "capability": "workbuddy-commit",
            "network": False,
            "external_write": True,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"(?:^|[._/])(?:view_image|imageview)(?:$|[._/])", re.IGNORECASE),
        {
            "headline": "查看本地图片",
            "description": "读取并展示本机图片，不会主动修改文件。",
            "capability": "filesystem-read",
            "network": False,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"(?:websearch|web__run|search_query|open_url)", re.IGNORECASE),
        {
            "headline": "查询外部信息",
            "description": "通过网络检索或读取外部网页。",
            "capability": "network-read",
            "network": True,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"(?:imagegeneration|image_gen|imagegen)", re.IGNORECASE),
        {
            "headline": "调用图片生成服务",
            "description": "将提示或引用图片发送给图片生成服务，并接收生成结果。",
            "capability": "network-generate",
            "network": True,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"(?:apply_patch|write_file|edit_file)", re.IGNORECASE),
        {
            "headline": "修改工作区文件",
            "description": "按工具参数修改工作区中的文件。",
            "capability": "filesystem-write",
            "network": False,
            "external_write": False,
            "filesystem_write": True,
        },
    ),
    (
        re.compile(r"(?:collab|subagent|spawn_agent|send_message|followup_task)", re.IGNORECASE),
        {
            "headline": "调用协作 Agent",
            "description": "把限定任务交给协作 Agent 或向其发送消息。",
            "capability": "agent-coordination",
            "network": False,
            "external_write": False,
            "filesystem_write": False,
        },
    ),
    (
        re.compile(r"(?:github|create_issue|create_pull|merge_pull|send_email)", re.IGNORECASE),
        {
            "headline": "调用外部服务工具",
            "description": "通过网络读取或修改已连接的外部服务。",
            "capability": "external-write",
            "network": True,
            "external_write": True,
            "filesystem_write": False,
        },
    ),
)


def _safe_tool_arguments(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if _SENSITIVE_KEY_RE.search(key):
        return "[已隐藏敏感参数]"
    if depth >= 4:
        return "[内容层级过深，已省略]"
    if isinstance(value, Mapping):
        return {
            str(item_key): _safe_tool_arguments(
                item_value,
                key=str(item_key),
                depth=depth + 1,
            )
            for item_key, item_value in list(value.items())[:32]
        }
    if isinstance(value, list):
        return [_safe_tool_arguments(item, key=key, depth=depth + 1) for item in value[:32]]
    if isinstance(value, str):
        return redact_text(value[:2_000])
    return value


def explain_tool(
    item: Mapping[str, Any],
    *,
    item_type: str,
    status: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    server = str(item.get("server") or item.get("serverName") or "")
    tool = str(item.get("tool") or item.get("toolName") or item_type)
    identity = "/".join(value for value in (server, tool, item_type) if value)
    declaration: dict[str, Any] | None = None
    for pattern, value in _TOOL_CAPABILITIES:
        if pattern.search(identity):
            declaration = dict(value)
            break
    known = declaration is not None
    declaration = declaration or {
        "headline": "调用未登记工具",
        "description": "副作用尚未登记，请在批准前检查工具参数。",
        "capability": "unknown",
        "network": None,
        "external_write": None,
        "filesystem_write": None,
    }
    arguments = item.get("arguments", item.get("params", item.get("input", {})))
    result = item.get("result", item.get("output"))
    result_text = str(result or "")
    risk_level = (
        "warning"
        if not known or declaration["network"] or declaration["filesystem_write"]
        else "low"
    )
    if declaration["external_write"]:
        risk_level = "high"
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "headline": declaration["headline"],
        "action": "tool_call",
        "description": declaration["description"],
        "purpose": {
            "text": redact_text(purpose) if purpose else "完成当前任务所需的工具步骤",
            "source": "agent_plan" if purpose else "contextual_inference",
            "confidence": "declared" if purpose else "contextual",
        },
        "tool": {
            "server": redact_text(server) if server else None,
            "name": redact_text(tool),
            "capability": declaration["capability"],
            "side_effects_registered": known,
            "non_sensitive_arguments": _safe_tool_arguments(arguments),
        },
        "effects": {
            "reads": [],
            "writes": ["由工具参数决定"] if declaration["filesystem_write"] else [],
            "network": ["工具声明需要网络"] if declaration["network"] else [],
            "processes": [],
            "external_write": declaration["external_write"],
        },
        "risk": {
            "level": risk_level,
            "reasons": (
                ["工具能力或副作用尚未登记"]
                if not known
                else [
                    value
                    for value, enabled in (
                        ("数据会离开本机", declaration["network"]),
                        ("工具可能修改本地文件", declaration["filesystem_write"]),
                        ("工具可能修改外部状态", declaration["external_write"]),
                    )
                    if enabled
                ]
            ),
            "basis": "tool_capability_registry" if known else "conservative_fallback",
        },
        "result": {
            "status": status or str(item.get("status") or "unknown"),
            "summary": (
                f"工具返回 {len(result_text.splitlines())} 行文本"
                if result_text
                else "暂无结果摘要"
            ),
        },
        "sources": _unique(
            [
                "tool_capability_registry" if known else "conservative_fallback",
                "codex_app_server",
                "agent_plan" if purpose else "contextual_inference",
            ]
        ),
        "conservative_fallback": not known,
    }


def explain_file_change(
    changes: Sequence[Mapping[str, Any]],
    *,
    status: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    paths = _unique(str(change.get("path") or "") for change in changes)
    operations = _unique(
        str(change.get("kind") or change.get("type") or "modify") for change in changes
    )
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "headline": f"修改 {len(paths)} 个文件" if paths else "修改工作区文件",
        "action": "file_change",
        "description": (
            f"Agent 请求或完成了对 {len(paths)} 个工作区文件的修改。"
            if paths
            else "Agent 请求或完成了文件修改；具体路径未由协议提供。"
        ),
        "purpose": {
            "text": redact_text(purpose) if purpose else "落实当前任务所需的文件修改",
            "source": "agent_plan" if purpose else "contextual_inference",
            "confidence": "declared" if purpose else "contextual",
        },
        "effects": {
            "reads": [],
            "writes": paths,
            "network": [],
            "processes": [],
        },
        "risk": {
            "level": "warning",
            "reasons": ["操作会修改工作区文件"],
            "basis": "deterministic_file_change_analysis",
        },
        "result": {
            "status": status or "unknown",
            "summary": f"涉及 {len(paths)} 个文件" if paths else "文件路径未提供",
            "operations": operations,
        },
        "sources": _unique(
            [
                "codex_app_server",
                "deterministic_file_change_analysis",
                "agent_plan" if purpose else "contextual_inference",
            ]
        ),
        "conservative_fallback": not bool(paths),
    }


def empty_evidence(
    *,
    turn_id: str | None = None,
    item_id: str | None = None,
    reason: str = "暂无 OS 级证据",
) -> dict[str, Any]:
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "availability": "unavailable",
        "completeness": "none",
        "summary": reason,
        "observations": [],
        "negative_observations": [],
        "correlation": {
            "turn_id": turn_id,
            "item_id": item_id,
            "pid": None,
            "ppid": None,
            "started_at": None,
            "ended_at": None,
            "source": None,
            "confidence": "none",
        },
    }


def policy_block_evidence(
    *,
    turn_id: str | None,
    item_id: str | None,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "availability": "pre_execution",
        "completeness": "complete",
        "summary": "策略在进程启动前返回拒绝，命令未进入执行阶段。",
        "observations": [
            {
                "kind": "policy_decision",
                "label": "执行前策略已拒绝该命令",
                "source": "security_policy",
                "turn_id": turn_id,
                "item_id": item_id,
                "pid": None,
                "ppid": None,
                "file_path": None,
                "network_target": None,
                "syscall": None,
                "correlation_confidence": "exact",
                "policy_id": policy.get("policy_id"),
                "blocking_rule": policy.get("blocking_rule"),
                "matched_rules": policy.get("matched_rules") or [],
            },
            {
                "kind": "execution_state",
                "label": "进程未启动（执行前阻断证据）",
                "source": "security_policy",
                "turn_id": turn_id,
                "item_id": item_id,
                "pid": None,
                "ppid": None,
                "file_path": None,
                "network_target": None,
                "syscall": None,
                "correlation_confidence": "exact",
            },
        ],
        "negative_observations": [],
        "correlation": {
            "turn_id": turn_id,
            "item_id": item_id,
            "pid": None,
            "ppid": None,
            "started_at": None,
            "ended_at": None,
            "source": "codexscope_policy",
            "confidence": "exact",
        },
    }


def _tail_json_objects(path: Path, *, limit: int = 20_000) -> list[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            lines = source.readlines()[-limit:]
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _timestamp_seconds(row: Mapping[str, Any]) -> float | None:
    value = row.get("wall_time_ns")
    if isinstance(value, int):
        return value / 1_000_000_000
    value = row.get("wall_time")
    if isinstance(value, (int, float)):
        return float(value)
    return None


def collect_command_evidence(
    run_dir: Path | str,
    *,
    turn_id: str | None,
    item_id: str | None,
    process_id: str | int | None,
    started_at: float | None,
    ended_at: float | None,
    exit_code: int | None = None,
) -> dict[str, Any]:
    """Aggregate real Linux audit rows for a completed command.

    Exact PID/process-tree matches are preferred.  Time-only rows are never
    presented as facts because concurrent Agent commands could otherwise be
    attributed to the wrong item.
    """

    path = Path(run_dir).expanduser().resolve() / "raw" / "os_audit.jsonl"
    if not path.is_file():
        return empty_evidence(turn_id=turn_id, item_id=item_id)
    rows = _tail_json_objects(path)
    if not rows:
        return empty_evidence(
            turn_id=turn_id,
            item_id=item_id,
            reason="OS 审计已启用，但当前没有可用记录",
        )
    try:
        root_pid = int(process_id) if process_id is not None else None
    except (TypeError, ValueError):
        root_pid = None
    if root_pid is None:
        evidence = empty_evidence(
            turn_id=turn_id,
            item_id=item_id,
            reason="OS 审计存在，但命令没有可用于关联的 PID",
        )
        evidence["availability"] = "available_unassociated"
        evidence["correlation"]["source"] = "linux_strace"
        return evidence

    window_rows: list[dict[str, Any]] = []
    for row in rows:
        timestamp = _timestamp_seconds(row)
        if started_at is not None and timestamp is not None and timestamp < started_at - 1.0:
            continue
        if ended_at is not None and timestamp is not None and timestamp > ended_at + 1.0:
            continue
        window_rows.append(row)
    matched_pids = {root_pid}
    changed = True
    while changed:
        changed = False
        for row in window_rows:
            pid = row.get("pid")
            ppid = row.get("ppid")
            if isinstance(pid, int) and isinstance(ppid, int) and ppid in matched_pids and pid not in matched_pids:
                matched_pids.add(pid)
                changed = True
    matched = [row for row in window_rows if row.get("pid") in matched_pids]
    if not matched:
        evidence = empty_evidence(
            turn_id=turn_id,
            item_id=item_id,
            reason="OS 审计存在，但没有找到与该 PID 匹配的记录",
        )
        evidence["availability"] = "available_unassociated"
        evidence["correlation"].update(
            {"pid": root_pid, "source": "linux_strace", "confidence": "none"}
        )
        return evidence

    observations: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    observed_writes = False
    observed_network = False
    meaningful = {
        "execve",
        "execveat",
        "open",
        "openat",
        "openat2",
        "read",
        "write",
        "connect",
        "sendto",
        "sendmsg",
        "rename",
        "renameat",
        "renameat2",
        "unlink",
        "unlinkat",
        "chmod",
        "fchmod",
        "chown",
        "fchown",
    }
    for row in matched:
        syscall = str(row.get("syscall") or "")
        if syscall not in meaningful or row.get("success") is False:
            continue
        access = str(row.get("access") or "")
        file_path = str(row.get("path") or "") or None
        network_target = str(row.get("endpoint") or "") or None
        if syscall in {"connect", "sendto", "sendmsg"}:
            kind = "network"
            observed_network = True
            label = {
                "connect": "尝试建立网络连接",
                "sendto": "向网络目标发送数据",
                "sendmsg": "向网络目标发送数据",
            }[syscall]
        elif syscall in {"execve", "execveat"}:
            kind = "process"
            label = f"启动 {file_path or row.get('comm') or '本地进程'}"
        elif syscall in {"unlink", "unlinkat"}:
            kind = "file_delete"
            observed_writes = True
            label = "删除文件"
        elif syscall.startswith("rename"):
            kind = "file_move"
            observed_writes = True
            label = "移动或替换文件"
        elif syscall in {"chmod", "fchmod", "chown", "fchown"}:
            kind = "permission_change"
            observed_writes = True
            label = "修改文件权限或所有权"
        elif access in {"write", "metadata_write"} or syscall == "write":
            kind = "file_write"
            observed_writes = True
            label = "打开或写入文件"
        elif access in {"read", "metadata_read"} or syscall == "read":
            kind = "file_read"
            label = "以只读方式访问文件"
        else:
            continue
        key = (kind, row.get("pid"), file_path, network_target)
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            {
                "kind": kind,
                "label": label,
                "source": "os_observation",
                "turn_id": turn_id,
                "item_id": item_id,
                "pid": row.get("pid"),
                "ppid": row.get("ppid"),
                "observed_at": _timestamp_seconds(row),
                "file_path": redact_text(file_path) if file_path else None,
                "network_target": redact_text(network_target) if network_target else None,
                "syscall": syscall,
                "correlation_confidence": (
                    "exact_pid" if row.get("pid") == root_pid else "process_tree"
                ),
            }
        )
    observations.append(
        {
            "kind": "process_exit",
            "label": f"进程已退出，退出码 {exit_code}" if exit_code is not None else "命令生命周期已结束",
            "source": "codex_app_server",
            "turn_id": turn_id,
            "item_id": item_id,
            "pid": root_pid,
            "ppid": next((row.get("ppid") for row in matched if row.get("pid") == root_pid), None),
            "observed_at": ended_at,
            "file_path": None,
            "network_target": None,
            "syscall": None,
            "correlation_confidence": "exact_item",
        }
    )
    negative: list[dict[str, str]] = []
    if not observed_writes:
        negative.append(
            {
                "label": "在已关联的 OS 审计记录中未观察到文件写入",
                "source": "os_observation",
                "scope": "matched_process_tree",
            }
        )
    if not observed_network:
        negative.append(
            {
                "label": "在已关联的 OS 审计记录中未观察到网络连接",
                "source": "os_observation",
                "scope": "matched_process_tree",
            }
        )
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "availability": "available",
        "completeness": "partial",
        "summary": f"关联到 {len(matched)} 条 OS 记录，聚合为 {len(observations)} 项证据",
        "observations": observations,
        "negative_observations": negative,
        "correlation": {
            "turn_id": turn_id,
            "item_id": item_id,
            "pid": root_pid,
            "ppid": next((row.get("ppid") for row in matched if row.get("pid") == root_pid), None),
            "started_at": started_at,
            "ended_at": ended_at,
            "source": "linux_strace+codex_app_server",
            "confidence": "exact_pid_or_process_tree",
        },
    }


__all__ = [
    "EXPLANATION_SCHEMA_VERSION",
    "collect_command_evidence",
    "empty_evidence",
    "explain_command",
    "explain_file_change",
    "explain_tool",
    "policy_block_evidence",
    "split_shell_operations",
]
