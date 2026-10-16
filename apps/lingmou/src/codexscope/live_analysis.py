"""Incremental analysis coordination for the live security console.

Local explainable analyzers provide an immediate pre-filter and safe fallback.
When configured, four asynchronous Codex-backed roles replace that pre-filter
with grounded model analysis without blocking dashboard polling.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

ANALYSIS_SCHEMA_VERSION = "lingmou.live-analysis.v1"
_LEVEL_RANK = {"normal": 0, "notice": 1, "warning": 2, "high": 3, "critical": 4}
_RANK_LEVEL = {value: key for key, value in _LEVEL_RANK.items()}


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _events(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = payload.get("events")
    if not isinstance(raw, list):
        return []
    return [event for event in raw if isinstance(event, Mapping)]


def _analysis_events(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return behavior-bearing events and suppress routine syscall churn.

    Command, approval, tool and filesystem events carry useful task semantics.
    The syscall stream is much noisier, so normal process launches and ordinary
    reads are retained in raw monitoring but excluded from model revisions.
    Risky, blocked or policy-linked syscalls remain available as evidence.
    """

    selected: list[Mapping[str, Any]] = []
    for event in _events(payload):
        source = str(event.get("source") or "")
        kind = str(event.get("kind") or "")
        raw_hits = event.get("policy_hits")
        has_policy_hits = isinstance(raw_hits, list) and any(
            isinstance(hit, Mapping) for hit in raw_hits
        )
        if source == "linux_strace" or kind == "syscall":
            if (
                _risk_rank(event) == 0
                and not bool(event.get("blocked"))
                and not has_policy_hits
            ):
                continue
        selected.append(event)
    return selected


def _chronological(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return sorted(
        _analysis_events(payload),
        key=lambda event: (
            float(event.get("timestamp") or 0.0),
            str(event.get("id") or ""),
        ),
    )


def _event_id(event: Mapping[str, Any]) -> str:
    return str(event.get("id") or "unknown-event")[:256]


def _risk_level(event: Mapping[str, Any]) -> str:
    risk = event.get("risk")
    risk = risk if isinstance(risk, Mapping) else {}
    level = str(risk.get("level") or "normal").lower()
    return level if level in _LEVEL_RANK else "normal"


def _risk_rank(event: Mapping[str, Any]) -> int:
    return _LEVEL_RANK[_risk_level(event)]


def _event_text(event: Mapping[str, Any]) -> str:
    risk = event.get("risk")
    risk = risk if isinstance(risk, Mapping) else {}
    reasons = risk.get("reasons")
    reasons = reasons if isinstance(reasons, list) else []
    technical = event.get("technical")
    technical = technical if isinstance(technical, Mapping) else {}
    hits = event.get("policy_hits")
    hits = hits if isinstance(hits, list) else []
    values: list[object] = [
        event.get("source"),
        event.get("kind"),
        event.get("action"),
        event.get("detail"),
        event.get("target"),
        technical.get("syscall"),
        technical.get("operation"),
        technical.get("blocking_rule"),
        *reasons,
    ]
    for hit in hits:
        if isinstance(hit, Mapping):
            values.extend((hit.get("id"), hit.get("name"), hit.get("action")))
    return " ".join(str(value) for value in values if value is not None).casefold()


def _contains(event: Mapping[str, Any], *terms: str) -> bool:
    text = _event_text(event)
    return any(term.casefold() in text for term in terms)


def _policy_ids(event: Mapping[str, Any]) -> list[str]:
    raw = event.get("policy_hits")
    raw = raw if isinstance(raw, list) else []
    result: list[str] = []
    for hit in raw:
        if not isinstance(hit, Mapping):
            continue
        policy_id = str(hit.get("id") or "").strip()
        if policy_id and policy_id not in result:
            result.append(policy_id[:128])
    return result


def _stage(event: Mapping[str, Any]) -> str:
    if bool(event.get("blocked")):
        return "blocked"
    status = str(event.get("status") or "completed").lower()
    if status == "review":
        return "review"
    if status == "failed":
        return "failed"
    if status == "running":
        return "requested"
    return "executed"


def _recommended_action(level: str, *, blocked: bool = False) -> str:
    if blocked:
        return "observe"
    return {
        "critical": "isolate",
        "high": "block",
        "warning": "review",
        "notice": "warn",
        "normal": "observe",
    }.get(level, "observe")


def _agent_result(agent_id: str, name: str, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "name": name,
        "status": "ready",
        "mode": "local_explainable",
        **body,
    }


class LiveAnalysisAgent(Protocol):
    agent_id: str
    name: str

    def analyze(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        dependencies: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...


class LiveAnalysisBackend(Protocol):
    provider: str
    mode: str
    model: str

    def analyze(
        self,
        agent_id: str,
        agent_name: str,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        fallback: Mapping[str, Any],
    ) -> dict[str, Any]: ...

    def describe(self) -> dict[str, Any]: ...

    def close(self) -> None: ...


class BehaviorPredictionAgent:
    agent_id = "behavior_prediction"
    name = "行为分析与预测"

    def analyze(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        dependencies: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        events = _chronological(payload)
        normal = [event for event in events if _risk_rank(event) <= 1 and not event.get("blocked")]
        risky = [event for event in events if _risk_rank(event) >= 2 or event.get("blocked")]
        action_counts = Counter(str(event.get("action") or "未知行为") for event in normal)
        source_counts = Counter(str(event.get("source") or "unknown") for event in normal)
        targets = [str(event.get("target")) for event in normal if event.get("target")]

        sensitive = [event for event in events if _contains(event, "secret", ".env", "credential", "凭证", "密钥", "敏感路径")]
        encoding = [event for event in events if _contains(event, "base64", "openssl enc", "tar -", "编码前兆")]
        network = [event for event in events if event.get("kind") == "network" or _contains(event, "curl ", "wget ", "connect", "sendto", "http://", "https://")]
        upload = [event for event in events if _contains(event, "--data", "--upload-file", "外部上传", "数据上传", "exfil")]
        scan = [event for event in events if _contains(event, "nmap", "masscan", "端口扫描", "连续端口", "内网探测")]
        persistence = [event for event in events if _contains(event, "authorized_keys", "crontab", "systemd", "开机自启", "持久化")]
        memory = [event for event in events if _contains(event, "ptrace", "mprotect", "process_vm_writev", "rwx", "内存注入")]
        destructive = [event for event in events if _contains(event, "rm -rf", "unlink", "mkfs", "删除文件", "高破坏性", "Git 工作区或历史破坏性变更", "停用主机安全控制")]

        def chain_ids(*chain_events: Mapping[str, Any]) -> list[str]:
            ordered = sorted(
                chain_events,
                key=lambda event: (
                    float(event.get("timestamp") or 0.0),
                    _event_id(event),
                ),
            )
            return list(dict.fromkeys(_event_id(event) for event in ordered))

        first_sensitive = sensitive[0] if sensitive else None

        patterns: list[dict[str, Any]] = []
        if sensitive:
            patterns.append(
                {
                    "pattern": "敏感资源访问",
                    "evidence_event_ids": [_event_id(event) for event in sensitive[-4:]],
                    "confidence": "high",
                }
            )
        if sensitive and encoding:
            patterns.append(
                {
                    "pattern": "敏感资源读取 → 内容编码",
                    "evidence_event_ids": chain_ids(first_sensitive, encoding[-1]),
                    "confidence": "high",
                }
            )
        if sensitive and network:
            patterns.append(
                {
                    "pattern": "敏感资源访问 → 网络出口",
                    "evidence_event_ids": chain_ids(first_sensitive, network[-1]),
                    "confidence": "high" if upload else "medium",
                }
            )
        if sensitive and upload:
            patterns.append(
                {
                    "pattern": "敏感资源访问 → 数据上传/外泄尝试",
                    "evidence_event_ids": chain_ids(first_sensitive, upload[-1]),
                    "confidence": "high",
                }
            )

        anomalies = [
            {
                "description": str(event.get("action") or "异常行为"),
                "target": str(event.get("target") or ""),
                "evidence_event_ids": [_event_id(event)],
                "risk_level": _risk_level(event),
                "stage": _stage(event),
                "confidence": "high" if event.get("blocked") or _risk_rank(event) >= 3 else "medium",
                "reason": "、".join(
                    str(value)
                    for value in (
                        (event.get("risk") or {}).get("reasons", [])
                        if isinstance(event.get("risk"), Mapping)
                        else []
                    )
                )[:320],
                "recommendation": (
                    "核对阻断证据并监控是否出现变体重试"
                    if event.get("blocked")
                    else "关联检查同一目标的后续工具、文件和 syscall 事件"
                ),
                "triggered_policy_ids": _policy_ids(event),
            }
            for event in risky[-8:]
        ]

        if any(event.get("blocked") for event in events):
            current_stage = "高风险行为已被阻断"
        elif upload:
            current_stage = "数据外发尝试"
        elif destructive:
            current_stage = "破坏性操作"
        elif memory:
            current_stage = "进程或内存操作"
        elif persistence:
            current_stage = "持久化准备"
        elif scan:
            current_stage = "网络侦察"
        elif encoding:
            current_stage = "敏感内容处理"
        elif sensitive:
            current_stage = "敏感信息收集"
        elif events:
            current_stage = "正常任务执行"
        else:
            current_stage = "等待行为事件"

        predictions: list[dict[str, Any]] = []

        def predict(
            behavior: str,
            probability: float,
            level: str,
            evidence: Sequence[Mapping[str, Any]],
            tools: Sequence[str],
            targets_: Sequence[str],
            control: str,
            reasoning: str,
        ) -> None:
            if any(item["predicted_behavior"] == behavior for item in predictions):
                return
            predictions.append(
                {
                    "predicted_behavior": behavior,
                    "probability": round(probability, 2),
                    "confidence": "high" if probability >= 0.75 else "medium" if probability >= 0.45 else "low",
                    "evidence_event_ids": [_event_id(event) for event in evidence[-4:]],
                    "likely_tools": list(tools),
                    "likely_targets": list(targets_),
                    "risk_level": level,
                    "recommended_control": control,
                    "reasoning": reasoning,
                }
            )

        if sensitive and encoding and not upload:
            predict("尝试通过网络工具发送已读取的敏感数据", 0.84, "critical", [*sensitive, *encoding], ["curl", "wget", "scp"], ["外部网络目标"], "block", "已连续观察到敏感资源访问与内容编码，但尚未看到上传结果。")
        elif sensitive and not encoding and not upload:
            predict("对敏感内容进行编码、压缩或分段处理", 0.68, "high", sensitive, ["base64", "openssl", "tar"], ["已读取的敏感文件"], "review", "已观察到敏感路径访问，内容转换常是后续转移或规避检测的前置步骤。")
        if scan:
            predict("继续探测相邻端口、服务或网络目标", 0.72, "high", scan, ["curl", "nmap", "nc"], ["相邻端口或内网地址"], "review", "已经出现侦察信号，连续枚举相邻目标是同类行为的常见延伸。")
        if persistence:
            predict("尝试继续修改持久化落点或其权限", 0.64, "high", persistence, ["shell", "chmod", "systemctl", "cron"], ["authorized_keys、启动项或认证文件"], "block", "已观察到 authorized_keys、计划任务或服务启动项相关事件，需要防止后续写入和权限放宽。")
        if any(event.get("blocked") for event in events):
            blocked_events = [event for event in events if event.get("blocked")]
            predict("更换参数、工具或目标后重试被拒绝的操作", 0.46, "high", blocked_events, ["替代工具"], ["原高风险目标"], "review", "存在明确阻断事件；当前没有重试证据，因此仅作为需要观察的低置信度预测。")
        if not predictions:
            predict("继续当前任务中的常规工具调用", 0.58 if events else 0.2, "normal", events[-3:], list(action_counts.keys())[:3], list(dict.fromkeys(targets))[:3], "observe", "当前事件尚未形成风险行为链，预测沿最近的常规操作继续。")
        predictions = predictions[:3]
        for rank, prediction in enumerate(predictions, start=1):
            prediction["rank"] = rank

        summary = (
            f"已分析 {len(events)} 条事件，当前阶段为“{current_stage}”；"
            f"发现 {len(anomalies)} 条异常证据，生成 {len(predictions)} 项下一步预测。"
        )
        return _agent_result(
            self.agent_id,
            self.name,
            {
                "analysis_type": "behavior_analysis_and_prediction",
                "current_stage": current_stage,
                "baseline_summary": {
                    "common_actions": [name for name, _count in action_counts.most_common(5)],
                    "common_sources": [name for name, _count in source_counts.most_common(5)],
                    "common_targets": list(dict.fromkeys(targets))[:8],
                    "normal_event_count": len(normal),
                },
                "observed_patterns": patterns,
                "anomalies": anomalies,
                "predictions": predictions,
                "new_event_count": new_event_count,
                "summary": summary,
            },
        )


class VulnerabilityBehaviorAgent:
    agent_id = "vulnerability_behavior"
    name = "漏洞行为识别"

    _DEFINITIONS = (
        ("reconnaissance", "环境、端口或服务侦察", ("nmap", "masscan", "端口扫描", "内网探测", "uname -a", "whoami", "id "), (), ("T1046",)),
        ("injection", "命令或解释器注入尝试", ("eval(", "exec(", "shell=true", "; /bin/sh", "| /bin/sh", "command injection"), ("CWE-78",), ("T1059",)),
        ("path_abuse", "路径穿越或敏感系统路径访问", ("../", "/etc/shadow", "/etc/passwd", "/proc/", "路径穿越"), ("CWE-22",), ("T1005",)),
        ("privilege_bypass", "权限提升或隔离绕过尝试", ("sudo ", "setuid", "capset", "chmod 777", "sandbox escape", "容器逃逸", "docker.sock", "--privileged", "nsenter"), ("CWE-269",), ("T1548",)),
        ("memory_exploitation", "进程附加或内存注入前兆", ("ptrace", "process_vm_writev", "mprotect", "rwx", "内存注入"), (), ("T1055",)),
        ("network_exploitation", "网络利用载荷或异常回连", ("reverse shell", "反向或交互式 shell", "nc -e", "bash -i", "/dev/tcp/", "漏洞载荷"), (), ("T1210",)),
        ("cloud_credential_access", "云凭证文件或实例身份访问", (".aws/", "aws_access_key_id", "云凭证", "169.254.169.254", "metadata.google.internal", "元数据凭证"), (), ("T1552.001",)),
        ("remote_script_execution", "远程脚本未经落盘核验直接执行", ("下载脚本直连解释器执行", "curl | sh", "wget | bash"), ("CWE-494",), ("T1059", "T1105")),
        ("source_control_destruction", "源码工作区或历史破坏", ("git reset --hard", "git clean -f", "git push --force", "git 工作区或历史破坏性变更"), (), ("T1070",)),
        ("security_control_disable", "主机安全控制被停用", ("setenforce 0", "ufw disable", "nft flush ruleset", "停用主机安全控制"), (), ("T1562.001",)),
        ("post_exploitation", "利用后凭证、持久化或防御规避行为", ("authorized_keys", "crontab", "systemd", ".github/workflows", ".git/hooks", "history -c", "truncate -s 0", "audit.log", "清除日志", "支付密钥外泄", "敏感数据外泄"), (), ("T1555", "T1547")),
    )

    def analyze(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        dependencies: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for event in _chronological(payload):
            text = _event_text(event)
            for category, behavior, terms, cwes, techniques in self._DEFINITIONS:
                matched = [term for term in terms if term.casefold() in text]
                if not matched:
                    continue
                stage = _stage(event)
                level = _risk_level(event)
                syscall_or_file = str(event.get("source") or "") in {"linux_strace", "linux_inotify"}
                impact_confirmed = syscall_or_file and stage == "executed" and category in {
                    "path_abuse",
                    "privilege_bypass",
                    "memory_exploitation",
                    "cloud_credential_access",
                    "post_exploitation",
                }
                findings.append(
                    {
                        "finding_id": f"VULN-{len(findings) + 1:03d}",
                        "category": category,
                        "behavior": behavior,
                        "stage": stage,
                        "target": str(event.get("target") or ""),
                        "evidence_event_ids": [_event_id(event)],
                        "matched_indicators": matched[:4],
                        "possible_cwe": list(cwes),
                        "possible_attack_techniques": list(techniques),
                        "severity": level,
                        "confidence": "high" if syscall_or_file or event.get("blocked") else "medium",
                        "impact_confirmed": impact_confirmed,
                        "false_positive_factors": ([] if syscall_or_file else ["当前主要证据来自命令或参数文本，需结合 syscall/文件结果确认"]),
                        "analysis": (
                            f"事件命中 {', '.join(matched[:4])}；目标为 {event.get('target') or '未识别'}，"
                            f"当前阶段为 {stage}，底层影响{'已有观察证据' if impact_confirmed else '尚未确认'}。"
                        ),
                        "recommendation": (
                            "保全底层结果并隔离相关主体"
                            if impact_confirmed
                            else "关联检查同一 PID 的 syscall 与文件审计结果"
                        ),
                        "recommended_action": _recommended_action(level, blocked=bool(event.get("blocked"))),
                    }
                )
                break
            if len(findings) >= 12:
                break

        highest_rank = max((_LEVEL_RANK.get(item["severity"], 0) for item in findings), default=0)
        highest = _RANK_LEVEL[highest_rank]
        confirmed = [item["finding_id"] for item in findings if item["impact_confirmed"]]
        finding_targets = list(
            dict.fromkeys(item["target"] for item in findings if item["target"])
        )[:3]
        return _agent_result(
            self.agent_id,
            self.name,
            {
                "analysis_type": "vulnerability_behavior_detection",
                "has_vulnerability_behavior": bool(findings),
                "highest_severity": highest,
                "findings": findings,
                "confirmed_impacts": confirmed,
                "unconfirmed_risks": [item["finding_id"] for item in findings if not item["impact_confirmed"]],
                "new_event_count": new_event_count,
                "summary": (
                    f"识别到 {len(findings)} 项漏洞相关行为证据，涉及"
                    f"{'、'.join(finding_targets) or '未识别目标'}；其中 {len(confirmed)} 项具有底层执行结果证据。"
                    if findings
                    else "当前事件中未发现明确的漏洞探测或利用行为。"
                ),
            },
        )


class DangerousBehaviorAgent:
    agent_id = "dangerous_behavior"
    name = "危险行为识别"

    _CATEGORIES = (
        ("exfiltration", ("--data", "--upload-file", "数据上传", "外部上传", "外泄", "exfil")),
        ("remote_script_execution", ("下载脚本直连解释器执行", "curl | sh", "wget | bash", "ling-remoteexec-017")),
        ("reverse_shell", ("反向或交互式 shell", "reverse shell", "nc -e", "/dev/tcp/", "ling-revshell-018")),
        ("cloud_metadata_access", ("元数据凭证", "169.254.169.254", "169.254.170.2", "metadata.google.internal", "ling-metadata-019")),
        ("container_escape", ("容器逃逸", "宿主控制面", "docker.sock", "--privileged", "nsenter", "ling-container-020")),
        ("source_control_destruction", ("git reset --hard", "git clean -f", "git push --force", "git 工作区或历史破坏性变更", "ling-git-021")),
        ("security_control_disable", ("停用主机安全控制", "setenforce 0", "ufw disable", "nft flush ruleset", "ling-secdisable-022")),
        ("network_tunnel", ("网络隧道", "代理通道", "remoteforward", "dynamicforward", "cloudflared tunnel", "ling-tunnel-023")),
        ("credential_access", ("secret", ".env", "credential", "凭证", "密钥", "敏感路径")),
        ("command_injection", ("命令注入", "; /bin/sh", "| /bin/sh", "shell injection")),
        ("path_traversal", ("路径穿越", "../", "..\\")),
        ("destruction", ("rm -rf", "unlink", "mkfs", "删除文件", "高破坏性")),
        ("privilege_change", ("chmod", "chown", "sudo ", "setuid", "capset", "修改权限")),
        ("memory_injection", ("ptrace", "process_vm_writev", "mprotect", "rwx", "内存注入")),
        ("persistence", ("authorized_keys", "crontab", "systemd", ".github/workflows", ".git/hooks", "开机自启", "持久化")),
        ("network_scan", ("nmap", "masscan", "端口扫描", "连续端口", "内网探测")),
        ("lateral_movement", ("横向移动", "pass-the-hash", "远程执行", "wmic", "psexec")),
        ("defense_evasion", ("history -c", "truncate -s 0", "audit.log", "审计或安全证据清除", "清除日志", "停用审计", "删除审计", "篡改日志")),
        ("process_abuse", ("execve", "启动进程", "创建进程")),
    )

    def analyze(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        dependencies: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for event in _chronological(payload):
            if _risk_rank(event) < 2 and not event.get("blocked") and not _policy_ids(event):
                continue
            text = _event_text(event)
            category = "process_abuse"
            for candidate, terms in self._CATEGORIES:
                if any(term.casefold() in text for term in terms):
                    category = candidate
                    break
            stage = _stage(event)
            level = _risk_level(event)
            executed = stage == "executed"
            low_level = str(event.get("source") or "") in {"linux_strace", "linux_inotify"}
            impact_confirmed = executed and low_level and category in {
                "destruction",
                "privilege_change",
                "memory_injection",
                "persistence",
                "exfiltration",
            }
            findings.append(
                {
                    "behavior": str(event.get("action") or "危险行为"),
                    "category": category,
                    "stage": stage,
                    "target": str(event.get("target") or ""),
                    "evidence_event_ids": [_event_id(event)],
                    "triggered_policy_ids": _policy_ids(event),
                    "severity": level,
                    "confidence": "high" if event.get("blocked") or low_level else "medium",
                    "executed": executed,
                    "blocked": bool(event.get("blocked")),
                    "impact_confirmed": impact_confirmed,
                    "recommended_action": _recommended_action(level, blocked=bool(event.get("blocked"))),
                    "reason": "、".join(
                        str(value)
                        for value in (
                            (event.get("risk") or {}).get("reasons", [])
                            if isinstance(event.get("risk"), Mapping)
                            else []
                        )
                    )[:320],
                }
            )
            if len(findings) >= 16:
                break

        highest_rank = max((_LEVEL_RANK.get(item["severity"], 0) for item in findings), default=0)
        highest = _RANK_LEVEL[highest_rank]
        blocked_count = sum(1 for item in findings if item["blocked"])
        impact_count = sum(1 for item in findings if item["impact_confirmed"])
        finding_targets = list(
            dict.fromkeys(item["target"] for item in findings if item["target"])
        )[:3]
        immediate_action = _recommended_action(highest, blocked=bool(findings) and blocked_count == len(findings))
        event_ids = [_event_id(event) for event in _chronological(payload)]
        retry_or_bypass = len(event_ids) != len(set(event_ids)) or sum(
            1 for event in _chronological(payload) if event.get("blocked")
        ) > 1
        return _agent_result(
            self.agent_id,
            self.name,
            {
                "analysis_type": "dangerous_behavior_detection",
                "dangerous_behavior_detected": bool(findings),
                "session_risk_level": highest,
                "immediate_action": immediate_action,
                "findings": findings,
                "blocked_count": blocked_count,
                "confirmed_impact_count": impact_count,
                "retry_or_bypass_detected": retry_or_bypass,
                "risk_expansion_paths": [
                    item["target"] for item in findings if item["target"]
                ][:8],
                "new_event_count": new_event_count,
                "summary": (
                    f"识别到 {len(findings)} 条危险行为证据，目标为"
                    f"{'、'.join(finding_targets) or '未识别'}；{blocked_count} 条已阻断，"
                    f"{impact_count} 条具有实际影响证据。"
                    if findings
                    else "当前未识别到需要处置的危险行为。"
                ),
            },
        )


class OverallBehaviorAgent:
    agent_id = "overall_behavior"
    name = "总体行为分析"

    def analyze(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
        dependencies: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        dependencies = dependencies or {}
        behavior = dependencies.get("behavior_prediction")
        behavior = behavior if isinstance(behavior, Mapping) else {}
        vulnerability = dependencies.get("vulnerability_behavior")
        vulnerability = vulnerability if isinstance(vulnerability, Mapping) else {}
        dangerous = dependencies.get("dangerous_behavior")
        dangerous = dangerous if isinstance(dangerous, Mapping) else {}
        events = _chronological(payload)
        risky = [event for event in events if _risk_rank(event) >= 2]
        blocked = [event for event in events if event.get("blocked")]
        failed = [event for event in events if str(event.get("status")) == "failed"]
        confirmed_impacts = int(dangerous.get("confirmed_impact_count") or 0)
        max_rank = max((_risk_rank(event) for event in events), default=0)
        base_score = {0: 0, 1: 12, 2: 32, 3: 58, 4: 82}[max_rank]
        risk_score = min(
            100,
            base_score
            + min(12, len(risky) * 2)
            + min(10, confirmed_impacts * 5)
            + (4 if vulnerability.get("has_vulnerability_behavior") else 0),
        )
        trust_score = max(0, 100 - risk_score)
        if confirmed_impacts:
            verdict = "confirmed_incident"
        elif blocked and max_rank >= 3:
            verdict = "attack_attempt"
        elif max_rank >= 3:
            verdict = "high_risk"
        elif risky:
            verdict = "suspicious"
        else:
            verdict = "normal"
        verdict_label = {
            "normal": "正常",
            "suspicious": "存在可疑行为",
            "high_risk": "高风险",
            "attack_attempt": "攻击尝试已识别",
            "confirmed_incident": "安全事件已确认",
        }[verdict]

        first_normal = next((event for event in events if _risk_rank(event) <= 1), None)
        first_risky = next((event for event in events if _risk_rank(event) >= 2), None)
        drift_detected = first_normal is not None and first_risky is not None
        timeline = [
            {
                "order": index,
                "event_id": _event_id(event),
                "behavior": str(event.get("action") or "行为"),
                "category": (
                    "attack_related"
                    if event.get("blocked") or _risk_rank(event) >= 4
                    else "dangerous"
                    if _risk_rank(event) >= 3
                    else "anomalous"
                    if _risk_rank(event) >= 2
                    else "normal"
                ),
                "target": str(event.get("target") or ""),
                "result": _stage(event),
                "risk_level": _risk_level(event),
                "policy_ids": _policy_ids(event),
            }
            for index, event in enumerate(events[-24:], start=max(1, len(events) - 23))
        ]
        event_by_id = {_event_id(event): event for event in events}
        chains: list[dict[str, Any]] = []
        for pattern in behavior.get("observed_patterns", []):
            if not isinstance(pattern, Mapping):
                continue
            event_ids = [
                str(value)
                for value in pattern.get("evidence_event_ids", [])
                if str(value) in event_by_id
            ]
            chain_events = [event_by_id[event_id] for event_id in event_ids]
            chain_blocked = any(event.get("blocked") for event in chain_events)
            target = next(
                (
                    str(event.get("target"))
                    for event in reversed(chain_events)
                    if event.get("target")
                ),
                "",
            )
            policy_ids = list(
                dict.fromkeys(
                    policy_id
                    for event in chain_events
                    for policy_id in _policy_ids(event)
                )
            )
            chains.append(
                {
                    "chain_name": str(pattern.get("pattern") or "关联行为链"),
                    "event_ids": event_ids,
                    "stage": "blocked" if chain_blocked else "executed",
                    "risk_level": _RANK_LEVEL[
                        max((_risk_rank(event) for event in chain_events), default=0)
                    ],
                    "confidence": str(pattern.get("confidence") or "medium"),
                    "target": target,
                    "analysis": (
                        f"按时间观察到 {len(chain_events)} 个关联事件；"
                        f"最终目标为 {target or '未识别'}，"
                        f"结果为{'执行前阻断' if chain_blocked else '已执行或已观察'}。"
                    ),
                    "policy_ids": policy_ids,
                }
            )
        confirmed_facts: list[str] = []
        if events:
            confirmed_facts.append(f"共观察到 {len(events)} 条标准化行为事件")
        if blocked:
            confirmed_facts.append(f"{len(blocked)} 条行为具有明确阻断结果")
        if confirmed_impacts:
            confirmed_facts.append(f"{confirmed_impacts} 条行为具有底层实际影响证据")
        predictions = [
            str(item.get("predicted_behavior"))
            for item in behavior.get("predictions", [])
            if isinstance(item, Mapping) and item.get("predicted_behavior")
        ]
        recommended: list[str] = []
        immediate = str(dangerous.get("immediate_action") or "observe")
        if immediate in {"block", "isolate"}:
            recommended.append("保持执行前审批，并对高风险主体实施隔离或阻断")
        elif immediate == "review":
            recommended.append("将后续高风险工具调用提升为人工复核")
        else:
            recommended.append("继续采集工具、文件和 syscall 证据")
        if predictions:
            recommended.append("针对预测行为设置短时高敏监控窗口")
        if vulnerability.get("unconfirmed_risks"):
            recommended.append("补充 syscall 或文件结果证据，确认漏洞相关行为是否真正执行")

        summary = (
            f"会话结论为“{verdict_label}”，风险分 {risk_score}/100，信任分 {trust_score}/100；"
            f"共 {len(risky)} 条异常或危险事件，{len(blocked)} 条已阻断。"
        )
        return _agent_result(
            self.agent_id,
            self.name,
            {
                "analysis_type": "overall_behavior_analysis",
                "session_verdict": verdict,
                "risk_score": risk_score,
                "trust_score": trust_score,
                "task_alignment": {
                    "aligned": None,
                    "drift_detected": drift_detected,
                    "drift_start_event_id": _event_id(first_risky) if first_risky else None,
                    "drift_reason": "会话由正常行为转入风险行为" if drift_detected else "缺少原始任务语义或未观察到明显偏移",
                },
                "executive_summary": summary,
                "timeline": timeline,
                "behavior_chains": chains,
                "statistics": {
                    "total_events": len(events),
                    "normal_events": len(events) - len(risky),
                    "anomalous_events": sum(1 for event in events if _risk_rank(event) == 2),
                    "dangerous_events": sum(1 for event in events if _risk_rank(event) >= 3),
                    "blocked_events": len(blocked),
                    "failed_events": len(failed),
                    "triggered_policy_count": int((payload.get("summary") or {}).get("triggered_policies_visible") or 0) if isinstance(payload.get("summary"), Mapping) else 0,
                },
                "confirmed_facts": confirmed_facts,
                "inferences": [str(behavior.get("summary") or "")],
                "predictions": predictions,
                "confirmed_impacts": list(vulnerability.get("confirmed_impacts") or []),
                "evidence_gaps": [
                    "实时状态不保留原始 Prompt 正文，任务目标一致性只能基于可见工具行为判断"
                ],
                "recommended_actions": recommended,
                "new_event_count": new_event_count,
                "final_conclusion": summary,
            },
        )


@dataclass(slots=True)
class _SessionAnalysisState:
    signature: str = ""
    seen_event_ids: set[str] = field(default_factory=set)
    revision: int = 0
    result: dict[str, Any] | None = None
    backend_signature: str = ""
    active_batch: _ActiveBackendBatch | None = None
    last_backend_submit: float = 0.0
    local_fallback_results: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class _ActiveBackendBatch:
    signature: str
    revision: int
    futures: dict[str, Future[dict[str, Any]]]
    fallback_results: dict[str, dict[str, Any]]
    started_at: str
    new_event_count: int
    collected_results: dict[str, dict[str, Any]] = field(default_factory=dict)


class LiveAnalysisCoordinator:
    """Run four fixed roles for each session, optionally through real Codex."""

    def __init__(
        self,
        *,
        agents: Sequence[LiveAnalysisAgent] | None = None,
        backend: LiveAnalysisBackend | None = None,
        max_sessions: int = 16,
        max_backend_workers: int = 4,
        min_backend_interval_seconds: float = 1.5,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        if max_backend_workers < 1:
            raise ValueError("max_backend_workers must be at least 1")
        if min_backend_interval_seconds < 0:
            raise ValueError("min_backend_interval_seconds cannot be negative")
        selected = tuple(
            agents
            or (
                BehaviorPredictionAgent(),
                VulnerabilityBehaviorAgent(),
                DangerousBehaviorAgent(),
                OverallBehaviorAgent(),
            )
        )
        if len({agent.agent_id for agent in selected}) != len(selected):
            raise ValueError("analysis agent ids must be unique")
        self.agents = selected
        self.backend = backend
        self.max_sessions = max_sessions
        self.min_backend_interval_seconds = float(min_backend_interval_seconds)
        self._states: OrderedDict[str, _SessionAnalysisState] = OrderedDict()
        self._lock = threading.RLock()
        self._executor = (
            ThreadPoolExecutor(
                max_workers=max_backend_workers,
                thread_name_prefix="codexscope-analysis",
            )
            if backend is not None
            else None
        )
        self._closed = False

    @staticmethod
    def _session_id(payload: Mapping[str, Any]) -> str:
        run_id = str(payload.get("run_id") or "pending-run")
        thread_id = str(payload.get("thread_id") or "pending-thread")
        return f"{run_id}:{thread_id}"[:512]

    @staticmethod
    def _signature(payload: Mapping[str, Any]) -> str:
        compact_events = []
        for event in _analysis_events(payload):
            compact_events.append(
                {
                    "id": event.get("id"),
                    "timestamp": event.get("timestamp"),
                    "source": event.get("source"),
                    "kind": event.get("kind"),
                    "action": event.get("action"),
                    "detail": event.get("detail"),
                    "target": event.get("target"),
                    "status": event.get("status"),
                    "blocked": event.get("blocked"),
                    "risk": event.get("risk"),
                    "policy_hits": event.get("policy_hits"),
                }
            )
        value = {
            "run_id": payload.get("run_id"),
            "thread_id": payload.get("thread_id"),
            "turn_id": payload.get("turn_id"),
            "events": compact_events,
            "enforcement": payload.get("enforcement"),
        }
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _local_results(
        self,
        payload: Mapping[str, Any],
        *,
        new_event_count: int,
    ) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for agent in self.agents:
            try:
                dependencies = (
                    results if agent.agent_id == "overall_behavior" else None
                )
                results[agent.agent_id] = agent.analyze(
                    payload,
                    new_event_count=new_event_count,
                    dependencies=dependencies,
                )
            except Exception as exc:  # Analysis must never take down monitoring.
                results[agent.agent_id] = {
                    "agent_id": agent.agent_id,
                    "name": agent.name,
                    "status": "degraded",
                    "mode": "local_explainable",
                    "error": type(exc).__name__,
                    "summary": "本轮本地初筛失败，实时行为采集仍在继续。",
                }
        return results

    def _backend_description(self) -> dict[str, Any]:
        if self.backend is None:
            return {
                "provider": "local",
                "mode": "local_explainable",
                "model": None,
            }
        try:
            description = self.backend.describe()
        except Exception:
            description = {}
        return {
            "provider": str(
                description.get("provider") or self.backend.provider
            ),
            "mode": str(description.get("mode") or self.backend.mode),
            "model": description.get("model") or self.backend.model,
        }

    def _mark_analyzing(
        self,
        state: _SessionAnalysisState,
        *,
        completed_agent_count: int = 0,
    ) -> None:
        if state.result is None:
            return
        runtime = state.result.get("runtime")
        if not isinstance(runtime, dict):
            return
        description = self._backend_description()
        runtime.update(
            {
                "status": "analyzing",
                "mode": description["mode"],
                "provider": description["provider"],
                "model": description["model"],
                "ready_agent_count": completed_agent_count,
            }
        )

    def _collect_backend(self, state: _SessionAnalysisState) -> None:
        batch = state.active_batch
        if batch is None:
            return
        for agent in self.agents:
            if agent.agent_id in batch.collected_results:
                continue
            future = batch.futures[agent.agent_id]
            if not future.done():
                continue
            try:
                batch.collected_results[agent.agent_id] = future.result()
            except Exception as exc:
                batch.collected_results[agent.agent_id] = {
                    "agent_id": agent.agent_id,
                    "name": agent.name,
                    "status": "degraded",
                    "mode": "codex_error",
                    "provider": self.backend.provider if self.backend else "local",
                    "backend_error": type(exc).__name__,
                    "summary": "Codex 分析失败；本地策略检测仍在运行，但未作为 Agent 分析结果展示。",
                }

        completed = len(batch.collected_results)
        if batch.signature == state.signature and state.result is not None:
            raw_agents = state.result.get("agents")
            if isinstance(raw_agents, dict):
                raw_agents.update(batch.collected_results)
            self._mark_analyzing(state, completed_agent_count=completed)
        if completed != len(batch.futures):
            return

        state.active_batch = None
        if batch.signature != state.signature or state.result is None:
            return
        results = batch.collected_results
        ready_count = sum(
            1 for result in results.values() if result.get("status") == "ready"
        )
        degraded_count = len(results) - ready_count
        description = self._backend_description()
        state.backend_signature = batch.signature
        state.result["agents"] = results
        state.result["updated_at"] = _now_iso()
        runtime = state.result.get("runtime")
        if isinstance(runtime, dict):
            runtime.update(
                {
                    "status": "ready" if degraded_count == 0 else "degraded",
                    "mode": description["mode"],
                    "provider": description["provider"],
                    "model": description["model"],
                    "ready_agent_count": ready_count,
                    "degraded_agent_count": degraded_count,
                    "backend_revision": batch.revision,
                    "backend_started_at": batch.started_at,
                    "backend_completed_at": state.result["updated_at"],
                }
            )

    def _schedule_backend(
        self,
        state: _SessionAnalysisState,
        payload: Mapping[str, Any],
        *,
        signature: str,
        new_event_count: int,
    ) -> None:
        if (
            self.backend is None
            or self._executor is None
            or self._closed
            or state.active_batch is not None
            or state.backend_signature == signature
            or not _analysis_events(payload)
            or state.result is None
        ):
            return
        now = time.monotonic()
        if now - state.last_backend_submit < self.min_backend_interval_seconds:
            return
        fallback_results = {
            agent.agent_id: dict(
                state.local_fallback_results.get(agent.agent_id) or {}
            )
            for agent in self.agents
        }
        futures: dict[str, Future[dict[str, Any]]] = {}
        for agent in self.agents:
            futures[agent.agent_id] = self._executor.submit(
                self.backend.analyze,
                agent.agent_id,
                agent.name,
                dict(payload),
                new_event_count=new_event_count,
                fallback=fallback_results[agent.agent_id],
            )
        started_at = _now_iso()
        state.active_batch = _ActiveBackendBatch(
            signature=signature,
            revision=state.revision,
            futures=futures,
            fallback_results=fallback_results,
            started_at=started_at,
            new_event_count=new_event_count,
        )
        state.last_backend_submit = now
        state.result["agents"] = {
            agent.agent_id: {
                "agent_id": agent.agent_id,
                "name": agent.name,
                "status": "analyzing",
                "mode": "codex_pending",
                "provider": self.backend.provider,
                "summary": "",
            }
            for agent in self.agents
        }
        self._mark_analyzing(state)
        runtime = state.result.get("runtime")
        if isinstance(runtime, dict):
            runtime["backend_started_at"] = started_at

    def enrich(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Return current analysis and asynchronously refresh it through Codex."""

        session_id = self._session_id(payload)
        signature = self._signature(payload)
        with self._lock:
            if self._closed:
                raise RuntimeError("analysis coordinator is closed")
            state = self._states.get(session_id)
            if state is None:
                state = _SessionAnalysisState()
                self._states[session_id] = state
            else:
                self._states.move_to_end(session_id)

            self._collect_backend(state)
            if state.signature == signature and state.result is not None:
                runtime = state.result.get("runtime")
                new_event_count = (
                    int(runtime.get("new_event_count") or 0)
                    if isinstance(runtime, Mapping)
                    else 0
                )
                self._schedule_backend(
                    state,
                    payload,
                    signature=signature,
                    new_event_count=new_event_count,
                )
                enriched = dict(payload)
                enriched["analysis"] = state.result
                return enriched

            event_ids = {_event_id(event) for event in _analysis_events(payload)}
            new_event_count = len(event_ids - state.seen_event_ids)
            results = self._local_results(
                payload,
                new_event_count=new_event_count,
            )
            state.local_fallback_results = results
            state.revision += 1
            state.signature = signature
            state.seen_event_ids = event_ids
            description = self._backend_description()
            state.result = {
                "schema_version": ANALYSIS_SCHEMA_VERSION,
                "session_id": session_id,
                "run_id": payload.get("run_id"),
                "thread_id": payload.get("thread_id"),
                "turn_id": payload.get("turn_id"),
                "revision": state.revision,
                "updated_at": _now_iso(),
                "runtime": {
                    "status": "running" if self.backend is None else "waiting",
                    "mode": description["mode"],
                    "provider": description["provider"],
                    "model": description["model"],
                    "agent_count": len(self.agents),
                    "ready_agent_count": len(self.agents)
                    if self.backend is None
                    else 0,
                    "analyzed_event_count": len(event_ids),
                    "new_event_count": new_event_count,
                },
                "agents": (
                    results
                    if self.backend is None
                    else {
                        agent.agent_id: {
                            "agent_id": agent.agent_id,
                            "name": agent.name,
                            "status": "analyzing",
                            "mode": "codex_pending",
                            "provider": description["provider"],
                            "summary": "",
                        }
                        for agent in self.agents
                    }
                ),
            }
            self._schedule_backend(
                state,
                payload,
                signature=signature,
                new_event_count=new_event_count,
            )
            while len(self._states) > self.max_sessions:
                _session, evicted = self._states.popitem(last=False)
                if evicted.active_batch is not None:
                    for future in evicted.active_batch.futures.values():
                        future.cancel()
            enriched = dict(payload)
            enriched["analysis"] = state.result
            return enriched

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self.backend is not None:
            self.backend.close()
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)


__all__ = [
    "ANALYSIS_SCHEMA_VERSION",
    "BehaviorPredictionAgent",
    "DangerousBehaviorAgent",
    "LiveAnalysisBackend",
    "LiveAnalysisCoordinator",
    "OverallBehaviorAgent",
    "VulnerabilityBehaviorAgent",
]
