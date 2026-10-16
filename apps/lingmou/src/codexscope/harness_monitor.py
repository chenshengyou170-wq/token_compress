"""Incremental, display-safe summaries for the current Codex harness run."""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .storage import json_load
from .util import now_iso


_RECENT_LIMIT = 80
_DISPLAY_ATTRIBUTES = (
    "rpc.method",
    "model",
    "provider_name",
    "reasoning_effort",
    "approval_policy",
    "sandbox_policy",
    "tool_name",
    "outcome",
    "success",
    "duration_ms",
    "http.response.status_code",
    "phase",
    "status",
    "startup.phase",
    "startup.status",
)

_OPERATION_LABELS: dict[str, tuple[str, str]] = {
    "auth": ("身份校验", "会话与配置"),
    "initialize": ("建立 Harness 会话", "会话与配置"),
    "list_models": ("读取模型目录", "会话与配置"),
    "fetch plugins": ("发现可用插件", "会话与配置"),
    "fetch_plugins": ("发现可用插件", "会话与配置"),
    "fetch_recommended_plugins": ("发现推荐插件", "会话与配置"),
    "plugin mode": ("确认插件模式", "会话与配置"),
    "plugin_mode": ("确认插件模式", "会话与配置"),
    "recommended_plugins_mode_for_config": ("确认插件运行模式", "会话与配置"),
    "endpoint_session.execute_with": ("执行内部请求", "Harness 调度"),
    "codex.api_request": ("访问模型服务", "模型服务"),
    "codex.tool_call": ("发起工具调用", "工具执行"),
    "codex.tool_result": ("接收工具结果", "工具执行"),
    "codex.user_prompt": ("接收用户任务", "会话与配置"),
    "codex.sse_event": ("接收模型流事件", "模型服务"),
}


def _operation_presentation(name: str) -> tuple[str, str]:
    exact = _OPERATION_LABELS.get(name)
    if exact is not None:
        return exact
    lowered = name.casefold()
    if "tool" in lowered:
        return name, "工具执行"
    if "api" in lowered or "http" in lowered or "model" in lowered:
        return name, "模型服务"
    if "session" in lowered or "auth" in lowered or "config" in lowered:
        return name, "会话与配置"
    return name, "Harness 内部"


def _safe_int(value: object) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _safe_float(value: object) -> float | None:
    if type(value) in {int, float}:
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _duration_ms(row: Mapping[str, Any]) -> float | None:
    attributes = row.get("attributes")
    if isinstance(attributes, Mapping):
        explicit = _safe_float(attributes.get("duration_ms"))
        if explicit is not None and explicit >= 0:
            return round(explicit, 3)
    start = _safe_int(row.get("start_time_unix_nano"))
    end = _safe_int(row.get("end_time_unix_nano"))
    if start is None or end is None or end < start:
        return None
    return round((end - start) / 1_000_000, 3)


def _outcome(row: Mapping[str, Any]) -> str:
    attributes = row.get("attributes")
    if isinstance(attributes, Mapping):
        if attributes.get("success") is False:
            return "error"
        http_status = _safe_int(attributes.get("http.response.status_code"))
        if http_status is not None and http_status >= 400:
            return "error"
        if attributes.get("success") is True:
            return "success"
        explicit = str(attributes.get("outcome") or "").casefold()
        if explicit in {"error", "failed", "failure", "denied"}:
            return "error"
        if explicit in {"success", "ok", "completed"}:
            return "success"
    status = row.get("status")
    if isinstance(status, Mapping) and str(status.get("code")) == "2":
        return "error"
    return "success"


def _display_attributes(row: Mapping[str, Any]) -> dict[str, object]:
    attributes = row.get("attributes")
    if not isinstance(attributes, Mapping):
        return {}
    result: dict[str, object] = {}
    for key in _DISPLAY_ATTRIBUTES:
        value = attributes.get(key)
        if type(value) in {str, int, float, bool}:
            result[key] = value
    return result


@dataclass(slots=True)
class _OperationStats:
    count: int = 0
    errors: int = 0
    duration_total_ms: float = 0.0
    duration_samples: int = 0
    last_received_at: str | None = None
    record_kind: str = "span"


class _IncrementalOtelReader:
    def __init__(self, path: Path, *, recent_limit: int = _RECENT_LIMIT) -> None:
        self.path = path
        self.recent_limit = recent_limit
        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._partial = b""
        self._reset()

    def _reset(self) -> None:
        self.total = 0
        self.spans = 0
        self.events = 0
        self.parse_errors = 0
        self.last_received_at: str | None = None
        self.operations: dict[str, _OperationStats] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=self.recent_limit)
        self._offset = 0
        self._partial = b""

    def refresh(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            if self._identity is not None:
                self._identity = None
                self._reset()
            return
        identity = (stat.st_dev, stat.st_ino)
        if self._identity != identity or stat.st_size < self._offset:
            self._identity = identity
            self._reset()
        if stat.st_size == self._offset:
            return
        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
            self._offset = handle.tell()
        if not chunk:
            return
        complete = self._partial + chunk
        lines = complete.split(b"\n")
        self._partial = lines.pop()
        for line in lines:
            if not line.strip():
                continue
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                self.parse_errors += 1
                continue
            if not isinstance(value, Mapping):
                self.parse_errors += 1
                continue
            self._consume(value)

    def _consume(self, row: Mapping[str, Any]) -> None:
        kind = str(row.get("record_kind") or "")
        name = str(row.get("name") or "").strip()
        if kind not in {"span", "event"} or not name:
            self.parse_errors += 1
            return
        received_at = str(row.get("received_at") or "") or None
        duration = _duration_ms(row)
        outcome = _outcome(row)
        label, category = _operation_presentation(name)
        attributes = _display_attributes(row)
        self.total += 1
        if kind == "span":
            self.spans += 1
        else:
            self.events += 1
        self.last_received_at = received_at or self.last_received_at
        stats = self.operations.setdefault(name, _OperationStats(record_kind=kind))
        stats.count += 1
        stats.errors += int(outcome == "error")
        stats.last_received_at = received_at or stats.last_received_at
        if duration is not None:
            stats.duration_total_ms += duration
            stats.duration_samples += 1
        trace_id = str(row.get("trace_id") or "")
        span_id = str(row.get("span_id") or "")
        self.recent.append(
            {
                "id": f"{trace_id[:12]}:{span_id[:12]}:{self.total}",
                "received_at": received_at,
                "record_kind": kind,
                "name": name,
                "label": label,
                "category": category,
                "duration_ms": duration,
                "outcome": outcome,
                "attributes": attributes,
            }
        )

    def operation_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for name, stats in self.operations.items():
            label, category = _operation_presentation(name)
            rows.append(
                {
                    "name": name,
                    "label": label,
                    "category": category,
                    "record_kind": stats.record_kind,
                    "count": stats.count,
                    "errors": stats.errors,
                    "average_duration_ms": (
                        round(stats.duration_total_ms / stats.duration_samples, 3)
                        if stats.duration_samples
                        else None
                    ),
                    "last_received_at": stats.last_received_at,
                }
            )
        return sorted(rows, key=lambda row: (-row["count"], row["name"]))


class _IncrementalLineCounter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._partial = b""
        self.count = 0

    def refresh(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            if self._identity is not None:
                self._identity = None
                self._offset = 0
                self._partial = b""
                self.count = 0
            return
        identity = (stat.st_dev, stat.st_ino)
        if self._identity != identity or stat.st_size < self._offset:
            self._identity = identity
            self._offset = 0
            self._partial = b""
            self.count = 0
        if stat.st_size == self._offset:
            return
        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
            self._offset = handle.tell()
        if not chunk:
            return
        complete = self._partial + chunk
        lines = complete.split(b"\n")
        self._partial = lines.pop()
        self.count += sum(1 for line in lines if line.strip())


def _read_mapping(path: Path) -> dict[str, Any]:
    try:
        value = json_load(path)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _layer_status(section: Mapping[str, Any], run_status: str) -> str:
    status = str(section.get("status") or "")
    if not section.get("enabled"):
        return "disabled" if status == "disabled" else "unavailable"
    if status in {"degraded", "unavailable", "failed"}:
        return status
    if status == "completed" or run_status in {"completed", "interrupted", "failed"}:
        return "completed"
    return "running"


class HarnessMonitor:
    """Build a bounded live view from one immutable Run directory."""

    def __init__(self, run_dir: Path, *, recent_limit: int = _RECENT_LIMIT) -> None:
        self.run_dir = run_dir.expanduser().resolve()
        raw = self.run_dir / "raw"
        self._otel = _IncrementalOtelReader(
            raw / "otel_trace.jsonl", recent_limit=recent_limit
        )
        self._protocol = _IncrementalLineCounter(raw / "appserver.jsonl")
        self._filesystem = _IncrementalLineCounter(raw / "filesystem.jsonl")
        self._lock = threading.Lock()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._otel.refresh()
            self._protocol.refresh()
            self._filesystem.refresh()
            manifest = _read_mapping(self.run_dir / "manifest.json")
            final_summary = _read_mapping(self.run_dir / "otel_trace_summary.json")
            return self._snapshot(manifest, final_summary)

    def _snapshot(
        self, manifest: Mapping[str, Any], final_summary: Mapping[str, Any]
    ) -> dict[str, Any]:
        run_status = str(manifest.get("status") or "unavailable")
        harness = manifest.get("harness_telemetry")
        harness = dict(harness) if isinstance(harness, Mapping) else {}
        os_audit = manifest.get("os_audit")
        os_audit = dict(os_audit) if isinstance(os_audit, Mapping) else {}
        file_audit = manifest.get("file_audit")
        file_audit = dict(file_audit) if isinstance(file_audit, Mapping) else {}
        collector = os_audit.get("collector")
        collector = dict(collector) if isinstance(collector, Mapping) else {}
        final_stats = final_summary.get("collector")
        final_stats = dict(final_stats) if isinstance(final_stats, Mapping) else {}

        max_events = _safe_int(harness.get("max_events"))
        dropped = _safe_int(final_stats.get("dropped_records")) or 0
        collector_errors = _safe_int(final_stats.get("persistence_errors")) or 0
        known_loss = bool(
            dropped
            or collector_errors
            or (max_events is not None and self._otel.total >= max_events)
        )
        harness_status = _layer_status(harness, run_status)
        if harness_status in {"running", "completed"} and (
            known_loss or self._otel.parse_errors
        ):
            harness_status = "degraded"

        captured_os = _safe_int(collector.get("events")) or 0
        observed_os = _safe_int(collector.get("observed_events")) or captured_os
        os_dropped = _safe_int(collector.get("dropped")) or 0
        os_parse_errors = _safe_int(collector.get("parse_errors")) or 0
        os_known_loss = bool(
            os_audit.get("known_loss_detected")
            or collector.get("known_loss")
            or os_dropped
            or os_parse_errors
        )
        os_status = _layer_status(os_audit, run_status)
        if os_status in {"running", "completed"} and os_known_loss:
            os_status = "degraded"

        file_status = _layer_status(file_audit, run_status)
        if file_status in {"running", "completed"} and file_audit.get(
            "known_loss_detected"
        ):
            file_status = "degraded"

        protocol_enabled = bool(manifest) and (
            self._protocol.count > 0 or bool(manifest.get("endpoint"))
        )
        protocol_status = (
            "running"
            if protocol_enabled and run_status == "running"
            else "completed"
            if protocol_enabled
            else "unavailable"
        )

        return {
            "schema_version": "lingmou.harness-monitor.v1",
            "run_id": manifest.get("run_id"),
            "run_status": run_status,
            "refreshed_at": now_iso(),
            "status": harness_status,
            "telemetry": {
                "requested": str(harness.get("requested") or "off"),
                "enabled": bool(harness.get("enabled")),
                "status": harness_status,
                "backend": harness.get("backend"),
                "transport": harness.get("transport"),
                "collector_scope": "loopback_only",
                "content_capture": False,
                "unknown_attributes_persisted": False,
                "max_events": max_events,
                "known_loss": known_loss,
                "parse_errors": self._otel.parse_errors,
                "dropped_records": dropped,
            },
            "summary": {
                "records": self._otel.total,
                "spans": self._otel.spans,
                "events": self._otel.events,
                "unique_operations": len(self._otel.operations),
                "last_received_at": self._otel.last_received_at,
                "protocol_messages": self._protocol.count,
                "os_events": captured_os,
                "os_observed_events": observed_os,
                "filesystem_events": self._filesystem.count,
            },
            "layers": [
                {
                    "id": "protocol",
                    "label": "Agent 协议",
                    "status": protocol_status,
                    "records": self._protocol.count,
                    "detail": "请求、通知、批准与响应边界",
                },
                {
                    "id": "harness",
                    "label": "Harness 内部 Trace",
                    "status": harness_status,
                    "records": self._otel.total,
                    "detail": "内部阶段、耗时与结果；不采集正文",
                },
                {
                    "id": "os",
                    "label": "系统调用",
                    "status": os_status,
                    "records": captured_os,
                    "observed_records": observed_os,
                    "detail": "App Server 后代进程的文件、进程与网络行为",
                },
                {
                    "id": "filesystem",
                    "label": "工作区变更",
                    "status": file_status,
                    "records": self._filesystem.count,
                    "detail": "工作区通知与变更后快照窗口",
                },
            ],
            "operations": self._otel.operation_rows(),
            "recent": list(reversed(self._otel.recent)),
            "privacy": {
                "prompts": "not_collected_by_harness_trace",
                "tool_arguments": "not_collected_by_harness_trace",
                "tool_output": "not_collected_by_harness_trace",
                "credentials": "redacted_and_not_returned_by_this_api",
                "content_capture": False,
            },
            "proof_boundary": [
                "Harness Trace 是 Codex 开源 Harness 的自报遥测，不具备抗篡改性。",
                "四层数值是当前 Run 的并列汇总，不代表记录之间已经逐条一一归因。",
                "系统调用层只覆盖监控启动后由 App Server 创建的后代进程。",
                "页面不会展示提示词、工具参数、工具输出或隐藏推理内容。",
                "某层存在采集丢失时，只能证明已记录的行为，不能据此证明行为从未发生。",
            ],
        }


__all__ = ["HarnessMonitor"]
