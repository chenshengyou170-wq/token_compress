"""Portable desktop sidecar; JSONL control on stdio, model traffic on loopback.

This entry point deliberately does not import monitor, the Unix gateway, or OS
auditors. Merely starting it never calls a model or modifies Codex configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .desktop_connection import (
    MODES, CodexConnection, ConnectionError, default_codex_config, file_lock, inspect_codex,
)
from .input_compression import CompressionObservation, ResponsesInputCompressor
from .full_compression import FullCompressionConfig
from .reference_selection import SourceStore
from .request_token_tap import RequestTokenTap
from .storage import atomic_json_dump, json_load
from .token_panel import token_panel_snapshot
from .unified_compression import UnifiedInputCompressor


def _source_available(body: dict, server_name: str) -> bool:
    """Require an advertised reader in this request, not just a config entry."""
    groups = [(body.get("tools", []), "")]
    for item in body.get("input", []) if isinstance(body.get("input"), list) else []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "additional_tools":
            groups.append((item.get("tools", []), ""))
        if isinstance(item.get("additional_tools"), dict):
            groups.append((item["additional_tools"].get("tools", []), ""))
    visited = 0
    while groups and visited < 10000:
        definitions, namespace = groups.pop()
        if not isinstance(definitions, list):
            continue
        for tool in definitions:
            visited += 1
            if not isinstance(tool, dict):
                continue
            function = tool.get("function")
            name = function.get("name", "") if isinstance(function, dict) else tool.get("name", "")
            if not isinstance(name, str):
                continue
            qualified = f"{namespace}__{name}".replace(".", "__")
            if qualified.split("__")[-2:] == [server_name, "lingmou_source_read"]:
                return True
            if isinstance(tool.get("tools"), list):
                groups.append((tool["tools"], qualified))
    return False


def remote_configuration() -> dict:
    """Report presence only. Never expose keys, paths, or credential contents."""
    kimi = any(os.environ.get(key, "").strip() for key in ("KIMI_API_KEY", "MOONSHOT_API_KEY"))
    if not kimi and (filename := os.environ.get("KIMI_API_KEY_FILE")):
        try:
            kimi = Path(filename).is_file()
        except OSError:
            pass
    jev = bool(os.environ.get("TYPESAFE_API_KEY", "").strip())
    return {"kimi_configured": bool(kimi), "jev_configured": jev, "ready": bool(kimi and jev)}


class DesktopCompressor(ResponsesInputCompressor):
    supports_chat_completions = True

    def __init__(self, mode: str, store: SourceStore, server_name: str, *, remote_enabled=False, **kwargs):
        super().__init__(**kwargs)
        self.mode, self.store, self.server_name = mode, store, server_name
        self.remote_enabled = remote_enabled
        self.last_reason = "waiting_for_request"
        self.last_status = "waiting"
        self.last_mode = None
        self.reader_seen = False
        self._stats["mode"] = mode

    def set_mode(self, mode: str, *, remote_enabled: bool):
        with self._lock:
            self.mode = mode
            self.remote_enabled = remote_enabled
            self._stats["mode"] = mode

    def _compress(self, raw: bytes):
        from .structural_compression import loads
        body = loads(raw)
        if not isinstance(body, dict):
            return raw, CompressionObservation("skipped", "unsupported_input")
        with self._lock:
            mode = self.mode
            remote = self.remote_enabled and remote_configuration()["ready"]
        has_reader = _source_available(body, self.server_name)
        # Multiple Codex conversations may share this provider. Request-local
        # engines never reuse another conversation's prefix/delta/cache state.
        # Request-local engines cannot share a startup allowance or cached
        # rewrites safely across conversations. Remote work must be funded by
        # this request's local savings; desktop options override ambient flags.
        config = FullCompressionConfig(max_remote_calls=4 if remote else 0,
                                       max_remote_tokens=6000 if remote else 0,
                                       startup_remote_tokens=0, output_rewrite=False)
        engine = UnifiedInputCompressor(mode, source_store=self.store if has_reader else None,
                                       token_counter=self.token_counter, full_config=config)
        output, observation = engine.compress_observed(raw)
        if not has_reader and mode in {"extract", "auto", "full"}:
            observation = replace(observation, reason="source_tool_unavailable")
        with self._lock:
            self.last_reason = observation.reason
            self.last_status = observation.status
            self.last_mode = "structure" if not has_reader and mode in {"extract", "auto", "full"} else mode
            self.reader_seen = has_reader
        return output, observation

    def stats(self):
        with self._lock:
            return {**self._stats, "last_reason": self.last_reason, "last_status": self.last_status,
                    "last_mode": self.last_mode, "source_reader_seen": self.reader_seen}


class Companion:
    def __init__(self, root: Path):
        self.root = root
        self.connection = CodexConnection(root)
        self.tap: RequestTokenTap | None = None
        self.compressor: DesktopCompressor | None = None
        self.error = ""
        self.started_at = datetime.now(UTC).isoformat()
        self._save_lock = threading.Lock()
        try:
            self.connection.recover()
            if self.connection.enabled:
                self._start_relay()
        except (OSError, ValueError):
            self.error = "后台连接未能恢复。请检查端口和配置，使用“重启服务”或“解除接入”恢复。"

    def _start_relay(self):
        record = self.connection.record
        self.compressor = DesktopCompressor(record["mode"], SourceStore(self.connection.directory / "sources"),
                                            record["source_server"], remote_enabled=record.get("remote_enabled") is True)
        self.tap = RequestTokenTap(
            record["upstream"], listen_port=record["port"], access_token=record["access_token"],
            access_token_in_path=record.get("path_auth", False),
            input_compressor=self.compressor, on_request_usage=self._record_usage,
        ).start()
        self.error = ""
        self.started_at = datetime.now(UTC).isoformat()

    def _record_usage(self, _record):
        if self.tap is None:
            return
        with self._save_lock:
            snapshot = {**self.tap.stats_dict(), "started_at": self.started_at}
            # Numeric observations only; original bodies belong exclusively to
            # the bounded source store used by explicitly enabled excerpt modes.
            atomic_json_dump(self.connection.directory / "last_usage.json", snapshot)

    def _stats(self):
        if self.tap:
            return self.tap.stats_dict()
        if self.connection.record:
            try:
                value = json_load(self.connection.directory / "last_usage.json")
                return {**value, "running": False, "active_requests": 0}
            except (OSError, ValueError, TypeError):
                pass
        return {"running": False, "active_requests": 0}

    def status(self):
        stats = self._stats()
        root = self.connection.directory if self.connection.record else self.root
        source_files = list((self.root / "connections").glob("*/sources/*.txt"))
        source_bytes = sum(file.stat().st_size for file in source_files if file.is_file() and not file.is_symlink())
        public_stats = {**stats, "configurable": bool(self.tap)}
        return {
            "schema_version": 1, "enabled": self.connection.enabled, "running": bool(self.tap),
            "active_requests": stats.get("active_requests", 0),
            "connection": self.connection.public(), "default_config_path": str(default_codex_config()),
            "error": self.error, "started_at": self.started_at,
            "request_count": stats.get("request_count", 0), "relay_errors": stats.get("error_count", 0),
            "source_bytes": source_bytes, "source_count": len(source_files),
            "source_reader_seen": (stats.get("input_compression") or {}).get("source_reader_seen", False),
            "last_reason": (stats.get("input_compression") or {}).get("last_reason", "waiting_for_request"),
            "last_status": (stats.get("input_compression") or {}).get("last_status", "waiting"),
            "last_mode": (stats.get("input_compression") or {}).get("last_mode"),
            "remote_configuration": remote_configuration(),
            "tokens": token_panel_snapshot(root, provider_snapshot=public_stats),
        }

    def connect(self, *, config_path: str, auth_kind: str, upstream: str = "", mode: str = "structure",
                remote_enabled: bool = False):
        if self.connection.enabled:
            raise ConnectionError("已有接入，请先解除当前连接。")
        source_args = (["compression-companion", "sources"] if getattr(sys, "frozen", False)
                       else ["-m", "codexscope.desktop_companion", "sources"])
        self.connection.prepare(path=config_path, auth_kind=auth_kind, upstream=upstream, mode=mode,
                                source_command=sys.executable, source_args=source_args, remote_enabled=remote_enabled)
        try:
            self._start_relay()
            port = urlsplit(self.tap.local_base_url).port
            upstream_url = urlsplit(self.connection.record["upstream"])
            if upstream_url.hostname in {"127.0.0.1", "localhost", "::1"} and upstream_url.port == port:
                raise ConnectionError("上游地址不能指向灵眸代理自身。")
            self.connection.apply(port)
        except Exception:
            if self.tap:
                self.tap.stop()
                self.tap = None
            # Recovery is field-scoped; never blindly replace a changed config.
            self.connection.restore()
            raise
        return self.status()

    def set_mode(self, mode: str, remote_enabled: bool | None = None):
        if mode not in MODES:
            raise ConnectionError("请选择关闭、结构压缩、原文选段、本地自动或完整压缩。")
        if not self.connection.enabled or not self.tap:
            raise ConnectionError("请先接入 Codex 并启动本地服务。")
        if remote_enabled is None:
            remote_enabled = self.connection.record.get("remote_enabled", False) is True
        if type(remote_enabled) is not bool:
            raise ConnectionError("远程改写开关必须为布尔值。")
        previous = self.connection.record
        self.connection.record = {**previous, "mode": mode, "remote_enabled": remote_enabled}
        try:
            self.connection._save()
        except Exception:
            self.connection.record = previous
            raise
        self.compressor.set_mode(mode, remote_enabled=remote_enabled)
        return self.status()

    def disconnect(self):
        if self.tap and not self.tap.pause_if_idle():
            raise ConnectionError("仍有请求正在运行。请先在 Codex 中停止任务，等待请求结束后再解除接入。")
        try:
            self.connection.restore()
        except Exception:
            if self.tap:
                self.tap.resume()
            raise
        self.stop()
        self.error = ""
        return self.status()

    def restart(self):
        if not self.connection.enabled:
            raise ConnectionError("当前没有需要恢复的接入。")
        if self.tap and not self.tap.pause_if_idle():
            raise ConnectionError("仍有请求正在运行，请等待完成后重启服务。")
        self.stop()
        self._start_relay()
        return self.status()

    def clear_sources(self):
        if self.connection.enabled:
            raise ConnectionError("请结束 Codex 会话并解除接入后，再清理原文。")
        for file in (self.root / "connections").glob("*/sources/*.txt"):
            if file.is_file() and not file.is_symlink():
                file.unlink()
        return self.status()

    def stop(self):
        if self.tap:
            self._record_usage(None)
            self.tap.stop()
            self.tap = None


def _emit(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _serve(root: Path):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with file_lock(root / "worker.lock"):
        companion = Companion(root)
        _emit({"event": "ready", "protocol": 1})
        try:
            while line := sys.stdin.readline(65537):
                request_id = None
                try:
                    if len(line) > 65536:
                        raise ConnectionError("桌面控制消息过长。")
                    request = json.loads(line)
                    request_id = request.get("id")
                    if type(request_id) is not int:
                        raise ConnectionError("无效的控制消息编号。")
                    method, params = request.get("method"), request.get("params", {})
                    if not isinstance(params, dict):
                        raise ConnectionError("控制参数必须为对象。")
                    if method == "status":
                        result = companion.status()
                    elif method == "inspect":
                        result = inspect_codex(params.get("config_path"))
                    elif method == "connect":
                        result = companion.connect(**params)
                    elif method == "set_mode":
                        result = companion.set_mode(params.get("mode"), params.get("remote_enabled"))
                    elif method == "disconnect":
                        result = companion.disconnect()
                    elif method == "restart":
                        result = companion.restart()
                    elif method == "clear_sources":
                        result = companion.clear_sources()
                    elif method == "shutdown":
                        if companion.connection.enabled:
                            raise ConnectionError("请先解除接入，再停止后台服务。")
                        _emit({"id": request_id, "result": {"ok": True}})
                        break
                    else:
                        raise ConnectionError("未知的桌面控制操作。")
                    _emit({"id": request_id, "result": result})
                except ConnectionError as exc:
                    _emit({"id": request_id, "error": str(exc)})
                except OSError:
                    _emit({"id": request_id, "error": "无法访问配置、数据目录或监听端口。请检查权限与端口占用后重试。"})
                except Exception:
                    _emit({"id": request_id, "error": "操作未完成，请检查设置后重试。原配置备份仍保留在灵眸数据目录。"})
        finally:
            # Parent EOF also happens during a desktop crash. Restore while the
            # sidecar is still alive so future Codex starts do not use a dead
            # port. A hard kill still leaves the journal for next-start recovery.
            try:
                companion.connection.restore()
            finally:
                companion.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--state-dir", type=Path, required=True)
    sources = commands.add_parser("sources")
    sources.add_argument("--store", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "sources":
        from .context_tools import build_source_server
        build_source_server(SourceStore(args.store)).run(transport="stdio")
    else:
        _serve(args.state_dir.expanduser().resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConnectionError as exc:
        _emit({"event": "fatal", "error": str(exc)})
        raise SystemExit(1)
