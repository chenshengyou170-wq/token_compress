from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import codexscope.cli as cli
import codexscope.monitor as monitor_module
from codexscope.cli import _parser
from codexscope.environment import capture_transform
from codexscope.monitor import (
    LINGMOU_SECURITY_PATH_ENV,
    GatewayRecorder,
    InteractiveState,
    MonitorError,
    _acquire_monitor_lock,
    _clear_stale_registry,
    _enable_codexscope_preflight_trace,
    _parse_codexscope_preflight_log,
    _resolve_codex_bin,
    active_monitor_path,
    attach_command,
    attach_environment,
    default_run_dir,
    monitor_codex,
    read_active_monitor,
    workspace_metadata,
)
from codexscope.live_status_scenario import (
    formal_scenario_steps,
    validate_checkpoint,
)
from codexscope.live_status_server import create_live_status_server
from codexscope.snapshots import SnapshotManager
from codexscope.storage import atomic_json_dump


def _envelope(
    seq: int,
    direction: str,
    message: dict,
    *,
    connection_id: str = "connection-1",
) -> dict:
    return {
        "seq": seq,
        "connection_id": connection_id,
        "direction": direction,
        "wall_time": float(seq),
        "wall_time_ns": seq * 1_000_000_000,
        "mono_ns": seq * 1_000_000,
        "message": message,
    }


def _patch_idle_monitor_transport(monkeypatch) -> None:
    """Patch only the app-server transport; snapshot/audit code stays real."""

    monkeypatch.setattr(monitor_module, "codex_version", lambda _path: "fake 1.0")

    class IdleProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.finished = asyncio.Event()

        async def wait(self) -> int:
            await self.finished.wait()
            assert self.returncode is not None
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15
            self.finished.set()

        def kill(self) -> None:
            self.returncode = -9
            self.finished.set()

    async def fake_spawn(*_args, **_kwargs):
        return IdleProcess()

    async def fake_wait_for_socket(*_args, **_kwargs) -> None:
        return None

    class FakeGateway:
        def __init__(self, frontend, _backend, **_kwargs) -> None:
            self.endpoint = f"unix://{frontend}"
            self.callback_errors: tuple[BaseException, ...] = ()

        async def start(self) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(monitor_module.asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setattr(monitor_module, "_wait_for_socket", fake_wait_for_socket)
    monkeypatch.setattr(monitor_module, "UnixSocketGateway", FakeGateway)


def test_codex_preflight_trace_environment_and_parser() -> None:
    environment = {"RUST_LOG": "info"}
    _enable_codexscope_preflight_trace(environment)
    assert environment == {
        "RUST_LOG": "info,codex_core::codexscope_preflight_usage=trace",
        "LOG_FORMAT": "json",
    }

    line = json.dumps(
        {
            "target": "codex_core::codexscope_preflight_usage",
            "fields": {
                "message": "CodexScope preflight token estimate",
                "turn_id": "turn-1",
                "model": "gpt-5.4",
                "estimated_input_tokens": 15_120,
            },
        }
    )
    assert _parse_codexscope_preflight_log(line) == {
        "estimated_input_tokens": 15_120,
        "turn_id": "turn-1",
        "model": "gpt-5.4",
    }
    assert _parse_codexscope_preflight_log("not json") is None


async def _wait_for_manifest_status(path: Path, status: str) -> None:
    for _ in range(300):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            value = {}
        if value.get("status") == status:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"manifest never reached status {status!r}")


def test_monitor_cli_is_convenient_and_attach_keeps_codex_arguments() -> None:
    parser = _parser()
    monitor = parser.parse_args(["monitor"])
    assert monitor.repo == Path(".")
    assert monitor.out is None
    assert monitor.function_trace == "off"
    assert monitor.file_audit == "off"
    assert monitor.file_audit_max_events == 100_000
    assert monitor.os_audit == "off"
    assert monitor.os_audit_max_events == 200_000
    assert monitor.harness_telemetry == "off"
    assert monitor.harness_telemetry_max_events == 100_000
    assert monitor.capture_surfaced_reasoning is False
    assert monitor.request_token_tap_upstream is None

    audited = parser.parse_args(
        [
            "monitor",
            "--file-audit",
            "auto",
            "--file-audit-max-events",
            "123",
            "--os-audit",
            "strace",
            "--os-audit-max-events",
            "456",
            "--harness-telemetry",
            "otel",
            "--harness-telemetry-max-events",
            "789",
            "--capture-surfaced-reasoning",
            "--request-token-tap-upstream",
            "https://chatgpt.com/backend-api/codex",
        ]
    )
    assert audited.file_audit == "auto"
    assert audited.file_audit_max_events == 123
    assert audited.os_audit == "strace"
    assert audited.os_audit_max_events == 456
    assert audited.harness_telemetry == "otel"
    assert audited.harness_telemetry_max_events == 789
    assert audited.capture_surfaced_reasoning is True
    assert (
        audited.request_token_tap_upstream
        == "https://chatgpt.com/backend-api/codex"
    )

    attach = parser.parse_args(
        ["attach", "--print-command", "--", "--model", "gpt-test"]
    )
    assert attach.print_command is True
    assert attach.codex_args == ["--", "--model", "gpt-test"]


@pytest.mark.parametrize("compression", ["off", "caveman", "hybrid"])
def test_monitor_request_token_tap_is_opt_in_and_configures_codex(
    monkeypatch, tmp_path: Path, compression: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    taps: list[object] = []

    class FakeTap:
        def __init__(self, upstream, **callbacks) -> None:
            self.upstream = SimpleNamespace(path="/backend-api/codex")
            self.upstream_value = upstream
            self.callbacks = callbacks
            self.local_base_url = "http://127.0.0.1:43210/backend-api/codex"
            self.started = False
            self.stopped = False
            taps.append(self)

        def start(self):
            self.started = True
            return self

        def stats_dict(self):
            return {'running': not self.stopped, 'request_count': 2}

        def stop(self):
            self.stopped = True
            return {
                "running": False,
                "request_count": 2,
                "observed_request_count": 2,
                "sse_event_count": 3,
                "error_count": 0,
            }

    class IdleProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.finished = asyncio.Event()

        async def wait(self) -> int:
            await self.finished.wait()
            assert self.returncode is not None
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15
            self.finished.set()

        def kill(self) -> None:
            self.returncode = -9
            self.finished.set()

    spawn_calls: list[tuple[object, ...]] = []

    async def capture_spawn(*args, **_kwargs):
        spawn_calls.append(args)
        return IdleProcess()

    async def inline_to_thread(function, /, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(monitor_module, "RequestTokenTap", FakeTap)
    # This test verifies command/callback wiring, not executor behavior.  Keep
    # its fake synchronous tap and snapshot helpers on the event-loop thread.
    monkeypatch.setattr(monitor_module.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(
        monitor_module.asyncio,
        "create_subprocess_exec",
        capture_spawn,
    )

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                request_token_tap_upstream=(
                    "https://chatgpt.com/backend-api/codex"
                ),
                input_compression=compression,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        taps[0].callbacks['on_request_usage']({'request_id': 'tap-1',
            'input_tokens_before_estimate': 120, 'input_tokens_after_estimate': 100,
            'official_usage': {'input_tokens': 103, 'output_tokens': 20, 'total_tokens': 123}})
        await asyncio.sleep(0)
        stop.set()
        return await asyncio.wait_for(task, timeout=3)

    assert asyncio.run(exercise()) == run_dir.resolve()
    assert len(taps) == 1
    tap = taps[0]
    assert tap.upstream_value == "https://chatgpt.com/backend-api/codex"
    assert tap.started is True
    assert tap.stopped is True
    assert ("input_compressor" in tap.callbacks) == (compression != "off")
    command = spawn_calls[0]
    assert 'model_provider="codexscope_request_tap"' in command
    provider_override = next(
        str(value)
        for value in command
        if str(value).startswith("model_providers.codexscope_request_tap=")
    )
    assert 'name="OpenAI"' in provider_override
    assert (
        'base_url="http://127.0.0.1:43210/backend-api/codex"'
        in provider_override
    )
    assert 'http_headers={version="1.0"}' in provider_override
    assert '"OpenAI-Organization"="OPENAI_ORGANIZATION"' in provider_override
    assert "requires_openai_auth=true" in provider_override
    assert "supports_websockets=false" in provider_override
    assert "features.enable_request_compression=false" in command
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["request_token_tap"]["status"] == "completed"
    assert manifest["request_token_tap"]["request_count"] == 2
    assert manifest["request_token_tap"]["request_body_persistence"] is False
    assert manifest["request_token_tap"]["input_compression_mode"] == compression
    assert manifest['request_token_tap']['usage_log'] == 'request_usage.jsonl'
    usage_rows = (run_dir / 'request_usage.jsonl').read_text().splitlines()
    assert len(usage_rows) == 1
    assert json.loads(usage_rows[0])['official_usage']['total_tokens'] == 123


def test_monitor_harness_telemetry_is_opt_in_and_trace_safe(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)
    original_spawn = monitor_module.asyncio.create_subprocess_exec
    spawn_calls: list[tuple[object, ...]] = []

    async def capture_spawn(*args, **kwargs):
        spawn_calls.append(args)
        return await original_spawn(*args, **kwargs)

    monkeypatch.setattr(
        monitor_module.asyncio, "create_subprocess_exec", capture_spawn
    )

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                harness_telemetry="otel",
                harness_telemetry_max_events=321,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        stop.set()
        return await asyncio.wait_for(task, timeout=3)

    assert asyncio.run(exercise()) == run_dir.resolve()
    command = tuple(str(value) for value in spawn_calls[0])
    assert 'otel.log_user_prompt=false' in command
    assert 'otel.exporter="none"' in command
    assert 'otel.metrics_exporter="none"' in command
    trace_override = next(
        value for value in command if value.startswith("otel.trace_exporter=")
    )
    assert "http://127.0.0.1:" in trace_override
    assert trace_override.endswith('/v1/traces",protocol="json"}}')
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    telemetry = manifest["harness_telemetry"]
    assert telemetry["status"] == "completed"
    assert telemetry["enabled"] is True
    assert telemetry["content_capture"] is False
    assert telemetry["collector"]["max_events"] == 321
    assert telemetry["collector"]["persisted_records"] == 0
    assert (run_dir / "raw" / "otel_trace.jsonl").exists()
    assert (run_dir / "otel_trace_summary.json").exists()


def test_monitor_cli_startup_failure_never_reprocesses_existing_trace(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    old_run = tmp_path / "old-run"
    (old_run / "raw").mkdir(parents=True)
    atomic_json_dump(old_run / "manifest.json", {"run_id": "old-run"})
    old_derived = old_run / "summary.json"
    old_derived.write_text("old-derived-data\n", encoding="utf-8")

    async def fail_before_run(**_kwargs):
        raise MonitorError("simulated ownership failure")

    processed: list[Path] = []
    monkeypatch.setattr("codexscope.monitor.monitor_codex", fail_before_run)
    monkeypatch.setattr(cli, "process_run", lambda path: processed.append(path))

    status = cli.main(
        [
            "monitor",
            "--repo",
            str(repo),
            "--out",
            str(old_run),
            "--no-schema",
        ]
    )
    captured = capsys.readouterr()
    assert status == 1
    assert processed == []
    assert old_derived.read_text(encoding="utf-8") == "old-derived-data\n"
    assert "Partial trace" not in captured.err


def test_active_registry_and_attach_command(monkeypatch, tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    endpoint_path = tmp_path / "monitor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint_path))
    owner = _acquire_monitor_lock()
    try:
        registry = {
            "run_id": "run-1",
            "pid": os.getpid(),
            "endpoint": f"unix://{endpoint_path}",
            "repo": "/workspace/demo",
            "lingmou_security_path": "/private/run/live_security.json",
            "codex_bin": "/opt/bin/codex",
        }
        atomic_json_dump(active_monitor_path(), registry)

        loaded = read_active_monitor()
        assert loaded["run_id"] == "run-1"
        assert attach_command(loaded, ["--", "--model", "test-model"]) == [
            "/opt/bin/codex",
            "--remote",
            f"unix://{endpoint_path}",
            "-C",
            "/workspace/demo",
            "--model",
            "test-model",
        ]
        assert attach_environment(
            loaded,
            {
                "KEEP": "yes",
                LINGMOU_SECURITY_PATH_ENV: "/stale/run/live_security.json",
            },
        ) == {
            "KEEP": "yes",
            LINGMOU_SECURITY_PATH_ENV: "/private/run/live_security.json",
        }
    finally:
        os.close(owner)
        listener.close()


def test_active_registry_requires_a_live_ownership_lock(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    endpoint_path = tmp_path / "stale.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint_path))
    registry_path = active_monitor_path()
    atomic_json_dump(
        registry_path,
        {
            "run_id": "stale-run",
            "pid": os.getpid(),
            "endpoint": f"unix://{endpoint_path}",
            "repo": str(tmp_path),
        },
    )
    try:
        with pytest.raises(MonitorError, match="no longer running"):
            read_active_monitor()
        assert not registry_path.exists()
    finally:
        listener.close()


def test_monitor_ownership_lock_prevents_concurrent_start(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    first = _acquire_monitor_lock()
    try:
        with pytest.raises(MonitorError, match="already active"):
            _acquire_monitor_lock()
    finally:
        os.close(first)

    second = _acquire_monitor_lock()
    os.close(second)

    stale = active_monitor_path()
    atomic_json_dump(stale, {"pid": os.getpid(), "run_id": "stale-run"})
    owner = _acquire_monitor_lock()
    try:
        _clear_stale_registry(stale)
        assert not stale.exists()
    finally:
        os.close(owner)


def test_codex_binary_is_resolved_once_for_monitor_and_attach(
    monkeypatch, tmp_path: Path
) -> None:
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    assert _resolve_codex_bin("./fake-codex") == str(executable.resolve())

    monkeypatch.setenv("PATH", str(tmp_path))
    assert _resolve_codex_bin("fake-codex") == str(executable.resolve())
    with pytest.raises(MonitorError, match="cannot find executable"):
        _resolve_codex_bin("missing-codex")


def test_monitor_with_pre_set_stop_skips_all_expensive_startup(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))

    calls: list[str] = []

    def unexpected(name: str):
        def fail(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"unexpected startup stage: {name}")

        return fail

    async def unexpected_spawn(*_args, **_kwargs):
        calls.append("appserver")
        raise AssertionError("app-server must not start after stop was requested")

    monkeypatch.setattr(monitor_module, "workspace_metadata", unexpected("metadata"))
    monkeypatch.setattr(monitor_module, "codex_version", unexpected("version"))
    monkeypatch.setattr(
        monitor_module, "capture_protocol_schema", unexpected("schema")
    )
    monkeypatch.setattr(
        monitor_module.SnapshotManager,
        "capture_baseline",
        unexpected("baseline"),
    )
    monkeypatch.setattr(
        monitor_module.FunctionTraceCollector,
        "start",
        unexpected("function_collector"),
    )
    monkeypatch.setattr(
        monitor_module, "InotifyWorkspaceObserver", unexpected("file_audit")
    )
    monkeypatch.setattr(
        monitor_module, "StraceAuditCollector", unexpected("os_audit")
    )
    monkeypatch.setattr(
        monitor_module.asyncio, "create_subprocess_exec", unexpected_spawn
    )

    async def exercise() -> Path:
        stop = asyncio.Event()
        stop.set()
        return await monitor_codex(
            repo=repo,
            run_dir=run_dir,
            codex_bin=str(executable),
            capture_schema=True,
            function_trace="all",
            file_audit="inotify",
            os_audit="strace",
            frontend_socket=tmp_path / "frontend.sock",
            external_stop=stop,
        )

    assert asyncio.run(exercise()) == run_dir.resolve()
    assert calls == []
    assert not (tmp_path / "frontend.sock").exists()
    assert not active_monitor_path().exists()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "interrupted"
    assert manifest["startup_stop_stage"] == "before_codex_version"
    assert manifest["workspace_metadata_skipped"] == (
        "stop_requested_before_startup"
    )
    assert manifest["file_audit"]["status"] == "not_started"
    assert manifest["os_audit"]["status"] == "not_started"
    assert (run_dir / "raw" / "appserver.jsonl").read_text(encoding="utf-8") == ""


def test_strict_file_audit_failure_never_starts_appserver(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(monitor_module, "codex_version", lambda _path: "fake 1.0")

    class FailingObserver:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self):
            raise RuntimeError("simulated inotify startup failure")

    spawned = False

    async def unexpected_spawn(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        raise AssertionError("app-server must not start")

    monkeypatch.setattr(monitor_module, "InotifyWorkspaceObserver", FailingObserver)
    monkeypatch.setattr(
        monitor_module.asyncio, "create_subprocess_exec", unexpected_spawn
    )

    with pytest.raises(RuntimeError, match="simulated inotify startup failure"):
        asyncio.run(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                file_audit="inotify",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=asyncio.Event(),
            )
        )

    assert spawned is False
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["file_audit"]["status"] == "unavailable"
    assert not (tmp_path / "frontend.sock").exists()


def test_strict_os_audit_failure_never_starts_appserver(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(monitor_module, "codex_version", lambda _path: "fake 1.0")

    class MissingStrace:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self):
            raise RuntimeError("simulated strace unavailable")

    spawned = False

    async def unexpected_spawn(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        raise AssertionError("app-server must not start")

    monkeypatch.setattr(monitor_module, "StraceAuditCollector", MissingStrace)
    monkeypatch.setattr(
        monitor_module.asyncio, "create_subprocess_exec", unexpected_spawn
    )

    with pytest.raises(RuntimeError, match="simulated strace unavailable"):
        asyncio.run(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                os_audit="strace",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=asyncio.Event(),
            )
        )

    assert spawned is False
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["os_audit"]["status"] == "unavailable"
    assert manifest["os_audit"]["scope"] == "appserver_descendant_process_tree"
    assert (run_dir / "os_audit_summary.json").exists()


def test_auto_os_audit_startup_failure_degrades_and_appserver_runs(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    class MissingStrace:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self):
            raise RuntimeError("simulated strace unavailable")

    monkeypatch.setattr(monitor_module, "StraceAuditCollector", MissingStrace)

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                os_audit="auto",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        stop.set()
        return await asyncio.wait_for(task, timeout=3)

    assert asyncio.run(exercise()) == run_dir.resolve()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "interrupted"
    assert manifest["os_audit"]["enabled"] is False
    assert manifest["os_audit"]["status"] == "unavailable"


def test_monitor_persists_inflight_estimate_then_reconciles_exact_usage(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    callbacks: dict[str, object] = {}

    class CapturingGateway:
        def __init__(self, frontend, _backend, **kwargs) -> None:
            self.endpoint = f"unix://{frontend}"
            self.callback_errors: tuple[BaseException, ...] = ()
            callbacks["on_message"] = kwargs["on_message"]

        async def start(self) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(monitor_module, "UnixSocketGateway", CapturingGateway)

    async def wait_for_live_output() -> dict:
        path = run_dir / "live_status.json"
        for _ in range(100):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                payload = {}
            estimate = payload.get("inflight_token_estimate") or {}
            if estimate.get("output_tokens_observed", 0) > 0:
                return payload
            await asyncio.sleep(0.01)
        raise AssertionError("live output estimate was never persisted")

    async def exercise() -> tuple[dict, dict]:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        try:
            await _wait_for_manifest_status(run_dir / "manifest.json", "running")
            on_message = callbacks["on_message"]
            assert callable(on_message)
            await on_message(
                _envelope(
                    1,
                    "client_to_server",
                    {
                        "method": "turn/start",
                        "params": {
                            "threadId": "thread-1",
                            "input": [{"type": "text", "text": "count me"}],
                        },
                    },
                )
            )
            await on_message(
                _envelope(
                    2,
                    "server_to_client",
                    {
                        "method": "turn/started",
                        "params": {
                            "threadId": "thread-1",
                            "turn": {"id": "turn-1", "status": "inProgress"},
                        },
                    },
                )
            )
            await on_message(
                _envelope(
                    3,
                    "server_to_client",
                    {
                        "method": "item/agentMessage/delta",
                        "params": {"itemId": "answer-1", "delta": "streamed text"},
                    },
                )
            )
            estimated = await wait_for_live_output()

            await on_message(
                _envelope(
                    4,
                    "server_to_client",
                    {
                        "method": "thread/tokenUsage/updated",
                        "params": {
                            "threadId": "thread-1",
                            "turnId": "turn-1",
                            "tokenUsage": {
                                "last": {
                                    "totalTokens": 120,
                                    "inputTokens": 100,
                                    "cachedInputTokens": 20,
                                    "outputTokens": 20,
                                    "reasoningOutputTokens": 10,
                                },
                                "total": {
                                    "totalTokens": 120,
                                    "inputTokens": 100,
                                    "cachedInputTokens": 20,
                                    "outputTokens": 20,
                                    "reasoningOutputTokens": 10,
                                },
                            },
                        },
                    },
                )
            )
            exact = json.loads(
                (run_dir / "live_status.json").read_text(encoding="utf-8")
            )
            return estimated, exact
        finally:
            stop.set()
            await asyncio.wait_for(task, timeout=3)

    estimated, exact = asyncio.run(exercise())
    live = estimated["inflight_token_estimate"]
    assert live["active"] is True
    assert live["output_tokens_observed"] > 0
    assert "live" in estimated["status_line"]
    assert exact["inflight_token_estimate"]["active"] is False
    assert exact["inflight_token_estimate"]["reconciliation_count"] == 1
    assert exact["token_usage"]["total"]["total_tokens"] == 120
    assert exact["status_line"] == "tokens: 120  (in 100 / out 20)"
    security = json.loads(
        (run_dir / "live_security.json").read_text(encoding="utf-8")
    )
    assert security["schema_version"] == "codexscope.live-security.v1"
    assert security["run_id"] == exact["run_id"]


def test_formal_live_token_scenario_reaches_browser_api_with_all_checks(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    callbacks: dict[str, object] = {}

    class CapturingGateway:
        def __init__(self, frontend, _backend, **kwargs) -> None:
            self.endpoint = f"unix://{frontend}"
            self.callback_errors: tuple[BaseException, ...] = ()
            callbacks["on_message"] = kwargs["on_message"]

        async def start(self) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(monitor_module, "UnixSocketGateway", CapturingGateway)

    async def exercise() -> tuple[int, list[str], dict]:
        stop = asyncio.Event()
        monitor_task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        web_server = None
        web_thread = None
        try:
            await _wait_for_manifest_status(run_dir / "manifest.json", "running")
            on_message = callbacks["on_message"]
            assert callable(on_message)

            web_server = create_live_status_server(
                run_dir / "live_status.json",
                host="127.0.0.1",
                port=0,
                frontend="token",
                analysis_backend="local",
            )
            web_thread = threading.Thread(
                target=web_server.serve_forever,
                daemon=True,
            )
            web_thread.start()
            endpoint = (
                str(web_server.server_address[0]),
                int(web_server.server_address[1]),
            )

            def read_browser_api() -> dict:
                connection = http.client.HTTPConnection(*endpoint, timeout=2)
                try:
                    connection.request("GET", "/api/live-status")
                    response = connection.getresponse()
                    assert response.status == 200
                    return json.loads(response.read())
                finally:
                    connection.close()

            history: dict[str, dict] = {}
            passed_labels: list[str] = []
            sequence = 0
            delta_checkpoints = {
                "streaming_reasoning",
                "streaming_answer",
                "second_model_streaming",
                "final_model_streaming",
            }
            for step in formal_scenario_steps():
                if step.wait_s:
                    await asyncio.sleep(step.wait_s)
                sequence += 1
                envelope = step.envelope(sequence)
                if envelope is not None:
                    await on_message(envelope)
                if step.checkpoint is None:
                    continue
                # Model deltas are deliberately coalesced by the monitor's
                # 250 ms disk ticker; lifecycle and exact usage persist eagerly.
                await asyncio.sleep(
                    0.30 if step.checkpoint in delta_checkpoints else 0.03
                )
                payload = await asyncio.to_thread(read_browser_api)
                passed_labels.extend(
                    validate_checkpoint(step.checkpoint, payload, history)
                )
                history[step.checkpoint] = payload

            return len(history), passed_labels, history["all_complete"]
        finally:
            if web_server is not None:
                web_server.shutdown()
                web_server.server_close()
            if web_thread is not None:
                web_thread.join(timeout=2)
            stop.set()
            await asyncio.wait_for(monitor_task, timeout=4)

    checkpoint_count, assertions, final_payload = asyncio.run(exercise())
    assert checkpoint_count == 16
    assert len(assertions) == 62
    assert final_payload["token_usage"]["total"]["total_tokens"] == 56_970
    assert final_payload["inflight_token_estimate"]["reconciliation_count"] == 4


def test_os_audit_wraps_appserver_and_stops_its_process_group(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    instances: list[object] = []

    class FakeCollector:
        def __init__(self, repo_arg, output, *, max_events, trace_profile) -> None:
            self.repo = repo_arg
            self.output = output
            self.max_events = max_events
            self.trace_profile = trace_profile
            self.pass_fds = (71, 72)
            self.after_spawn_called = False
            self.closed = False
            self.running = True
            instances.append(self)

        def start(self):
            return self

        def wrap_command(self, argv):
            self.original_command = list(argv)
            return ["fake-strace", "--", *argv]

        def after_spawn(self) -> None:
            self.after_spawn_called = True

        def stats_dict(self):
            return {
                "backend": "linux_strace",
                "events": 7,
                "dropped": 0,
                "parse_errors": 0,
                "unfinished_pending": 0,
                "reader_error": None,
                "limit_reached": False,
                "known_loss": False,
            }

        def close(self):
            self.closed = True
            self.running = False
            return self.stats_dict()

    class GroupProcess:
        def __init__(self) -> None:
            self.pid = 424242
            self.returncode: int | None = None
            self.finished = asyncio.Event()

        async def wait(self) -> int:
            await self.finished.wait()
            assert self.returncode is not None
            return self.returncode

    process = GroupProcess()
    spawn_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def fake_spawn(*args, **kwargs):
        spawn_calls.append((args, kwargs))
        return process

    group_signals: list[tuple[int, signal.Signals]] = []

    def fake_killpg(pid: int, sig: signal.Signals) -> None:
        if sig == 0:
            return
        group_signals.append((pid, sig))
        if sig == signal.SIGTERM:
            process.returncode = -int(sig)
            process.finished.set()

    monkeypatch.setattr(monitor_module, "StraceAuditCollector", FakeCollector)
    monkeypatch.setattr(monitor_module.asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setattr(monitor_module.os, "killpg", fake_killpg)
    monkeypatch.setattr(monitor_module, "_PROCESS_STOP_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(monitor_module, "_OS_AUDIT_MANIFEST_HEARTBEAT_SECONDS", 0.01)

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                os_audit="strace",
                os_audit_max_events=321,
                capture_surfaced_reasoning=True,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        for _ in range(100):
            current = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            if current["os_audit"].get("collector", {}).get("events") == 7:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("running OS-audit stats were not persisted")
        stop.set()
        return await asyncio.wait_for(task, timeout=3)

    assert asyncio.run(exercise()) == run_dir.resolve()
    collector = instances[0]
    assert collector.repo == repo.resolve()
    assert collector.output == run_dir / "raw" / "os_audit.jsonl"
    assert collector.max_events == 321
    assert collector.trace_profile == "behavior"
    assert collector.after_spawn_called is True
    assert collector.closed is True
    args, kwargs = spawn_calls[0]
    assert args[:2] == ("fake-strace", "--")
    assert "show_raw_agent_reasoning=true" in args
    assert kwargs["pass_fds"] == (71, 72)
    assert kwargs["start_new_session"] is True
    assert group_signals == [
        (process.pid, signal.SIGTERM),
        (process.pid, signal.SIGKILL),
    ]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["os_audit"]["status"] == "completed"
    assert manifest["os_audit"]["process_identity"] is True
    assert manifest["os_audit"]["scope"] == "appserver_descendant_process_tree"
    assert manifest["os_audit"]["trace_profile"] == "behavior"
    assert manifest["os_audit"]["intentional_filtering"] is True
    assert manifest["os_audit"]["collector"]["events"] == 7
    assert manifest["reasoning_capture"]["surfaced_reasoning_only"] is True
    assert manifest["reasoning_capture"]["hidden_chain_of_thought"] is False


@pytest.mark.parametrize(
    ("mode", "expect_failure"), (("strace", True), ("auto", False))
)
def test_os_audit_collection_loss_has_mode_appropriate_result(
    monkeypatch, tmp_path: Path, mode: str, expect_failure: bool
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    class LossyCollector:
        pass_fds: tuple[int, ...] = ()

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def start(self):
            return self

        def wrap_command(self, argv):
            return list(argv)

        def after_spawn(self) -> None:
            pass

        def close(self):
            return {
                "events": 1,
                "dropped": 3,
                "parse_errors": 0,
                "unfinished_pending": 0,
                "reader_error": None,
                "limit_reached": True,
                "known_loss": True,
            }

    async def fake_stop(process, *, process_group: bool = False) -> None:
        assert process_group is True
        process.terminate()
        await process.wait()

    monkeypatch.setattr(monitor_module, "StraceAuditCollector", LossyCollector)
    monkeypatch.setattr(monitor_module, "_stop_process", fake_stop)

    async def exercise() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                os_audit=mode,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        stop.set()
        if expect_failure:
            with pytest.raises(MonitorError, match="collection gap"):
                await asyncio.wait_for(task, timeout=3)
        else:
            assert await asyncio.wait_for(task, timeout=3) == run_dir.resolve()

    asyncio.run(exercise())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == ("failed" if expect_failure else "interrupted")
    assert manifest["os_audit"]["status"] == "degraded"
    assert manifest["os_audit"]["known_loss_detected"] is True
    summary = json.loads(
        (run_dir / "os_audit_summary.json").read_text(encoding="utf-8")
    )
    assert summary["known_loss_detected"] is True
    assert summary["collector"]["dropped"] == 3


def test_strict_os_audit_runtime_loss_stops_monitor(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)
    instances: list[object] = []

    class RuntimeLossCollector:
        pass_fds: tuple[int, ...] = ()

        def __init__(self, *_args, **_kwargs) -> None:
            self.running = True
            self.loss = False
            instances.append(self)

        def start(self):
            return self

        def wrap_command(self, argv):
            return list(argv)

        def after_spawn(self) -> None:
            pass

        def stats_dict(self):
            return {
                "dropped": 1 if self.loss else 0,
                "parse_errors": 0,
                "reader_error": None,
                "limit_reached": False,
                # An unfinished syscall is normal before EOF and must not by
                # itself stop a strict live monitor.
                "unfinished_pending": 1,
                "known_loss": True,
            }

        def close(self):
            self.running = False
            stats = self.stats_dict()
            stats["unfinished_pending"] = 0
            stats["known_loss"] = self.loss
            return stats

    async def fake_stop(process, *, process_group: bool = False) -> None:
        assert process_group is True
        process.terminate()
        await process.wait()

    monkeypatch.setattr(
        monitor_module, "StraceAuditCollector", RuntimeLossCollector
    )
    monkeypatch.setattr(monitor_module, "_stop_process", fake_stop)

    async def exercise() -> None:
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                os_audit="strace",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=asyncio.Event(),
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        # Give the health loop one pass where only unfinished_pending and the
        # aggregate known_loss flag are present; it must keep running.
        await asyncio.sleep(0.15)
        assert not task.done()
        instances[0].loss = True
        with pytest.raises(MonitorError, match="collection gap"):
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(exercise())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["stop_reason"] == "os_audit_failed"
    assert manifest["os_audit"]["known_loss_detected"] is True


def test_strict_file_audit_runtime_death_stops_monitor(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "module.py").write_text("value = 1\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    instances: list[object] = []

    class RuntimeObserver:
        def __init__(self, *_args, **_kwargs) -> None:
            self.running = True
            self.closed = False
            self.stats = SimpleNamespace(jsonl_dropped=0)
            instances.append(self)

        def start(self):
            return self

        def stats_dict(self):
            return {
                "kernel_overflows": 0,
                "jsonl_dropped": 0,
                "watch_add_errors": 0,
                "watch_limit_errors": 0,
                "callback_errors": 0,
                "callback_dropped": 0,
                "last_error": None if self.running else "simulated reader death",
            }

        def close(self, *, raise_on_error: bool = True) -> None:
            self.closed = True
            self.running = False

    monkeypatch.setattr(
        monitor_module, "InotifyWorkspaceObserver", RuntimeObserver
    )

    async def exercise() -> None:
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                file_audit="inotify",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=asyncio.Event(),
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        assert instances
        instances[0].running = False
        with pytest.raises(MonitorError, match="collection gap"):
            await asyncio.wait_for(task, timeout=3)
        leaked = [
            value
            for value in asyncio.all_tasks()
            if value is not asyncio.current_task()
            and not value.done()
            and value.get_name()
            in {
                "codexscope-file-audit-health",
                "codexscope-file-audit-debounce",
            }
        ]
        assert leaked == []

    asyncio.run(exercise())
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["stop_reason"] == "file_audit_failed"
    assert manifest["file_audit"]["runtime_stopped_unexpectedly"] is True
    assert instances[0].closed is True


def test_auto_file_audit_close_error_degrades_without_failing_run(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "module.py").write_text("value = 1\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    instances: list[object] = []

    class CloseFailingObserver:
        def __init__(self, *_args, **_kwargs) -> None:
            self.running = True
            self.stats = SimpleNamespace(jsonl_dropped=0)
            instances.append(self)

        def start(self):
            return self

        def stats_dict(self):
            return {
                "kernel_overflows": 0,
                "jsonl_dropped": 0,
                "watch_add_errors": 0,
                "watch_limit_errors": 0,
                "callback_errors": 0,
                "callback_dropped": 0,
                "last_error": None,
            }

        def close(self, *, raise_on_error: bool = True) -> None:
            raise RuntimeError("simulated close failure")

        def stop(self, *, raise_on_error: bool = True) -> None:
            self.running = False

    monkeypatch.setattr(
        monitor_module, "InotifyWorkspaceObserver", CloseFailingObserver
    )

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                file_audit="auto",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        stop.set()
        result = await asyncio.wait_for(task, timeout=3)
        leaked = [
            value
            for value in asyncio.all_tasks()
            if value is not asyncio.current_task()
            and not value.done()
            and value.get_name().startswith("codexscope-file-audit-")
        ]
        assert leaked == []
        return result

    assert asyncio.run(exercise()) == run_dir.resolve()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "interrupted"
    assert manifest["file_audit"]["status"] == "degraded"
    assert manifest["file_audit"]["known_loss_detected"] is True
    assert manifest["file_audit"]["close_error"]["message"] == (
        "simulated close failure"
    )
    assert instances[0].running is False


def test_slow_file_audit_scan_has_bounded_pending_windows(
    monkeypatch, tmp_path: Path
) -> None:
    # Import from the owning module so the skip remains accurate even though
    # monitor intentionally exposes only its observer integration class.
    from codexscope.fswatch import inotify_available

    if not inotify_available():
        pytest.skip("inotify unavailable")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "module.py").write_text("value = 1\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    _patch_idle_monitor_transport(monkeypatch)

    original_capture_after = SnapshotManager.capture_after
    scan_started = threading.Event()

    def slow_capture_after(self, seq, item):
        if item.get("action_type") == "filesystem_observation":
            scan_started.set()
            # Slow enough for many callbacks to arrive while the first audit
            # scan is in flight. They must merge into one pending window.
            import time

            time.sleep(0.35)
        return original_capture_after(self, seq, item)

    monkeypatch.setattr(SnapshotManager, "capture_after", slow_capture_after)

    async def exercise() -> Path:
        stop = asyncio.Event()
        task = asyncio.create_task(
            monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                file_audit="inotify",
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=stop,
            )
        )
        await _wait_for_manifest_status(run_dir / "manifest.json", "running")
        (repo / "first.py").write_text("first = 1\n", encoding="utf-8")
        started = await asyncio.to_thread(scan_started.wait, 2)
        assert started is True
        for index in range(30):
            (repo / f"burst-{index}.py").write_text(
                f"value = {index}\n", encoding="utf-8"
            )
        stop.set()
        return await asyncio.wait_for(task, timeout=5)

    assert asyncio.run(exercise()) == run_dir.resolve()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    audit = manifest["file_audit"]
    assert audit["status"] == "completed"
    assert audit["snapshot_windows"] == 2
    assert audit["snapshot_windows_dropped"] == 0
    assert len(audit["recent_snapshot_windows"]) == 2
    assert audit["recent_snapshot_windows"][0]["capture_ended_monotonic_ns"]


def test_file_audit_rejects_internal_frontend_socket(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))

    with pytest.raises(MonitorError, match="--socket must be outside"):
        asyncio.run(
            monitor_codex(
                repo=repo,
                run_dir=tmp_path / "run",
                codex_bin=str(executable),
                capture_schema=False,
                file_audit="auto",
                frontend_socket=repo / "internal.sock",
                external_stop=asyncio.Event(),
            )
        )

    assert not (repo / "internal.sock").exists()
    assert not (tmp_path / "run").exists()


def test_monitor_cleans_stop_waiter_when_appserver_exits_unexpectedly(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "run"
    executable = tmp_path / "fake-codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setattr(monitor_module, "codex_version", lambda _path: "fake 1.0")

    class ExitingProcess:
        returncode: int | None = None

        async def wait(self) -> int:
            await asyncio.sleep(0)
            self.returncode = 17
            return 17

        def terminate(self) -> None:
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

    process = ExitingProcess()

    async def fake_spawn(*_args, **_kwargs):
        return process

    async def fake_wait_for_socket(*_args, **_kwargs) -> None:
        return None

    class FakeGateway:
        def __init__(self, frontend, _backend, **_kwargs) -> None:
            self.endpoint = f"unix://{frontend}"
            self.callback_errors: tuple[BaseException, ...] = ()

        async def start(self) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(monitor_module.asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setattr(monitor_module, "_wait_for_socket", fake_wait_for_socket)
    monkeypatch.setattr(monitor_module, "UnixSocketGateway", FakeGateway)

    async def exercise() -> None:
        with pytest.raises(MonitorError, match="exited unexpectedly"):
            await monitor_codex(
                repo=repo,
                run_dir=run_dir,
                codex_bin=str(executable),
                capture_schema=False,
                frontend_socket=tmp_path / "frontend.sock",
                external_stop=asyncio.Event(),
            )
        leaked = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task()
            and not task.done()
            and task.get_name() == "codexscope-monitor-stop"
        ]
        assert leaked == []

    asyncio.run(exercise())


def test_default_run_dir_and_non_git_metadata(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "plain-workspace"
    repo.mkdir()
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))

    destination = default_run_dir(repo)
    assert destination.parent == state / "codexscope" / "runs"
    assert destination.name.startswith("interactive-")
    metadata = workspace_metadata(repo)
    assert metadata["repo"] == str(repo.resolve())
    assert metadata["git_available"] is False
    assert metadata["git_head"] is None


def test_gateway_recorder_redacts_copy_but_keeps_token_usage(tmp_path: Path) -> None:
    raw = tmp_path / "appserver.jsonl"
    recorder = GatewayRecorder(raw, include_sensitive=False)
    source = _envelope(
        1,
        "client_to_server",
        {
            "id": 1,
            "method": "turn/start",
            "params": {"input": [{"type": "text", "text": "private prompt"}]},
        },
    )
    recorder.write(source)
    recorder.write(
        _envelope(
            2,
            "server_to_client",
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread-1",
                    "tokenUsage": {
                        "total": {"inputTokens": 12, "outputTokens": 3}
                    },
                },
            },
        )
    )
    recorder.close()

    rows = [json.loads(line) for line in raw.read_text().splitlines()]
    persisted_input = rows[0]["message"]["params"]["input"][0]
    assert persisted_input["text"] == "[OMITTED]"
    assert persisted_input["text_length"] == len("private prompt")
    assert source["message"]["params"]["input"][0]["text"] == "private prompt"
    assert rows[1]["message"]["params"]["tokenUsage"]["total"] == {
        "inputTokens": 12,
        "outputTokens": 3,
    }


def test_gateway_recorder_can_keep_only_appserver_surfaced_reasoning(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "appserver.jsonl"
    recorder = GatewayRecorder(
        raw,
        include_sensitive=False,
        capture_surfaced_reasoning=True,
    )
    recorder.write(
        _envelope(
            1,
            "client_to_server",
            {
                "id": 1,
                "method": "turn/start",
                "params": {"input": [{"type": "text", "text": "private prompt"}]},
            },
        )
    )
    recorder.write(
        _envelope(
            2,
            "server_to_client",
            {
                "method": "item/reasoning/summaryTextDelta",
                "params": {"itemId": "reason-1", "delta": "surfaced summary"},
            },
        )
    )
    recorder.write(
        _envelope(
            3,
            "server_to_client",
            {
                "method": "item/agentMessage/delta",
                "params": {"itemId": "answer-1", "delta": "private answer"},
            },
        )
    )
    recorder.write(
        _envelope(
            4,
            "server_to_client",
            {
                "method": "item/completed",
                "params": {
                    "item": {
                        "id": "reason-1",
                        "type": "reasoning",
                        "summary": ["surfaced completed summary"],
                    }
                },
            },
        )
    )
    recorder.write(
        _envelope(
            5,
            "client_to_server",
            {
                "method": "item/reasoning/textDelta",
                "params": {"delta": "client-controlled private text"},
            },
        )
    )
    recorder.close()

    rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["message"]["params"]["input"][0]["text"] == "[OMITTED]"
    assert rows[1]["message"]["params"]["delta"] == "surfaced summary"
    assert rows[2]["message"]["params"]["delta"] == "[OMITTED]"
    assert rows[3]["message"]["params"]["item"]["summary"] == [
        "surfaced completed summary"
    ]
    assert rows[4]["message"]["params"]["delta"] == "[OMITTED]"


def test_default_capture_omits_interactive_streams_and_named_text() -> None:
    cases = [
        (
            {
                "method": "item/agentMessage/delta",
                "params": {"delta": "private agent stream", "itemId": "item-1"},
            },
            "delta",
            "private agent stream",
        ),
        (
            {
                "method": "item/reasoning/summaryTextDelta",
                "params": {"delta": "private reasoning summary", "itemId": "item-2"},
            },
            "delta",
            "private reasoning summary",
        ),
        (
            {
                "method": "thread/realtime/transcript/done",
                "params": {"text": "private spoken transcript", "role": "user"},
            },
            "text",
            "private spoken transcript",
        ),
        (
            {
                "method": "thread/name/updated",
                "params": {"threadId": "thread-1", "threadName": "private title"},
            },
            "threadName",
            "private title",
        ),
        (
            {
                "id": 10,
                "method": "thread/goal/set",
                "params": {"threadId": "thread-1", "objective": "private goal"},
            },
            "objective",
            "private goal",
        ),
    ]

    for message, field, original in cases:
        transformed = capture_transform(message)
        assert transformed["params"][field] == "[OMITTED]"
        assert original not in json.dumps(transformed, ensure_ascii=False)
        # Opting in retains conversation text (credential scrubbing still runs).
        assert capture_transform(message, include_sensitive=True)["params"][field] == original

    plan = {
        "method": "turn/plan/updated",
        "params": {
            "explanation": "private plan explanation",
            "plan": [{"step": "private plan step", "status": "pending"}],
        },
    }
    transformed_plan = capture_transform(plan)
    assert transformed_plan["params"]["explanation"] == "[OMITTED]"
    assert transformed_plan["params"]["plan"][0]["step"] == "[OMITTED]"
    assert capture_transform(plan, include_sensitive=True) == plan

    steer = {
        "id": 11,
        "method": "turn/steer",
        "params": {
            "threadId": "thread-1",
            "expectedTurnId": "turn-1",
            "input": [{"type": "text", "text": "private steering prompt"}],
        },
    }
    assert capture_transform(steer)["params"]["input"][0]["text"] == "[OMITTED]"

    decorated_prompt = {
        "id": 13,
        "method": "turn/start",
        "params": {
            "threadId": "thread-1",
            "input": [
                {
                    "type": "text",
                    "text": "inspect the private mention",
                    "text_elements": [
                        {
                            "byteRange": {"start": 12, "end": 27},
                            "placeholder": "private mention",
                        }
                    ],
                }
            ],
        },
    }
    transformed_decorated = capture_transform(decorated_prompt)
    decorated_input = transformed_decorated["params"]["input"][0]
    assert decorated_input["text"] == "[OMITTED]"
    assert decorated_input["text_elements"][0]["placeholder"] == "[OMITTED]"
    assert "private mention" not in json.dumps(transformed_decorated)

    injected = {
        "id": 12,
        "method": "thread/injectItems",
        "params": {
            "threadId": "thread-1",
            "items": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "private injection"}],
                }
            ],
        },
    }
    transformed_injected = capture_transform(injected)
    assert transformed_injected["params"]["items"][0]["content"][0]["text"] == "[OMITTED]"
    assert capture_transform(injected, include_sensitive=True) == injected


def test_default_capture_omits_thread_history_without_response_method() -> None:
    response = {
        "id": 7,
        "result": {
            "thread": {
                "id": "thread-1",
                "sessionId": "session-1",
                "status": "idle",
                "name": "private thread title",
                "preview": "private first prompt",
                "turns": [
                    {
                        "id": "turn-1",
                        "status": "completed",
                        "items": [
                            {
                                "id": "user-1",
                                "type": "userMessage",
                                "content": [
                                    {"type": "text", "text": "private resumed prompt"}
                                ],
                            },
                            {
                                "id": "agent-1",
                                "type": "agentMessage",
                                "text": "private resumed answer",
                            },
                            {
                                "id": "plan-1",
                                "type": "plan",
                                "text": "private resumed plan",
                            },
                            {
                                "id": "reasoning-1",
                                "type": "reasoning",
                                "content": ["private reasoning text"],
                                "summary": ["private reasoning summary"],
                            },
                            {
                                "id": "hook-1",
                                "type": "hookPrompt",
                                "fragments": [
                                    {"hookRunId": "run-1", "text": "private hook prompt"}
                                ],
                            },
                            {
                                "id": "collab-1",
                                "type": "collabAgentToolCall",
                                "prompt": "private subagent prompt",
                                "agentsStates": {
                                    "thread-child": {
                                        "status": "completed",
                                        "message": "private subagent status",
                                    }
                                },
                            },
                        ],
                    }
                ],
            },
            "goal": {
                "threadId": "thread-1",
                "objective": "private persisted goal",
                "status": "active",
            },
        },
    }

    transformed = capture_transform(response)
    serialized = json.dumps(transformed, ensure_ascii=False)
    for private_text in (
        "private thread title",
        "private first prompt",
        "private resumed prompt",
        "private resumed answer",
        "private resumed plan",
        "private reasoning text",
        "private reasoning summary",
        "private hook prompt",
        "private subagent prompt",
        "private subagent status",
        "private persisted goal",
    ):
        assert private_text not in serialized

    thread = transformed["result"]["thread"]
    assert thread["name"] == thread["preview"] == "[OMITTED]"
    items = thread["turns"][0]["items"]
    assert items[0]["content"][0]["text"] == "[OMITTED]"
    assert items[1]["text"] == "[OMITTED]"
    assert items[3]["content"] == ["[OMITTED]"]
    assert items[3]["summary"] == ["[OMITTED]"]
    assert items[5]["agentsStates"]["thread-child"]["message"] == "[OMITTED]"
    assert transformed["result"]["goal"]["objective"] == "[OMITTED]"
    assert capture_transform(response, include_sensitive=True) == response


def test_interactive_state_tracks_multiple_turns_and_prompt_hashes() -> None:
    state = InteractiveState()
    state.connection_started({"connection_id": "connection-1", "wall_time": 1.0})
    assert state.consume(
        _envelope(
            1,
            "client_to_server",
            {"id": 1, "method": "thread/start", "params": {"model": "gpt-test"}},
        )
    ) is False
    assert state.consume(
        _envelope(
            2,
            "server_to_client",
            {
                "id": 1,
                "result": {
                    "thread": {"id": "thread-1", "status": "idle"},
                    "model": "gpt-test",
                    "approvalPolicy": "on-request",
                },
            },
        )
    ) is True

    for offset, prompt in ((10, "first prompt"), (20, "second prompt")):
        assert state.consume(
            _envelope(
                offset,
                "client_to_server",
                {
                    "id": offset,
                    "method": "turn/start",
                    "params": {
                        "threadId": "thread-1",
                        "input": [{"type": "text", "text": prompt}],
                    },
                },
            )
        ) is True
        turn_id = f"turn-{offset}"
        state.consume(
            _envelope(
                offset + 1,
                "server_to_client",
                {"id": offset, "result": {"turn": {"id": turn_id}}},
            )
        )
        state.consume(
            _envelope(
                offset + 2,
                "server_to_client",
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": turn_id, "status": "inProgress"},
                    },
                },
            )
        )
        state.consume(
            _envelope(
                offset + 3,
                "server_to_client",
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": turn_id, "status": "completed"},
                    },
                },
            )
        )

    steer_prompt = "one more constraint"
    assert state.consume(
        _envelope(
            50,
            "client_to_server",
            {
                "id": 50,
                "method": "turn/steer",
                "params": {
                    "threadId": "thread-1",
                    "input": [{"type": "text", "text": steer_prompt}],
                },
            },
        )
    ) is True
    assert state.consume(
        _envelope(
            51,
            "server_to_client",
            {"id": 50, "result": {"turnId": "turn-20"}},
        )
    ) is True

    manifest: dict = {}
    state.apply_manifest(manifest)
    assert manifest["thread_id"] == "thread-1"
    assert len(manifest["turns"]) == 2
    assert len(manifest["turn_prompt_sha256s"]) == 3
    assert manifest["steering_prompt_count"] == 1
    assert manifest["turns"][-1]["steering_prompts"][0]["prompt_length"] == len(
        steer_prompt
    )


def test_interactive_manifest_omits_thread_names_unless_opted_in() -> None:
    private_name = "Fix the private billing regression"
    state = InteractiveState()
    state.consume(
        _envelope(
            1,
            "server_to_client",
            {
                "method": "thread/started",
                "params": {
                    "thread": {
                        "id": "thread-private",
                        "status": "idle",
                        "name": private_name,
                    }
                },
            },
        )
    )
    manifest: dict = {}
    state.apply_manifest(manifest)
    thread = manifest["threads"][0]
    assert "name" not in thread
    assert thread["name_length"] == len(private_name)
    assert thread["name_sha256"] == hashlib.sha256(
        private_name.encode("utf-8")
    ).hexdigest()

    opted_in = InteractiveState(include_sensitive=True)
    opted_in.consume(
        _envelope(
            2,
            "server_to_client",
            {
                "method": "thread/name/updated",
                "params": {
                    "threadId": "thread-private",
                    "threadName": private_name,
                },
            },
        )
    )
    opted_manifest: dict = {}
    opted_in.apply_manifest(opted_manifest)
    assert opted_manifest["threads"][0]["name"] == private_name

    opted_in.consume(
        _envelope(
            3,
            "server_to_client",
            {
                "method": "thread/name/updated",
                "params": {"threadId": "thread-private", "threadName": None},
            },
        )
    )
    cleared_manifest: dict = {}
    opted_in.apply_manifest(cleared_manifest)
    assert "name" not in cleared_manifest["threads"][0]
    assert state.active_turns == set()


def test_workspace_snapshot_baseline_supports_dirty_non_git_folder(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "plain"
    repo.mkdir()
    source = repo / "module.py"
    source.write_text("value = 1\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    (repo / "link.py").symlink_to(outside)
    run_dir = tmp_path / "trace"

    manager = SnapshotManager(repo, run_dir, baseline_source="workspace")
    manager.capture_baseline()
    baseline = json.loads(
        (run_dir / "snapshots" / "baseline_manifest.json").read_text()
    )
    assert baseline["source"] == "workspace"
    assert (run_dir / "snapshots" / "baseline" / "module.py").read_text() == "value = 1\n"
    assert not (run_dir / "snapshots" / "baseline" / "link.py").exists()

    source.write_text("value = 2\n", encoding="utf-8")
    rows = manager.capture_after(4, {"id": "edit-1", "type": "fileChange"})
    manager.close()
    changed = next(row for row in rows if row["path"] == "module.py")
    assert changed["before_sha256"] != changed["after_sha256"]
    assert manager.scan_stats["baseline_source"] == "workspace"


def test_workspace_snapshot_marks_concurrent_boundary_as_ambiguous(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "concurrent-workspace"
    repo.mkdir()
    source = repo / "module.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_dir = tmp_path / "concurrent-trace"

    manager = SnapshotManager(repo, run_dir, baseline_source="workspace")
    manager.capture_baseline()
    source.write_text("value = 2\n", encoding="utf-8")
    rows = manager.capture_after(
        7,
        {
            "id": "tool-a",
            "type": "commandExecution",
            "_codexscope_attribution_ambiguous": True,
            "_codexscope_attribution_candidate_item_ids": ["tool-b", "tool-a"],
        },
    )
    manager.close()

    row = next(value for value in rows if value["path"] == "module.py")
    assert row["capture_source"] == "concurrent_item_boundary"
    assert row["attribution_ambiguous"] is True
    assert row["attribution_candidate_item_ids"] == ["tool-a", "tool-b"]
    assert row["capture_started_monotonic_ns"] <= row[
        "capture_ended_monotonic_ns"
    ]
    assert row["capture_started_wall_time_ns"] <= row[
        "capture_ended_wall_time_ns"
    ]


def test_workspace_snapshot_uses_git_candidates_and_skips_ignored_builds(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "git-workspace"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("build/\n", encoding="utf-8")
    tracked = repo / "tracked.py"
    tracked.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", ".gitignore", "tracked.py"], cwd=repo, check=True
    )
    (repo / "untracked.py").write_text("extra = True\n", encoding="utf-8")
    ignored = repo / "build" / "large.bin"
    ignored.parent.mkdir()
    ignored.write_bytes(b"x" * (2 * 1024 * 1024))

    run_dir = tmp_path / "git-trace"
    manager = SnapshotManager(repo, run_dir, baseline_source="workspace")
    manager.capture_baseline()
    baseline = json.loads(
        (run_dir / "snapshots" / "baseline_manifest.json").read_text()
    )
    paths = {row["path"] for row in baseline["files"]}
    assert "tracked.py" in paths
    assert "untracked.py" in paths
    assert "build/large.bin" not in paths
    assert manager.scan_stats["candidate_policy"] == (
        "git_cached_and_nonignored_untracked_workspace_bytes"
    )

    tracked.write_text("value = 2\n", encoding="utf-8")
    rows = manager.capture_after(5, {"id": "edit-git", "type": "fileChange"})
    manager.close()
    assert [row["path"] for row in rows] == ["tracked.py"]


def test_workspace_snapshot_rejects_symlinked_parent_components(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "git-safe"
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)
    source = source_dir / "x.py"
    source.write_text("SAFE = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "src/x.py"], cwd=repo, check=True)

    run_dir = tmp_path / "safe-trace"
    manager = SnapshotManager(repo, run_dir, baseline_source="workspace")
    manager.capture_baseline()

    source.unlink()
    source_dir.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("OUTSIDE_SECRET = 123\n", encoding="utf-8")
    source_dir.symlink_to(outside, target_is_directory=True)

    rows = manager.capture_after(6, {"id": "unsafe-edit", "type": "fileChange"})
    manager.close()
    src_row = next(row for row in rows if row["path"] == "src/x.py")
    assert src_row["kind"] == "delete"
    item_bytes = b"".join(
        path.read_bytes()
        for path in (run_dir / "snapshots" / "items").rglob("*")
        if path.is_file()
    )
    assert b"OUTSIDE_SECRET" not in item_bytes
