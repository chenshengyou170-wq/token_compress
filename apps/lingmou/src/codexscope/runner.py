from __future__ import annotations

import asyncio
import json
import os
import time
import types
import uuid
from pathlib import Path
from typing import Any

from .appserver import AppServerClient, JsonlRecorder
from .environment import (
    capture_protocol_schema,
    capture_transform,
    codex_version,
    git_metadata,
    hash_json,
    runtime_metadata,
)
from .function_trace import FunctionTraceCollector, FunctionTraceConfig
from .snapshots import SnapshotManager
from .storage import RunLayout, atomic_json_dump
from .util import now_iso, sha256_text


_CAPTURE_AFTER_ITEM_TYPES = frozenset(
    {
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "dynamicToolCall",
        # A collab tool can mutate the same worktree through a subagent.  The
        # final reconcile is still authoritative, but scanning here preserves
        # the closest observable action boundary.
        # Current app-server schema uses collabAgentToolCall.  Keep the older
        # spelling for traces produced by earlier Codex builds.
        "collabAgentToolCall",
        "collabToolCall",
    }
)
_INTERRUPT_TIMEOUT_SECONDS = 5.0


class TurnProtocolError(RuntimeError):
    """The app-server emitted an invalid or unrelated terminal turn."""


class TurnFailedError(RuntimeError):
    """Codex reported a failed turn."""


class TurnInterruptedError(RuntimeError):
    """Codex reported an interrupted turn."""


class TraceTimeoutError(TimeoutError):
    """A Codex turn exceeded the configured trace deadline."""


def _redacted_value(value: Any, *, include_sensitive: bool = False) -> Any:
    transformed = capture_transform(
        {"value": value}, include_sensitive=include_sensitive
    )
    return transformed.get("value")


def _error_record(error: BaseException) -> dict[str, Any]:
    return {
        "type": type(error).__name__,
        "message": str(error),
    }


def _required_id(container: Any, key: str, *, context: str) -> str:
    if not isinstance(container, dict):
        raise TurnProtocolError(f"{context} is not an object")
    value = container.get(key)
    if not isinstance(value, str) or not value:
        raise TurnProtocolError(f"{context}.{key} is missing or invalid")
    return value


def _turn_error_text(error: Any) -> str:
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    try:
        return json.dumps(error, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(error)


def _validate_terminal_turn(
    params: Any, *, expected_thread_id: str, expected_turn_id: str
) -> dict[str, Any]:
    if not isinstance(params, dict):
        raise TurnProtocolError("turn/completed params is not an object")

    thread_id = _required_id(params, "threadId", context="turn/completed params")
    if thread_id != expected_thread_id:
        raise TurnProtocolError(
            "turn/completed belongs to an unexpected thread "
            f"({thread_id!r}, expected {expected_thread_id!r})"
        )

    turn = params.get("turn")
    turn_id = _required_id(turn, "id", context="turn/completed turn")
    if turn_id != expected_turn_id:
        raise TurnProtocolError(
            "turn/completed belongs to an unexpected turn "
            f"({turn_id!r}, expected {expected_turn_id!r})"
        )
    assert isinstance(turn, dict)

    status = turn.get("status")
    error = turn.get("error")
    if status == "completed":
        if error is not None:
            raise TurnProtocolError("completed turn unexpectedly contains an error")
        return turn
    if status == "failed":
        detail = _turn_error_text(error)
        raise TurnFailedError(f"Codex turn {turn_id} failed: {detail}")
    if status == "interrupted":
        detail = "" if error is None else f": {_turn_error_text(error)}"
        raise TurnInterruptedError(f"Codex turn {turn_id} was interrupted{detail}")
    raise TurnProtocolError(
        f"turn/completed has invalid terminal status {status!r}"
    )


async def _interrupt_turn(
    client: AppServerClient, thread_id: str, turn_id: str
) -> dict[str, Any]:
    try:
        await client.request(
            "turn/interrupt",
            {"threadId": thread_id, "turnId": turn_id},
            timeout=_INTERRUPT_TIMEOUT_SECONDS,
        )
    except BaseException as exc:
        return {"requested": True, "succeeded": False, "error": _error_record(exc)}
    return {"requested": True, "succeeded": True}


async def _wait_for_terminal_or_reader_failure(
    client: AppServerClient,
    terminal: asyncio.Future[dict[str, Any]],
    *,
    timeout_seconds: float,
    thread_id: str,
    turn_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    terminal_task = asyncio.ensure_future(asyncio.shield(terminal))
    reader_task = asyncio.create_task(
        client.wait_reader_failure(), name="codexscope-reader-failure"
    )
    try:
        done, _ = await asyncio.wait(
            {terminal_task, reader_task},
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done:
            interrupt = await _interrupt_turn(client, thread_id, turn_id)
            error = TraceTimeoutError(
                f"Codex turn {turn_id} exceeded {timeout_seconds:g} seconds"
            )
            # The caller records the interruption evidence in the manifest.
            setattr(error, "interrupt", interrupt)
            raise error

        # Prefer transport integrity if both futures become ready together.  A
        # terminal notification received just before a reader crash does not
        # prove that the complete protocol stream was captured.
        if reader_task in done:
            await reader_task
            raise TurnProtocolError(
                "app-server transport ended before trace shutdown"
            )
        return await terminal_task, None
    finally:
        for task in (terminal_task, reader_task):
            if not task.done():
                task.cancel()
            try:
                await task
            except (asyncio.CancelledError, BaseException):
                pass


def _register_noninteractive_handlers(client: AppServerClient) -> None:
    """Make an unexpected server request terminate promptly, never block."""

    client.register_request_handler(
        "item/commandExecution/requestApproval",
        lambda _params: {"decision": "decline"},
    )
    client.register_request_handler(
        "item/fileChange/requestApproval",
        lambda _params: {"decision": "decline"},
    )
    client.register_request_handler(
        "item/permissions/requestApproval",
        lambda _params: {"permissions": {}, "scope": "turn"},
    )
    client.register_request_handler(
        "item/tool/requestUserInput", lambda _params: {"answers": {}}
    )
    client.register_request_handler(
        "mcpServer/elicitation/request", lambda _params: {"action": "decline"}
    )
    # Legacy approval requests are retained for compatibility with older
    # app-server builds.  They should not occur with approvalPolicy=never.
    client.register_request_handler(
        "execCommandApproval", lambda _params: {"decision": "denied"}
    )
    client.register_request_handler(
        "applyPatchApproval", lambda _params: {"decision": "denied"}
    )


async def run_codex_trace(
    repo: Path,
    prompt: str,
    run_dir: Path,
    codex_bin: str = "codex",
    model: str | None = None,
    timeout_seconds: float = 1800,
    *,
    include_sensitive: bool = False,
    capture_schema: bool = True,
    function_trace: str = "off",
    function_max_calls: int = 100_000,
) -> None:
    """Run one non-interactive Codex turn and persist an auditable trace.

    The observed worktree must be clean and the trace layout is created outside
    it.  Once ``manifest.json`` enters ``running``, every exit path atomically
    records exactly one terminal status before propagating the original error.
    """

    repo = repo.expanduser().resolve()
    run_dir = run_dir.expanduser().resolve()
    trace_config = FunctionTraceConfig(
        mode=function_trace,
        max_calls_per_process=function_max_calls,
        max_records_per_run=max(10_000, min(2_000_000, function_max_calls * 4)),
    )

    # Validate the observed state before creating any trace artifacts.
    git = await asyncio.to_thread(git_metadata, repo, require_clean=True)
    layout = RunLayout.create(run_dir, repo=repo)

    started_mono_ns = time.monotonic_ns()
    sandbox_policy: dict[str, Any] = {
        "type": "workspaceWrite",
        "writableRoots": [os.fspath(repo)],
        "networkAccess": False,
        "excludeTmpdirEnvVar": False,
        "excludeSlashTmp": False,
    }
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "status": "running",
        "created_at": now_iso(),
        "started_at": now_iso(),
        "runtime": runtime_metadata(),
        "git": git,
        **git,
        "prompt_sha256": sha256_text(prompt),
        "prompt_length": len(prompt),
        "codex_bin": codex_bin,
        "codex_version": None,
        "model_requested": model,
        "model_resolved": None,
        "config_sha256": None,
        "approval_policy": "never",
        "sandbox_policy": sandbox_policy,
        "protocol_schema": {
            "captured": False,
            "pending": bool(capture_schema),
        },
        "function_trace": {
            "requested": trace_config.mode,
            "enabled": trace_config.enabled,
            "languages": list(trace_config.languages),
            "raw_schema": "codexscope.function_trace.v1",
            "max_calls_per_process": trace_config.max_calls_per_process,
            "max_records_per_run": trace_config.max_records_per_run,
            "max_bytes_per_run": trace_config.max_bytes_per_run,
            "trust": "instrumented_process_self_report; peer_pid_when_supported",
            "tamper_resistant": False,
        },
    }
    atomic_json_dump(layout.manifest, manifest)

    recorder: JsonlRecorder | None = None
    client: AppServerClient | None = None
    snapshots: SnapshotManager | None = None
    thread_id: str | None = None
    turn_id: str | None = None
    caught: BaseException | None = None
    caught_traceback: types.TracebackType | None = None
    terminal_status = "completed"
    cleanup_errors: list[dict[str, Any]] = []
    function_collector: FunctionTraceCollector | None = None

    try:
        version = await asyncio.to_thread(codex_version, codex_bin)
        manifest["codex_version"] = version
        manifest["codex"] = {"binary": codex_bin, "version": version}

        if capture_schema:
            schema = await asyncio.to_thread(
                capture_protocol_schema, codex_bin, layout.root / "protocol"
            )
        else:
            schema = {"captured": False, "skipped": True}
        manifest["protocol_schema"] = schema
        atomic_json_dump(layout.manifest, manifest)

        snapshots = SnapshotManager(repo, layout.root)
        await asyncio.to_thread(snapshots.capture_baseline)

        if trace_config.enabled:
            function_collector = await asyncio.to_thread(
                FunctionTraceCollector.start, layout.functions_raw, trace_config
            )

        terminal: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        terminal_candidates: list[dict[str, Any]] = []

        def terminal_matches(params: dict[str, Any]) -> bool:
            if thread_id is None or turn_id is None:
                return False
            turn_value = params.get("turn")
            candidate_turn_id = (
                turn_value.get("id") if isinstance(turn_value, dict) else None
            )
            return (
                params.get("threadId") == thread_id
                and candidate_turn_id == turn_id
            )

        async def on_message(envelope: dict[str, Any]) -> None:
            message = envelope.get("message")
            if not isinstance(message, dict):
                raise TurnProtocolError("app-server callback message is not an object")
            method = message.get("method")
            params = message.get("params")

            if method == "item/completed" and isinstance(params, dict):
                item = params.get("item")
                if (
                    isinstance(item, dict)
                    and item.get("type") in _CAPTURE_AFTER_ITEM_TYPES
                ):
                    seq = envelope.get("seq")
                    if not isinstance(seq, int):
                        raise TurnProtocolError(
                            "item/completed envelope has no integer sequence"
                        )
                    # Hashing a worktree is blocking and can be substantial.  It
                    # belongs after the item's terminal event, off the protocol
                    # event loop, while callback FIFO preserves action order.
                    await asyncio.to_thread(snapshots.capture_after, seq, item)

            if method == "turn/completed" and not terminal.done():
                if not isinstance(params, dict):
                    terminal.set_exception(
                        TurnProtocolError("turn/completed params is not an object")
                    )
                elif terminal_matches(params):
                    terminal.set_result(params)
                elif thread_id is None or turn_id is None:
                    # Subagents and resumed background threads emit the same
                    # notification.  Keep early candidates until turn/start's
                    # response establishes the main turn id, then ignore all
                    # unrelated terminal events.
                    terminal_candidates.append(params)

        recorder = JsonlRecorder(
            layout.appserver_raw,
            transform=lambda message: capture_transform(
                message, include_sensitive=include_sensitive
            ),
        )
        try:
            layout.appserver_raw.chmod(0o600)
        except OSError:
            pass

        child_env = {
            "CODEXSCOPE_HOOK_SPOOL": os.fspath(layout.hooks_raw),
            "CODEXSCOPE_INCLUDE_SENSITIVE": "1" if include_sensitive else "0",
        }
        if function_collector is not None:
            child_env.update(
                function_collector.child_environment(
                    repo, run_id=str(manifest["run_id"])
                )
            )

        client = AppServerClient(
            codex_bin=codex_bin,
            recorder=recorder,
            on_message=on_message,
            env=child_env,
            stderr_path=layout.appserver_stderr,
        )
        _register_noninteractive_handlers(client)
        await client.start()

        initialize_result = await client.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "codexscope",
                    "title": "CodexScope",
                    "version": str(runtime_metadata()["codexscope_version"]),
                }
            },
        )
        await client.notify("initialized", {})

        environment: dict[str, Any] = {
            "schema_version": "1.0",
            "captured_at": now_iso(),
            "initialize": _redacted_value(
                initialize_result, include_sensitive=include_sensitive
            ),
        }
        try:
            config_result = await client.request(
                "config/read", {"cwd": os.fspath(repo), "includeLayers": True}
            )
        except Exception as exc:
            config_result = None
            environment["config_read"] = {
                "available": False,
                "error": _error_record(exc),
            }
            manifest["config_read_error"] = _error_record(exc)
        else:
            if not isinstance(config_result, dict):
                raise TurnProtocolError("config/read result is not an object")
            effective_config = config_result.get("config")
            manifest["config_sha256"] = hash_json(effective_config)
            environment["config_read"] = {
                "available": True,
                "response": _redacted_value(
                    config_result, include_sensitive=include_sensitive
                ),
                "config_sha256": manifest["config_sha256"],
            }
        atomic_json_dump(layout.root / "environment.json", environment)

        thread_params: dict[str, Any] = {
            "cwd": os.fspath(repo),
            "approvalPolicy": "never",
            "sandbox": "workspace-write",
            "serviceName": "codexscope",
        }
        if model is not None:
            thread_params["model"] = model
        thread_result = await client.request("thread/start", thread_params)
        if not isinstance(thread_result, dict):
            raise TurnProtocolError("thread/start result is not an object")
        thread = thread_result.get("thread")
        thread_id = _required_id(thread, "id", context="thread/start thread")

        resolved_model = thread_result.get("model")
        if not isinstance(resolved_model, str) or not resolved_model:
            resolved_model = model
        instruction_sources = thread_result.get("instructionSources", [])
        if not isinstance(instruction_sources, list):
            raise TurnProtocolError("thread/start instructionSources is not an array")
        instruction_sources = [
            source for source in instruction_sources if isinstance(source, str)
        ]

        manifest.update(
            {
                "thread_id": thread_id,
                "model_resolved": resolved_model,
                "model_provider": thread_result.get("modelProvider"),
                "instruction_sources": instruction_sources,
                "effective_approval_policy": thread_result.get("approvalPolicy"),
                "effective_sandbox_policy": _redacted_value(
                    thread_result.get("sandbox"),
                    include_sensitive=include_sensitive,
                ),
            }
        )
        environment["thread"] = {
            "id": thread_id,
            "model": resolved_model,
            "model_provider": thread_result.get("modelProvider"),
            "instruction_sources": instruction_sources,
            "approval_policy": thread_result.get("approvalPolicy"),
            "sandbox": _redacted_value(
                thread_result.get("sandbox"),
                include_sensitive=include_sensitive,
            ),
        }
        atomic_json_dump(layout.root / "environment.json", environment)
        atomic_json_dump(layout.manifest, manifest)

        turn_params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [{"type": "text", "text": prompt}],
            "cwd": os.fspath(repo),
            "approvalPolicy": "never",
            "sandboxPolicy": sandbox_policy,
        }
        if model is not None:
            turn_params["model"] = model
        turn_result = await client.request("turn/start", turn_params)
        if not isinstance(turn_result, dict):
            raise TurnProtocolError("turn/start result is not an object")
        turn = turn_result.get("turn")
        turn_id = _required_id(turn, "id", context="turn/start turn")
        manifest["turn_id"] = turn_id
        atomic_json_dump(layout.manifest, manifest)

        for candidate in terminal_candidates:
            if terminal_matches(candidate):
                if not terminal.done():
                    terminal.set_result(candidate)
                break
        terminal_candidates.clear()

        terminal_params, _ = await _wait_for_terminal_or_reader_failure(
            client,
            terminal,
            timeout_seconds=timeout_seconds,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        completed_turn = _validate_terminal_turn(
            terminal_params,
            expected_thread_id=thread_id,
            expected_turn_id=turn_id,
        )
        manifest["turn_status"] = completed_turn.get("status")
        if "durationMs" in completed_turn:
            manifest["turn_duration_ms"] = completed_turn.get("durationMs")
    except BaseException as exc:
        caught = exc
        caught_traceback = exc.__traceback__
        if isinstance(exc, TraceTimeoutError):
            terminal_status = "timeout"
            interrupt = getattr(exc, "interrupt", None)
            if isinstance(interrupt, dict):
                manifest["interrupt"] = interrupt
        elif isinstance(
            exc, (TurnInterruptedError, asyncio.CancelledError, KeyboardInterrupt)
        ):
            terminal_status = "interrupted"
            if (
                not isinstance(exc, TurnInterruptedError)
                and client is not None
                and thread_id is not None
                and turn_id is not None
            ):
                manifest["interrupt"] = await _interrupt_turn(
                    client, thread_id, turn_id
                )
        else:
            terminal_status = "failed"

    # Close the transport first so its callback FIFO cannot race the final
    # workspace reconcile.  SnapshotManager.close() performs that reconcile.
    if client is not None:
        try:
            await client.close()
        except BaseException as exc:
            cleanup_errors.append(_error_record(exc))
            if caught is None:
                caught = exc
                caught_traceback = exc.__traceback__
                terminal_status = "failed"
    elif recorder is not None:
        try:
            recorder.close()
        except BaseException as exc:
            cleanup_errors.append(_error_record(exc))
            if caught is None:
                caught = exc
                caught_traceback = exc.__traceback__
                terminal_status = "failed"

    # The app-server and its foreground tool children are gone before the
    # receiver is drained. Runtime processes never receive write access to the
    # run directory; only this collector writes the raw artifact.
    if function_collector is not None:
        try:
            function_stats = await asyncio.to_thread(function_collector.close)
            manifest["function_trace"]["collector"] = function_stats
            manifest["function_trace"]["trust"] = (
                "instrumented_process_self_report_with_unix_peer_pid"
                if function_stats.get("peer_credentials")
                else "instrumented_process_self_report_only"
            )
            atomic_json_dump(
                layout.function_trace_summary,
                {
                    "schema_version": "1.0",
                    "mode": trace_config.mode,
                    "languages": list(trace_config.languages),
                    "collector": function_stats,
                    "loss_counts_are_observed_lower_bounds": True,
                    "limitations": [
                        "cooperative_instrumentation",
                        "target_can_disable_or_forge_function_identity",
                        "background_processes_after_collector_close_are_not_observed",
                        "sender_drop_counts_can_be_underreported_after_abrupt_exit",
                        "processed_json_and_graph_can_exceed_raw_trace_size",
                    ],
                },
            )
        except BaseException as exc:
            cleanup_errors.append(_error_record(exc))
            manifest["function_trace"]["collector_error"] = _error_record(exc)
            if caught is None:
                caught = exc
                caught_traceback = exc.__traceback__
                terminal_status = "failed"

    if snapshots is not None:
        try:
            await asyncio.to_thread(snapshots.close)
        except BaseException as exc:
            cleanup_errors.append(_error_record(exc))
            if caught is None:
                caught = exc
                caught_traceback = exc.__traceback__
                terminal_status = "failed"

    manifest["status"] = terminal_status
    manifest["finished_at"] = now_iso()
    manifest["duration_ms"] = (time.monotonic_ns() - started_mono_ns) / 1_000_000
    if caught is not None:
        manifest["error"] = _redacted_value(_error_record(caught))
    if cleanup_errors:
        manifest["cleanup_errors"] = _redacted_value(cleanup_errors)
    atomic_json_dump(layout.manifest, manifest)

    if caught is not None:
        raise caught.with_traceback(caught_traceback)
