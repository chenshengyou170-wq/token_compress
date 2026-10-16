from __future__ import annotations

import asyncio
import copy
import inspect
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

JsonObject: TypeAlias = dict[str, Any]
RequestId: TypeAlias = int | str
MessageCallback: TypeAlias = Callable[[JsonObject], Awaitable[None] | None]
RequestHandler: TypeAlias = Callable[[Any], Awaitable[Any] | Any]
MessageTransform: TypeAlias = Callable[[JsonObject], JsonObject]


class AppServerError(RuntimeError):
    """Base error for the app-server transport."""


class AppServerProtocolError(AppServerError):
    """The child emitted data that is not a valid JSON-RPC message."""


class AppServerResponseError(AppServerError):
    """A JSON-RPC request completed with an error response."""

    def __init__(self, method: str, error: Any) -> None:
        super().__init__(f"{method} failed: {error}")
        self.method = method
        self.error = error


@dataclass(slots=True, frozen=True)
class Envelope:
    seq: int
    direction: str
    wall_time: float
    wall_time_ns: int
    mono_ns: int
    message: JsonObject

    def as_dict(self) -> JsonObject:
        return {
            "seq": self.seq,
            "direction": self.direction,
            "wall_time": self.wall_time,
            "wall_time_ns": self.wall_time_ns,
            "mono_ns": self.mono_ns,
            "message": self.message,
        }


class JsonlRecorder:
    """Line-buffered recorder for the exact client/server message stream."""

    def __init__(
        self, path: Path, *, transform: MessageTransform | None = None
    ) -> None:
        self.path = path
        self.transform = transform
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        self._fp = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
        self._closed = False

    def write(self, envelope: Envelope) -> None:
        if self._closed:
            raise RuntimeError("recorder is closed")
        row = envelope.as_dict()
        if self.transform is not None:
            # Capture transforms (normally redaction/bounding) apply only to the
            # persisted copy.  Routing and callbacks retain the exact protocol
            # message so capture policy cannot change client behaviour.
            transformed = self.transform(copy.deepcopy(envelope.message))
            if not isinstance(transformed, dict):
                raise TypeError("recorder transform must return a dict")
            row["message"] = transformed
        self._fp.write(json.dumps(row, ensure_ascii=False) + "\n")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._fp.close()


class AppServerClient:
    """Robust JSON-RPC-over-JSONL client for ``codex app-server``.

    Incoming callbacks run on a separate, bounded FIFO.  The stdout reader can
    therefore continue resolving JSON-RPC responses while an async callback is
    waiting for another client request.  Server-initiated requests are likewise
    handled in independent tasks and always receive either a result or a
    standards-based JSON-RPC error response.
    """

    def __init__(
        self,
        codex_bin: str,
        recorder: JsonlRecorder,
        on_message: MessageCallback | None = None,
        *,
        env: Mapping[str, str] | None = None,
        stderr_path: Path | None = None,
        callback_queue_size: int = 256,
        shutdown_timeout: float = 5.0,
        terminate_timeout: float = 2.0,
        kill_timeout: float = 2.0,
    ) -> None:
        if callback_queue_size < 1:
            raise ValueError("callback_queue_size must be at least 1")
        if min(shutdown_timeout, terminate_timeout, kill_timeout) < 0:
            raise ValueError("shutdown timeouts cannot be negative")

        self.codex_bin = codex_bin
        self.recorder = recorder
        self.on_message = on_message
        self.env = dict(env) if env is not None else None
        self.stderr_path = stderr_path
        self.shutdown_timeout = shutdown_timeout
        self.terminate_timeout = terminate_timeout
        self.kill_timeout = kill_timeout

        self.proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._callback_task: asyncio.Task[None] | None = None
        self._server_request_tasks: set[asyncio.Task[None]] = set()
        self._next_id = 1
        self._next_seq = 1
        self._pending: dict[RequestId, asyncio.Future[JsonObject]] = {}
        self._request_handlers: dict[str, RequestHandler] = {}

        # Kept public for observability/backwards compatibility, but unlike the
        # old queue this is bounded and is continuously consumed by our worker.
        self.events: asyncio.Queue[Envelope] = asyncio.Queue(maxsize=callback_queue_size)
        self._send_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._terminal_event = asyncio.Event()
        self._fatal_error: BaseException | None = None
        self._started = False
        self._closing = False
        self._closed = False

    def register_request_handler(self, method: str, handler: RequestHandler) -> None:
        """Register a handler for a server-to-client JSON-RPC request.

        The handler receives the request's ``params`` value (or ``{}`` when the
        field is absent) and may return either a value or an awaitable value.
        Registering a method again replaces its previous handler.
        """

        if not method:
            raise ValueError("request method cannot be empty")
        if not callable(handler):
            raise TypeError("request handler must be callable")
        self._request_handlers[method] = handler

    def _envelope(self, direction: str, message: JsonObject) -> Envelope:
        wall_time_ns = time.time_ns()
        envelope = Envelope(
            seq=self._next_seq,
            direction=direction,
            wall_time=wall_time_ns / 1_000_000_000,
            wall_time_ns=wall_time_ns,
            mono_ns=time.monotonic_ns(),
            message=message,
        )
        self._next_seq += 1
        self.recorder.write(envelope)
        return envelope

    @staticmethod
    def _is_request_id(value: Any) -> bool:
        # bool is an int subclass, but is not permitted by Codex's RequestId
        # schema (string | int64).
        return isinstance(value, str) or type(value) is int

    def _raise_if_unavailable(self) -> None:
        if self._fatal_error is not None:
            raise self._fatal_error
        if self._closed or self._closing:
            raise AppServerError("app-server client is closing or closed")
        if not self._started or self.proc is None or self.proc.stdin is None:
            raise AppServerError("app-server is not running")
        if self.proc.returncode is not None:
            raise AppServerError(
                f"app-server process has exited with status {self.proc.returncode}"
            )

    def _set_fatal(self, error: BaseException) -> None:
        if self._fatal_error is not None:
            return
        self._fatal_error = error
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()
        self._terminal_event.set()

    async def start(self) -> None:
        if self._started:
            raise AppServerError("app-server client has already been started")
        if self._closed:
            raise AppServerError("app-server client is closed")

        process_env: dict[str, str] | None = None
        if self.env is not None:
            process_env = os.environ.copy()
            process_env.update(self.env)

        stderr_stream = None
        if self.stderr_path is not None:
            self.stderr_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_CREAT | os.O_TRUNC | os.O_WRONLY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.stderr_path, flags, 0o600)
            os.fchmod(fd, 0o600)
            stderr_stream = os.fdopen(fd, "wb", buffering=0)
        try:
            self.proc = await asyncio.create_subprocess_exec(
                self.codex_bin,
                "app-server",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr_stream,
                env=process_env,
            )
        finally:
            if stderr_stream is not None:
                stderr_stream.close()
        self._started = True
        self._callback_task = asyncio.create_task(
            self._callback_loop(), name="codexscope-appserver-callback"
        )
        self._reader_task = asyncio.create_task(
            self._reader_loop(), name="codexscope-appserver-reader"
        )

    async def _reader_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    if not self._closing:
                        returncode = self.proc.returncode
                        suffix = "" if returncode is None else f" (status {returncode})"
                        raise AppServerError(
                            f"codex app-server stdout closed unexpectedly{suffix}"
                        )
                    break

                try:
                    decoded = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    diagnostic: JsonObject = {
                        "method": "client/invalidJson",
                        "params": {"raw": line.decode("utf-8", errors="replace")},
                    }
                    envelope = self._envelope("server_to_client", diagnostic)
                    await self.events.put(envelope)
                    raise AppServerProtocolError(
                        "codex app-server emitted invalid JSON"
                    ) from exc

                if not isinstance(decoded, dict):
                    diagnostic = {
                        "method": "client/invalidMessage",
                        "params": {"value": decoded},
                    }
                    envelope = self._envelope("server_to_client", diagnostic)
                    await self.events.put(envelope)
                    raise AppServerProtocolError(
                        "codex app-server emitted a non-object JSON-RPC message"
                    )

                message: JsonObject = decoded
                envelope = self._envelope("server_to_client", message)
                self._route_incoming(message)
                await self.events.put(envelope)
        except asyncio.CancelledError:
            if not self._closing and self._fatal_error is None:
                self._set_fatal(AppServerError("app-server reader was cancelled"))
            raise
        except BaseException as exc:
            self._set_fatal(exc)
        finally:
            if self._closing and self._fatal_error is None:
                self._terminal_event.set()

    def _route_incoming(self, message: JsonObject) -> None:
        message_id = message.get("id")
        method = message.get("method")

        if (
            self._is_request_id(message_id)
            and isinstance(method, str)
            and "result" not in message
            and "error" not in message
        ):
            task = asyncio.create_task(
                self._dispatch_server_request(message_id, method, message.get("params", {})),
                name=f"codexscope-server-request:{method}",
            )
            self._server_request_tasks.add(task)
            task.add_done_callback(self._server_request_done)
            return

        if self._is_request_id(message_id) and (
            "result" in message or "error" in message
        ):
            future = self._pending.pop(message_id, None)
            if future is not None and not future.done():
                future.set_result(message)

    def _server_request_done(self, task: asyncio.Task[None]) -> None:
        self._server_request_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None and not self._closing:
            self._set_fatal(error)

    async def _dispatch_server_request(
        self, request_id: RequestId, method: str, params: Any
    ) -> None:
        handler = self._request_handlers.get(method)
        if handler is None:
            response: JsonObject = {
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }
        else:
            try:
                result = handler(params)
                if inspect.isawaitable(result):
                    result = await result
                response = {"id": request_id, "result": result}
            except asyncio.CancelledError:
                raise
            except BaseException:
                response = {
                    "id": request_id,
                    "error": {"code": -32603, "message": "Internal error"},
                }

        await self._send(response)

    async def _callback_loop(self) -> None:
        while True:
            envelope = await self.events.get()
            try:
                if self.on_message is not None:
                    result = self.on_message(envelope.as_dict())
                    if inspect.isawaitable(result):
                        await result
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                error = AppServerError(f"app-server message callback failed: {exc}")
                error.__cause__ = exc
                self._set_fatal(error)
                if self._reader_task is not None and not self._reader_task.done():
                    self._reader_task.cancel()
                return
            finally:
                self.events.task_done()

    async def _send(self, message: JsonObject) -> None:
        async with self._send_lock:
            self._raise_if_unavailable()
            assert self.proc is not None and self.proc.stdin is not None
            try:
                self._envelope("client_to_server", message)
                payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
                self.proc.stdin.write((payload + "\n").encode("utf-8"))
                await self.proc.stdin.drain()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                error = AppServerError("failed to record or write to codex app-server")
                error.__cause__ = exc
                self._set_fatal(error)
                raise error

    async def request(
        self, method: str, params: dict[str, Any], timeout: float = 60.0
    ) -> Any:
        self._raise_if_unavailable()
        request_id: RequestId = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        future: asyncio.Future[JsonObject] = loop.create_future()
        self._pending[request_id] = future
        try:
            await self._send({"method": method, "id": request_id, "params": params})
            response = await asyncio.wait_for(future, timeout=timeout)
        finally:
            if self._pending.get(request_id) is future:
                self._pending.pop(request_id, None)
            if not future.done():
                future.cancel()

        if "error" in response:
            raise AppServerResponseError(method, response["error"])
        if "result" not in response:
            raise AppServerProtocolError(f"{method} response has no result")
        return response["result"]

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        await self._send({"method": method, "params": params})

    async def wait_reader_failure(self) -> None:
        """Wait until the transport terminates and propagate its fatal error.

        A graceful :meth:`close` makes this return normally.  Unexpected EOF,
        invalid protocol data, write failures, and callback failures are raised.
        """

        if not self._started and not self._closed:
            raise AppServerError("app-server client has not been started")
        await self._terminal_event.wait()
        if self._fatal_error is not None:
            raise self._fatal_error

    async def _wait_process(self, timeout: float) -> bool:
        assert self.proc is not None
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def _stop_process(self) -> None:
        if self.proc is None or self.proc.returncode is not None:
            return
        if await self._wait_process(self.shutdown_timeout):
            return

        try:
            self.proc.terminate()
        except ProcessLookupError:
            return
        if await self._wait_process(self.terminate_timeout):
            return

        try:
            self.proc.kill()
        except ProcessLookupError:
            return
        if not await self._wait_process(self.kill_timeout):
            self._set_fatal(AppServerError("app-server did not exit after kill"))

    @staticmethod
    async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
        if task is None or task.done():
            if task is not None:
                try:
                    task.result()
                except BaseException:
                    pass
            return
        task.cancel()
        try:
            await task
        except BaseException:
            pass

    def _drain_callback_queue(self) -> None:
        while True:
            try:
                self.events.get_nowait()
            except asyncio.QueueEmpty:
                return
            else:
                self.events.task_done()

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closing = True

            try:
                if self.proc is not None and self.proc.stdin is not None:
                    self.proc.stdin.close()
                    try:
                        await self.proc.stdin.wait_closed()
                    except (BrokenPipeError, ConnectionResetError):
                        pass

                await self._stop_process()

                if self._reader_task is not None and not self._reader_task.done():
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(self._reader_task),
                            timeout=self.shutdown_timeout,
                        )
                    except asyncio.TimeoutError:
                        await self._cancel_task(self._reader_task)

                for task in tuple(self._server_request_tasks):
                    await self._cancel_task(task)
                self._server_request_tasks.clear()

                if self._callback_task is not None and not self._callback_task.done():
                    try:
                        await asyncio.wait_for(
                            self.events.join(), timeout=self.shutdown_timeout
                        )
                    except asyncio.TimeoutError:
                        pass
                await self._cancel_task(self._callback_task)
                self._drain_callback_queue()

                if self._pending:
                    error = AppServerError("app-server client closed with pending requests")
                    for future in tuple(self._pending.values()):
                        if not future.done():
                            future.set_exception(error)
                    self._pending.clear()
            finally:
                self._closed = True
                self._terminal_event.set()
                self.recorder.close()
