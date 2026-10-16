"""WebSocket-over-Unix-socket gateway for Codex remote TUI.

``codex --remote unix://PATH`` speaks one JSON-RPC message per WebSocket text
frame.  :class:`UnixSocketGateway` keeps that transport intact while exposing
copies of valid JSON object messages to an observer callback.  The default is
fully transparent.  Callers may explicitly install a narrow message
interceptor for pre-execution policy decisions; intercepted requests and the
locally generated response are both exposed to the observer.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import socket
import stat
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeAlias

from websockets.asyncio.client import ClientConnection, unix_connect
from websockets.asyncio.server import Server, ServerConnection, unix_serve
from websockets.exceptions import ConnectionClosed


JsonObject: TypeAlias = dict[str, Any]
Direction: TypeAlias = Literal["client_to_server", "server_to_client"]
CallbackPayload: TypeAlias = dict[str, Any]
GatewayCallback: TypeAlias = Callable[
    [CallbackPayload], Awaitable[None] | None
]
CallbackBarrier: TypeAlias = Callable[[CallbackPayload], bool]


@dataclass(slots=True, frozen=True)
class GatewayInterception:
    """A locally generated JSON-RPC response replacing one forwarded request."""

    response: JsonObject
    metadata: JsonObject


MessageInterceptor: TypeAlias = Callable[
    [CallbackPayload],
    GatewayInterception | Awaitable[GatewayInterception | None] | None,
]


class GatewayError(RuntimeError):
    """Base error for the transparent gateway."""


class GatewayProtocolError(GatewayError):
    """A peer sent a frame that the Codex JSON-RPC transport doesn't support."""


@dataclass(slots=True, frozen=True)
class GatewayEnvelope:
    """An observed JSON object crossing the gateway."""

    seq: int
    connection_id: str
    direction: Direction
    wall_time: float
    wall_time_ns: int
    mono_ns: int
    message: JsonObject

    def as_dict(self) -> CallbackPayload:
        return {
            "seq": self.seq,
            "connection_id": self.connection_id,
            "direction": self.direction,
            "wall_time": self.wall_time,
            "wall_time_ns": self.wall_time_ns,
            "mono_ns": self.mono_ns,
            "message": self.message,
        }


@dataclass(slots=True, frozen=True)
class GatewayConnectionEvent:
    """Connection lifecycle information passed to connection callbacks."""

    event: Literal["connected", "disconnected"]
    connection_id: str
    wall_time: float
    wall_time_ns: int
    mono_ns: int
    close_code: int | None = None
    close_reason: str | None = None
    error: str | None = None

    def as_dict(self) -> CallbackPayload:
        return {
            "event": self.event,
            "connection_id": self.connection_id,
            "wall_time": self.wall_time,
            "wall_time_ns": self.wall_time_ns,
            "mono_ns": self.mono_ns,
            "close_code": self.close_code,
            "close_reason": self.close_reason,
            "error": self.error,
        }


@dataclass(slots=True)
class _CallbackItem:
    callback: GatewayCallback
    payload: CallbackPayload
    completion: asyncio.Future[None] | None = None


class UnixSocketGateway:
    """Proxy a single active Codex TUI to an app-server Unix socket.

    The first active frontend connection is bridged to ``backend_path``.  A
    concurrent second connection completes its WebSocket handshake and is then
    closed explicitly with code 1013.  Once the active TUI disconnects, a new
    TUI may connect.

    Message and lifecycle callbacks run on a separate FIFO worker.  This keeps
    a slow synchronous or asynchronous observer out of the transport pumps.
    ``callback_barrier`` may select the rare messages whose observer callback
    must finish before their original frame is forwarded (for example, a
    workspace snapshot boundary).  Callback failures are retained in
    :attr:`callback_errors` and don't break the user's interactive session.
    """

    def __init__(
        self,
        frontend_path: Path | str,
        backend_path: Path | str,
        *,
        on_message: GatewayCallback | None = None,
        on_connect: GatewayCallback | None = None,
        on_disconnect: GatewayCallback | None = None,
        callback_barrier: CallbackBarrier | None = None,
        message_interceptor: MessageInterceptor | None = None,
        callback_queue_size: int = 256,
        open_timeout: float = 10.0,
        close_timeout: float = 2.0,
        shutdown_timeout: float = 5.0,
    ) -> None:
        if callback_queue_size < 1:
            raise ValueError("callback_queue_size must be at least 1")
        if min(open_timeout, close_timeout, shutdown_timeout) < 0:
            raise ValueError("gateway timeouts cannot be negative")

        self.frontend_path = Path(frontend_path)
        self.backend_path = Path(backend_path)
        if not self.frontend_path.is_absolute():
            raise ValueError("frontend_path must be absolute")
        if not self.backend_path.is_absolute():
            raise ValueError("backend_path must be absolute")
        if self.frontend_path == self.backend_path:
            raise ValueError("frontend_path and backend_path must be different")

        self.on_message = on_message
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.callback_barrier = callback_barrier
        self.message_interceptor = message_interceptor
        self.open_timeout = open_timeout
        self.close_timeout = close_timeout
        self.shutdown_timeout = shutdown_timeout

        self.ready = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._server: Server | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._callback_queue: asyncio.Queue[_CallbackItem] = asyncio.Queue(
            maxsize=callback_queue_size
        )
        self._callback_task: asyncio.Task[None] | None = None
        self._callback_errors: list[BaseException] = []
        self._handler_tasks: set[asyncio.Task[Any]] = set()

        self._active_lock = asyncio.Lock()
        self._active_connection_id: str | None = None
        self._active_frontend: ServerConnection | None = None
        self._active_backend: ClientConnection | None = None
        self._next_connection = 1
        self._next_seq = 1

        self._close_lock = asyncio.Lock()
        self._started = False
        self._closing = False
        self._closed = False

    @property
    def endpoint(self) -> str:
        """Endpoint accepted by ``codex --remote``."""

        return f"unix://{self.frontend_path}"

    @property
    def active_connection_id(self) -> str | None:
        return self._active_connection_id

    @property
    def callback_errors(self) -> tuple[BaseException, ...]:
        """Observer failures encountered since :meth:`start`."""

        return tuple(self._callback_errors)

    async def start(self) -> None:
        """Bind the public Unix socket and mark :attr:`ready`."""

        if self._started:
            raise GatewayError("gateway has already been started")
        if self._closed:
            raise GatewayError("gateway is closed")
        if not hasattr(socket, "AF_UNIX"):
            raise GatewayError("Unix sockets aren't supported on this platform")

        self.frontend_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.frontend_path.exists() or self.frontend_path.is_symlink():
            raise GatewayError(
                f"frontend socket path already exists: {self.frontend_path}"
            )

        self._callback_task = asyncio.create_task(
            self._callback_loop(), name="codexscope-gateway-callback"
        )
        try:
            self._server = await unix_serve(
                self._handle_frontend,
                path=os.fspath(self.frontend_path),
                open_timeout=self.open_timeout,
                close_timeout=self.close_timeout,
                max_size=None,
                # Codex app-server's Unix listener currently implements the
                # base WebSocket protocol without permessage-deflate.
                compression=None,
            )
            socket_stat = self.frontend_path.lstat()
            if not stat.S_ISSOCK(socket_stat.st_mode):
                raise GatewayError(
                    f"frontend listener isn't a Unix socket: {self.frontend_path}"
                )
            self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)
            os.chmod(self.frontend_path, 0o600)
        except BaseException:
            if self._server is not None:
                self._server.close(close_connections=True)
                try:
                    await asyncio.wait_for(
                        self._server.wait_closed(),
                        timeout=max(self.close_timeout, 0.001),
                    )
                except BaseException:
                    pass
                self._server = None
            await self._stop_callback_worker(drain=False)
            self._unlink_owned_socket()
            raise

        self._started = True
        self.ready.set()

    async def _handle_frontend(self, frontend: ServerConnection) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handler_tasks.add(task)

        connection_id: str | None = None
        backend: ClientConnection | None = None
        error: BaseException | None = None
        try:
            async with self._active_lock:
                if self._closing or self._active_connection_id is not None:
                    rejected = True
                else:
                    rejected = False
                    connection_id = f"connection-{self._next_connection}"
                    self._next_connection += 1
                    self._active_connection_id = connection_id
                    self._active_frontend = frontend

            if rejected:
                await frontend.close(
                    code=1013,
                    reason="another Codex TUI is already connected",
                )
                return

            assert connection_id is not None
            await self._emit_connection(
                self.on_connect,
                GatewayConnectionEvent(
                    event="connected",
                    connection_id=connection_id,
                    **self._timestamp(),
                ),
            )

            try:
                backend = await unix_connect(
                    path=os.fspath(self.backend_path),
                    open_timeout=self.open_timeout,
                    close_timeout=self.close_timeout,
                    max_size=None,
                    compression=None,
                )
            except BaseException as exc:
                error = exc
                await frontend.close(
                    code=1011, reason="Codex app-server is unavailable"
                )
                return

            async with self._active_lock:
                if self._active_connection_id == connection_id:
                    self._active_backend = backend

            error = await self._bridge(frontend, backend, connection_id)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            error = exc
        finally:
            if backend is not None:
                await self._close_connection(backend)
            await self._close_connection(frontend)

            if connection_id is not None:
                close_code = frontend.close_code
                close_reason = frontend.close_reason
                if close_code is None and backend is not None:
                    close_code = backend.close_code
                    close_reason = backend.close_reason

                await self._emit_connection(
                    self.on_disconnect,
                    GatewayConnectionEvent(
                        event="disconnected",
                        connection_id=connection_id,
                        close_code=close_code,
                        close_reason=close_reason or None,
                        error=None if error is None else str(error),
                        **self._timestamp(),
                    ),
                    nonblocking=self._closing,
                )

                async with self._active_lock:
                    if self._active_connection_id == connection_id:
                        self._active_connection_id = None
                        self._active_frontend = None
                        self._active_backend = None

            if task is not None:
                self._handler_tasks.discard(task)

    async def _bridge(
        self,
        frontend: ServerConnection,
        backend: ClientConnection,
        connection_id: str,
    ) -> BaseException | None:
        client_to_server = asyncio.create_task(
            self._pump(
                frontend,
                backend,
                "client_to_server",
                connection_id,
            ),
            name=f"codexscope-gateway-c2s:{connection_id}",
        )
        server_to_client = asyncio.create_task(
            self._pump(
                backend,
                frontend,
                "server_to_client",
                connection_id,
            ),
            name=f"codexscope-gateway-s2c:{connection_id}",
        )
        tasks = {client_to_server, server_to_client}
        task_sources = {
            client_to_server: frontend,
            server_to_client: backend,
        }
        error: BaseException | None = None
        try:
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            completed = next(iter(done))
            source = task_sources[completed]
            for finished in done:
                try:
                    finished.result()
                except ConnectionClosed as exc:
                    if error is None:
                        error = exc
                except BaseException as exc:
                    if error is None:
                        error = exc

            code, reason = self._forwardable_close(source.close_code, source.close_reason)
            if isinstance(error, GatewayProtocolError):
                code, reason = 1003, str(error)
            elif error is not None and code == 1000:
                code, reason = 1011, "gateway transport error"

            await asyncio.gather(
                self._close_connection(frontend, code=code, reason=reason),
                self._close_connection(backend, code=code, reason=reason),
                return_exceptions=True,
            )
            for remaining in pending:
                remaining.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            return error
        except asyncio.CancelledError:
            for bridge_task in tasks:
                bridge_task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def _pump(
        self,
        source: ServerConnection | ClientConnection,
        target: ServerConnection | ClientConnection,
        direction: Direction,
        connection_id: str,
    ) -> None:
        async for frame in source:
            if not isinstance(frame, str):
                raise GatewayProtocolError(
                    f"binary WebSocket frame isn't supported ({direction})"
                )

            message = self._json_object(frame)
            interception: GatewayInterception | None = None
            if message is not None and (
                self.on_message is not None or self.message_interceptor is not None
            ):
                envelope = GatewayEnvelope(
                    seq=self._next_seq,
                    connection_id=connection_id,
                    direction=direction,
                    message=message,
                    **self._timestamp(),
                )
                self._next_seq += 1
                payload = envelope.as_dict()
                if self.message_interceptor is not None:
                    try:
                        candidate = self.message_interceptor(payload)
                        if inspect.isawaitable(candidate):
                            candidate = await candidate
                        if candidate is not None and not isinstance(
                            candidate, GatewayInterception
                        ):
                            raise TypeError(
                                "message_interceptor must return GatewayInterception or None"
                            )
                        interception = candidate
                    except Exception as exc:
                        # Policy failure is fail-open to the normal Codex approval
                        # UI, never an implicit approval.  The error remains visible
                        # to the monitor and the original request is forwarded.
                        self._callback_errors.append(exc)
                        interception = None
                if interception is not None:
                    payload["interception"] = dict(interception.metadata)
                wait_for_callback = False
                if self.callback_barrier is not None:
                    try:
                        wait_for_callback = bool(self.callback_barrier(payload))
                    except BaseException as exc:
                        # A boundary selector is observational policy.  Its
                        # failure must be visible to the caller without
                        # corrupting or stopping the interactive transport.
                        self._callback_errors.append(exc)
                if self.on_message is not None:
                    await self._enqueue_callback(
                        self.on_message,
                        payload,
                        wait=wait_for_callback or interception is not None,
                    )

            if interception is not None:
                synthetic_direction: Direction = (
                    "client_to_server"
                    if direction == "server_to_client"
                    else "server_to_client"
                )
                synthetic = GatewayEnvelope(
                    seq=self._next_seq,
                    connection_id=connection_id,
                    direction=synthetic_direction,
                    message=dict(interception.response),
                    **self._timestamp(),
                )
                self._next_seq += 1
                synthetic_payload = synthetic.as_dict()
                synthetic_payload["synthetic"] = True
                synthetic_payload["interception"] = dict(interception.metadata)
                if self.on_message is not None:
                    await self._enqueue_callback(
                        self.on_message,
                        synthetic_payload,
                        wait=True,
                    )
                await source.send(
                    json.dumps(
                        interception.response,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                continue

            # Forward the original string, including whitespace and key order.
            await target.send(frame)

    @staticmethod
    def _json_object(frame: str) -> JsonObject | None:
        try:
            decoded = json.loads(frame)
        except json.JSONDecodeError:
            return None
        return decoded if isinstance(decoded, dict) else None

    @staticmethod
    def _timestamp() -> dict[str, int | float]:
        wall_time_ns = time.time_ns()
        return {
            "wall_time": wall_time_ns / 1_000_000_000,
            "wall_time_ns": wall_time_ns,
            "mono_ns": time.monotonic_ns(),
        }

    @staticmethod
    def _forwardable_close(
        code: int | None, reason: str | None
    ) -> tuple[int, str]:
        # 1005, 1006, and 1015 are reserved and cannot appear in a close frame.
        if code is None or code in {1005, 1006, 1015}:
            return 1001, "peer connection closed"
        return code, reason or ""

    async def _emit_connection(
        self,
        callback: GatewayCallback | None,
        event: GatewayConnectionEvent,
        *,
        nonblocking: bool = False,
    ) -> None:
        if callback is None:
            return
        item = _CallbackItem(callback, event.as_dict())
        if nonblocking:
            try:
                self._callback_queue.put_nowait(item)
            except asyncio.QueueFull:
                # Shutdown must never wait forever on an observer.  Retain an
                # explicit error so callers can report the dropped event.
                self._callback_errors.append(
                    GatewayError("gateway callback queue was full during shutdown")
                )
            return
        await self._callback_queue.put(item)

    async def _enqueue_callback(
        self,
        callback: GatewayCallback,
        payload: CallbackPayload,
        *,
        wait: bool = False,
    ) -> None:
        completion = (
            asyncio.get_running_loop().create_future() if wait else None
        )
        await self._callback_queue.put(
            _CallbackItem(callback, payload, completion=completion)
        )
        if completion is not None:
            # Shielding leaves the FIFO observer able to finish (and lets the
            # monitor drain its snapshot worker) if a peer disconnects while a
            # selected boundary is being captured.
            await asyncio.shield(completion)

    async def _callback_loop(self) -> None:
        while True:
            item = await self._callback_queue.get()
            try:
                assert isinstance(item, _CallbackItem)
                try:
                    result = item.callback(item.payload)
                    if inspect.isawaitable(result):
                        await result
                except asyncio.CancelledError:
                    raise
                except BaseException as exc:
                    self._callback_errors.append(exc)
            finally:
                if item.completion is not None and not item.completion.done():
                    item.completion.set_result(None)
                self._callback_queue.task_done()

    async def _close_connection(
        self,
        connection: ServerConnection | ClientConnection,
        *,
        code: int = 1001,
        reason: str = "gateway is closing",
    ) -> None:
        try:
            await asyncio.wait_for(
                connection.close(code=code, reason=reason),
                timeout=max(self.close_timeout, 0.001),
            )
        except (asyncio.TimeoutError, ConnectionClosed, OSError):
            transport = getattr(connection, "transport", None)
            if transport is not None:
                transport.abort()

    async def _stop_callback_worker(self, *, drain: bool) -> None:
        task = self._callback_task
        if task is None:
            return
        if drain and not task.done():
            try:
                await asyncio.wait_for(
                    self._callback_queue.join(), timeout=self.shutdown_timeout
                )
            except asyncio.TimeoutError:
                self._callback_errors.append(
                    GatewayError(
                        "gateway callback queue did not drain before shutdown timeout"
                    )
                )
        if not task.done():
            task.cancel()
            try:
                await task
            except BaseException:
                pass
        self._drain_callback_queue()

    def _drain_callback_queue(self) -> None:
        while True:
            try:
                item = self._callback_queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            else:
                if item.completion is not None and not item.completion.done():
                    item.completion.set_result(None)
                self._callback_queue.task_done()

    def _unlink_owned_socket(self) -> None:
        identity = self._socket_identity
        if identity is None:
            return
        try:
            current = self.frontend_path.lstat()
        except FileNotFoundError:
            return
        if (
            (current.st_dev, current.st_ino) == identity
            and stat.S_ISSOCK(current.st_mode)
        ):
            self.frontend_path.unlink()

    async def wait_closed(self) -> None:
        """Wait until :meth:`close` completes."""

        if not self._started and not self._closed:
            raise GatewayError("gateway has not been started")
        await self._closed_event.wait()

    async def close(self) -> None:
        """Stop accepting clients, close active bridges, and remove the socket."""

        async with self._close_lock:
            if self._closed:
                return
            self._closing = True
            self.ready.clear()
            try:
                if self._server is not None:
                    # ``code`` and ``reason`` parameters were added after
                    # websockets 15; keeping the broadly supported call makes
                    # the gateway work across the declared dependency range.
                    self._server.close(close_connections=True)

                active = [
                    connection
                    for connection in (self._active_frontend, self._active_backend)
                    if connection is not None
                ]
                if active:
                    await asyncio.gather(
                        *(
                            self._close_connection(connection)
                            for connection in active
                        ),
                        return_exceptions=True,
                    )

                if self._server is not None:
                    try:
                        await asyncio.wait_for(
                            self._server.wait_closed(), timeout=self.shutdown_timeout
                        )
                    except asyncio.TimeoutError:
                        for task in tuple(self._handler_tasks):
                            task.cancel()
                        await asyncio.gather(
                            *tuple(self._handler_tasks), return_exceptions=True
                        )
                        try:
                            await asyncio.wait_for(
                                self._server.wait_closed(),
                                timeout=max(self.close_timeout, 0.001),
                            )
                        except asyncio.TimeoutError:
                            # Active transports were already closed or aborted
                            # above.  Don't let a library-level waiter prevent
                            # monitor shutdown and socket cleanup indefinitely.
                            pass

                await self._stop_callback_worker(drain=True)
            finally:
                self._unlink_owned_socket()
                self._closed = True
                self._closed_event.set()

    async def __aenter__(self) -> UnixSocketGateway:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: Any,
    ) -> None:
        await self.close()
