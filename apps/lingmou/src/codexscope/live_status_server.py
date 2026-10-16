from __future__ import annotations

import html
import importlib.resources
import json
import os
import stat
import threading
import webbrowser
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from . import __version__
from .codex_analysis import CodexAnalysisError, CodexExecAnalysisBackend
from .live_analysis import LiveAnalysisCoordinator
from .live_security import build_live_security_payload

DEFAULT_LIVE_HOST = "127.0.0.1"
DEFAULT_LIVE_PORT = 8765
_MAX_STATUS_BYTES = 8 * 1024 * 1024
Frontend = Literal["token", "lingmou"]


class LiveStatusServerError(ValueError):
    """The live dashboard cannot safely expose the requested status file."""


def _dashboard_bytes() -> bytes:
    resource = importlib.resources.files("codexscope").joinpath(
        "templates/live_status.html"
    )
    try:
        return resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise LiveStatusServerError("live status dashboard template is missing") from exc


def _showcase_bytes() -> bytes:
    resource = importlib.resources.files("codexscope").joinpath(
        "templates/investor_showcase.html"
    )
    try:
        return resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise LiveStatusServerError("product showcase template is missing") from exc


def _resolved_status_path(status_path: Path) -> Path:
    candidate = status_path.expanduser()
    try:
        parent = candidate.parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise LiveStatusServerError(
            f"live status directory does not exist: {candidate.parent}"
        ) from exc
    if not parent.is_dir():
        raise LiveStatusServerError(
            f"live status parent is not a directory: {candidate.parent}"
        )
    resolved = parent / candidate.name
    if resolved.exists() and not resolved.is_file():
        raise LiveStatusServerError(
            f"live status path is not a regular file: {resolved}"
        )
    return resolved


def _load_status_payload(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise LiveStatusServerError("live status is not available yet") from exc
    except OSError as exc:
        raise LiveStatusServerError("cannot open live status") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LiveStatusServerError("live status is not a regular file")
        if metadata.st_size > _MAX_STATUS_BYTES:
            raise LiveStatusServerError("live status exceeds the safety limit")
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = -1
            payload = json.load(source)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise LiveStatusServerError("live status contains invalid JSON") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if not isinstance(payload, dict):
        raise LiveStatusServerError("live status payload must be an object")
    return payload


def _load_live_security_payload(
    path: Path,
    *,
    analysis_coordinator: LiveAnalysisCoordinator | None = None,
) -> dict[str, Any]:
    payload = build_live_security_payload(
        _load_status_payload(path),
        run_dir=path.parent,
    )
    return (
        analysis_coordinator.enrich(payload)
        if analysis_coordinator is not None
        else payload
    )


class _LiveStatusRequestHandler(BaseHTTPRequestHandler):
    server_version = "CodexScopeLive/1"
    sys_version = ""

    def __init__(
        self,
        *args,
        status_path: Path,
        dashboard: bytes,
        showcase: bytes,
        frontend: Frontend,
        analysis_coordinator: LiveAnalysisCoordinator | None,
        **kwargs,
    ) -> None:
        self._status_path = status_path
        self._dashboard = dashboard
        self._showcase = showcase
        self._frontend = frontend
        self._analysis_coordinator = analysis_coordinator
        super().__init__(*args, **kwargs)

    def log_message(self, _format: str, *args: object) -> None:
        # Dashboard polling should not flood the monitor terminal.
        return None

    def do_GET(self) -> None:
        self._serve(send_body=True)

    def do_HEAD(self) -> None:
        self._serve(send_body=False)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )

    def _send_bytes(
        self,
        status_code: int,
        content_type: str,
        body: bytes,
        *,
        send_body: bool,
    ) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _send_json(
        self,
        status_code: int,
        payload: dict[str, Any],
        *,
        send_body: bool,
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send_bytes(
            status_code,
            "application/json; charset=utf-8",
            body,
            send_body=send_body,
        )

    def _serve(self, *, send_body: bool) -> None:
        try:
            path = unquote(urlsplit(self.path).path, errors="strict")
        except (UnicodeDecodeError, ValueError):
            self._send_json(400, {"error": "invalid request path"}, send_body=send_body)
            return

        if path == "/":
            self.send_response(302)
            self.send_header(
                "Location", "/live" if self._frontend == "token" else "/showcase"
            )
            self._security_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in {"/live", "/live.html"}:
            if self._frontend != "token":
                self._send_json(404, {"error": "not found"}, send_body=send_body)
                return
            self._send_bytes(
                200,
                "text/html; charset=utf-8",
                self._dashboard,
                send_body=send_body,
            )
            return
        if path in {"/showcase", "/showcase.html"}:
            if self._frontend != "lingmou":
                self._send_json(404, {"error": "not found"}, send_body=send_body)
                return
            try:
                initial = _load_live_security_payload(
                    self._status_path,
                    analysis_coordinator=self._analysis_coordinator,
                )
            except LiveStatusServerError:
                initial = {}
            embedded = (
                json.dumps(initial, ensure_ascii=False, separators=(",", ":"))
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .encode("utf-8")
            )
            self._send_bytes(
                200,
                "text/html; charset=utf-8",
                self._showcase
                .replace(
                    b"__CODEXSCOPE_LIVE_SECURITY_DATA__",
                    embedded,
                )
                .replace(
                    b"__CODEXSCOPE_VERSION__",
                    html.escape(__version__, quote=True).encode("utf-8"),
                ),
                send_body=send_body,
            )
            return
        if path == "/api/live-status":
            if self._frontend != "token":
                self._send_json(404, {"error": "not found"}, send_body=send_body)
                return
            try:
                payload = _load_status_payload(self._status_path)
            except LiveStatusServerError as exc:
                self._send_json(
                    503,
                    {"error": str(exc), "retryable": True},
                    send_body=send_body,
                )
                return
            self._send_json(200, payload, send_body=send_body)
            return
        if path == "/api/live-security":
            if self._frontend != "lingmou":
                self._send_json(404, {"error": "not found"}, send_body=send_body)
                return
            try:
                payload = _load_live_security_payload(
                    self._status_path,
                    analysis_coordinator=self._analysis_coordinator,
                )
            except LiveStatusServerError as exc:
                self._send_json(
                    503,
                    {"error": str(exc), "retryable": True},
                    send_body=send_body,
                )
                return
            self._send_json(200, payload, send_body=send_body)
            return

        # Never expose neighboring trace files or directory listings.
        self._send_json(404, {"error": "not found"}, send_body=send_body)


class _ThreadingLiveStatusServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler,
        *,
        status_path: Path,
        frontend: Frontend,
        analysis_coordinator: LiveAnalysisCoordinator | None,
    ) -> None:
        self.status_path = status_path
        self.frontend = frontend
        self.analysis_coordinator = analysis_coordinator
        self._analysis_stop = threading.Event()
        self._analysis_thread: threading.Thread | None = None
        self._closed = False
        super().__init__(server_address, handler)

    def start_analysis_watcher(self) -> None:
        """Analyze new status revisions even when no browser tab is open."""

        if self.frontend != "lingmou" or self.analysis_coordinator is None:
            return
        if self._analysis_thread is not None:
            return

        def watch() -> None:
            while not self._analysis_stop.is_set():
                try:
                    _load_live_security_payload(
                        self.status_path,
                        analysis_coordinator=self.analysis_coordinator,
                    )
                except LiveStatusServerError:
                    pass
                self._analysis_stop.wait(0.5)

        self._analysis_thread = threading.Thread(
            target=watch,
            name="codexscope-analysis-watch",
            daemon=True,
        )
        self._analysis_thread.start()

    def server_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._analysis_stop.set()
        if self._analysis_thread is not None:
            self._analysis_thread.join(timeout=2.0)
        if self.analysis_coordinator is not None:
            self.analysis_coordinator.close()
        super().server_close()


def create_live_status_server(
    status_path: Path,
    *,
    host: str = DEFAULT_LIVE_HOST,
    port: int = DEFAULT_LIVE_PORT,
    frontend: Frontend = "lingmou",
    analysis_backend: str = "codex",
    analysis_codex_bin: str = "codex",
    analysis_model: str | None = None,
    analysis_timeout_seconds: float = 90.0,
    analysis_min_interval_seconds: float = 1.5,
) -> ThreadingHTTPServer:
    """Create one isolated frontend and its corresponding sanitized API."""

    if not 0 <= port <= 65_535:
        raise LiveStatusServerError("port must be between 0 and 65535")
    if frontend not in {"token", "lingmou"}:
        raise LiveStatusServerError("frontend must be token or lingmou")
    if analysis_backend not in {"codex", "local"}:
        raise LiveStatusServerError("analysis backend must be codex or local")
    if analysis_timeout_seconds <= 0:
        raise LiveStatusServerError("analysis timeout must be positive")
    if analysis_min_interval_seconds < 0:
        raise LiveStatusServerError("analysis minimum interval cannot be negative")
    resolved = _resolved_status_path(status_path)
    dashboard = _dashboard_bytes() if frontend == "token" else b""
    showcase = _showcase_bytes() if frontend == "lingmou" else b""
    try:
        backend = (
            CodexExecAnalysisBackend(
                codex_bin=analysis_codex_bin,
                model=analysis_model,
                timeout_seconds=analysis_timeout_seconds,
            )
            if frontend == "lingmou" and analysis_backend == "codex"
            else None
        )
    except (CodexAnalysisError, OSError, ValueError) as exc:
        raise LiveStatusServerError(f"cannot start Codex analysis backend: {exc}") from exc
    coordinator = (
        LiveAnalysisCoordinator(
            backend=backend,
            min_backend_interval_seconds=analysis_min_interval_seconds,
        )
        if frontend == "lingmou"
        else None
    )
    handler = partial(
        _LiveStatusRequestHandler,
        status_path=resolved,
        dashboard=dashboard,
        showcase=showcase,
        frontend=frontend,
        analysis_coordinator=coordinator,
    )
    try:
        return _ThreadingLiveStatusServer(
            (host, port),
            handler,
            status_path=resolved,
            frontend=frontend,
            analysis_coordinator=coordinator,
        )
    except OSError as exc:
        if coordinator is not None:
            coordinator.close()
        raise LiveStatusServerError(f"cannot listen on {host}:{port}: {exc}") from exc


def _url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def serve_live_status(
    status_path: Path,
    *,
    host: str = DEFAULT_LIVE_HOST,
    port: int = DEFAULT_LIVE_PORT,
    open_browser: bool = False,
    frontend: Frontend = "lingmou",
    analysis_backend: str = "codex",
    analysis_codex_bin: str = "codex",
    analysis_model: str | None = None,
    analysis_timeout_seconds: float = 90.0,
    analysis_min_interval_seconds: float = 1.5,
) -> None:
    """Serve exactly one of the Token or Lingmou frontends until interrupted."""

    server = create_live_status_server(
        status_path,
        host=host,
        port=port,
        frontend=frontend,
        analysis_backend=analysis_backend,
        analysis_codex_bin=analysis_codex_bin,
        analysis_model=analysis_model,
        analysis_timeout_seconds=analysis_timeout_seconds,
        analysis_min_interval_seconds=analysis_min_interval_seconds,
    )
    if isinstance(server, _ThreadingLiveStatusServer) and frontend == "lingmou":
        server.start_analysis_watcher()
    actual_port = int(server.server_address[1])
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host
    page = "/live" if frontend == "token" else "/showcase"
    url = f"http://{_url_host(display_host)}:{actual_port}{page}"
    if frontend == "token":
        print(f"CodexScope live Token: {url}")
        print("Refresh: 250 ms | token usage and request diagnostics")
    else:
        print(f"CodexScope live behavior: {url}")
        print("Refresh: 500 ms | tools from Codex app-server | syscalls from linux_strace")
        backend_label = (
            f"Codex CLI ({analysis_model or 'CLI default model'})"
            if analysis_backend == "codex"
            else "local policy engine (instant analysis)"
        )
        print(f"Analysis backend: {backend_label}")
        print(
            "Analysis agents: 4 | behavior prediction | vulnerability | "
            "dangerous behavior | overall"
        )
    if host in {"0.0.0.0", "::", ""}:
        print(
            "Warning: no authentication or TLS; expose this only on a trusted network."
        )
    if open_browser:
        webbrowser.open(url)
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
