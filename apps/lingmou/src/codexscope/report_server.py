from __future__ import annotations

import shutil
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote, urlsplit


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


class ReportServerError(ValueError):
    """Raised when a run cannot be exposed safely."""


def _report_path(run_dir: Path) -> Path:
    try:
        root = run_dir.expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ReportServerError(f"run directory does not exist: {run_dir}") from exc
    if not root.is_dir():
        raise ReportServerError(f"run directory is not a directory: {run_dir}")

    candidate = root / "timeline.html"
    try:
        report = candidate.resolve(strict=True)
        report.relative_to(root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ReportServerError(
            f"timeline.html is missing or points outside the run directory: {run_dir}"
        ) from exc
    if not report.is_file():
        raise ReportServerError(f"timeline.html is not a regular file: {candidate}")
    return report


class _ReportRequestHandler(BaseHTTPRequestHandler):
    server_version = "CodexScopeReport/1"
    sys_version = ""

    def __init__(self, *args, report_path: Path, **kwargs) -> None:
        self._report_path = report_path
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve(send_body=False)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _serve(self, *, send_body: bool) -> None:
        try:
            path = unquote(urlsplit(self.path).path, errors="strict")
        except (UnicodeDecodeError, ValueError):
            self.send_error(400, "Invalid request path")
            return

        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/timeline.html")
            self._security_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path != "/timeline.html":
            # Deliberately do not inherit SimpleHTTPRequestHandler: a trace
            # directory contains raw and derived data that the report does not
            # need to expose, and directory listings must never be generated.
            self.send_error(404, "Not found")
            return

        try:
            source: BinaryIO = self._report_path.open("rb")
        except OSError:
            self.send_error(404, "Report is unavailable")
            return
        with source:
            try:
                size = self._report_path.stat().st_size
            except OSError:
                self.send_error(404, "Report is unavailable")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(size))
            self._security_headers()
            self.end_headers()
            if send_body:
                shutil.copyfileobj(source, self.wfile)


class _ThreadingReportServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_report_server(
    run_dir: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> ThreadingHTTPServer:
    """Create a server restricted to one run's self-contained HTML report."""

    if not 0 <= port <= 65_535:
        raise ReportServerError("port must be between 0 and 65535")
    report_path = _report_path(run_dir)
    handler = partial(_ReportRequestHandler, report_path=report_path)
    return _ThreadingReportServer((host, port), handler)


def _url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def serve_report(
    run_dir: Path,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> None:
    """Serve one report until interrupted, closing the listening socket cleanly."""

    server = create_report_server(run_dir, host=host, port=port)
    actual_port = int(server.server_address[1])
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host
    print(f"CodexScope report: http://{_url_host(display_host)}:{actual_port}/timeline.html")
    if host in {"0.0.0.0", "::", ""}:
        print(
            f"Listening on {host or 'all interfaces'}; replace 127.0.0.1 "
            "with this machine's LAN IP for intranet access."
        )
        print("Warning: this server has no authentication or TLS; use only on a trusted LAN.")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
