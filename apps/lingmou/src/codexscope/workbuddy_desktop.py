"""Prepare a real WorkBuddy Desktop connection to one running Lingmou MCP."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import shlex
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from mcp import Client
from mcp.client.streamable_http import (
    create_mcp_http_client,
    streamable_http_client,
)

from .storage import atomic_json_dump, json_load


_SERVER_NAME = "lingmou-workbuddy"
_SSH_TARGET = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"
)


class DesktopConnectionError(RuntimeError):
    """A safe, user-facing Desktop connection preparation failure."""


@dataclass(frozen=True, slots=True)
class StrictMCPConnection:
    run_dir: Path
    run_id: str
    scenario_id: str
    endpoint: str
    authorization: str
    port: int


@dataclass(frozen=True, slots=True)
class GatewayProbe:
    protocol_version: str
    tool_count: int
    server_name: str | None


@dataclass(frozen=True, slots=True)
class DesktopBundle:
    config_path: Path
    desktop_endpoint: str
    tunnel_command: str | None
    copy_command: str | None
    probe: GatewayProbe


def _port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= parsed <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def _positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < parsed <= 120:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 120 seconds")
    return parsed


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validated_endpoint(value: Any) -> tuple[str, SplitResult, int]:
    if not isinstance(value, str) or not value:
        raise DesktopConnectionError("mcp.strict.json has no MCP URL")
    parsed = urlsplit(value)
    if parsed.scheme != "http":
        raise DesktopConnectionError("the run-scoped MCP URL must use loopback HTTP")
    if parsed.username is not None or parsed.password is not None:
        raise DesktopConnectionError("the MCP URL must not contain user information")
    if parsed.hostname is None or not _is_loopback(parsed.hostname):
        raise DesktopConnectionError("the MCP gateway is not loopback-scoped")
    if parsed.query or parsed.fragment:
        raise DesktopConnectionError("the MCP URL must not contain a query or fragment")
    if parsed.path.rstrip("/") != "/mcp":
        raise DesktopConnectionError("the MCP URL path must be /mcp")
    try:
        port = parsed.port
    except ValueError as exc:
        raise DesktopConnectionError("the MCP URL contains an invalid port") from exc
    if port is None:
        raise DesktopConnectionError("the MCP URL must contain an explicit port")
    return value, parsed, port


def load_strict_connection(run_dir: Path) -> StrictMCPConnection:
    resolved = run_dir.expanduser().resolve()
    if not resolved.is_dir():
        raise DesktopConnectionError(f"run directory does not exist: {resolved}")

    manifest_path = resolved / "manifest.json"
    config_path = resolved / "mcp.strict.json"
    try:
        manifest = json_load(manifest_path)
        config = json_load(config_path)
    except FileNotFoundError as exc:
        raise DesktopConnectionError(f"missing run file: {exc.filename}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DesktopConnectionError("the run manifest or MCP config is not valid JSON") from exc

    if not isinstance(manifest, dict) or manifest.get("schema_version") != "lingmou.workbuddy-run.v1":
        raise DesktopConnectionError("the selected directory is not a Lingmou WorkBuddy run")
    servers = config.get("mcpServers") if isinstance(config, dict) else None
    server = servers.get(_SERVER_NAME) if isinstance(servers, dict) else None
    if not isinstance(server, dict) or server.get("type") != "http":
        raise DesktopConnectionError(
            f"mcp.strict.json has no HTTP server named {_SERVER_NAME}"
        )

    endpoint, _parsed, port = _validated_endpoint(server.get("url"))
    headers = server.get("headers")
    authorization = headers.get("Authorization") if isinstance(headers, dict) else None
    if (
        not isinstance(authorization, str)
        or not authorization.startswith("Bearer ")
        or len(authorization.removeprefix("Bearer ")) < 16
    ):
        raise DesktopConnectionError("mcp.strict.json has no valid Bearer authorization header")

    ports = manifest.get("ports")
    manifest_port = ports.get("mcp") if isinstance(ports, dict) else None
    if manifest_port != port:
        raise DesktopConnectionError("manifest and mcp.strict.json disagree on the MCP port")
    network = manifest.get("network")
    mcp_bind = network.get("mcp_bind") if isinstance(network, dict) else None
    if not isinstance(mcp_bind, str) or not _is_loopback(mcp_bind):
        raise DesktopConnectionError("manifest does not confirm a loopback MCP bind")

    scenario = manifest.get("scenario")
    scenario_id = scenario.get("id") if isinstance(scenario, dict) else None
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not isinstance(scenario_id, str):
        raise DesktopConnectionError("manifest has no run or scenario identity")
    return StrictMCPConnection(
        run_dir=resolved,
        run_id=run_id,
        scenario_id=scenario_id,
        endpoint=endpoint,
        authorization=authorization,
        port=port,
    )


def _health_url(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return urlunsplit((parsed.scheme, parsed.netloc, "/healthz", "", ""))


async def _authenticated_mcp_probe(
    connection: StrictMCPConnection, timeout: float
) -> GatewayProbe:
    headers = {"Authorization": connection.authorization}

    @asynccontextmanager
    async def authenticated_transport() -> AsyncIterator[Any]:
        async with create_mcp_http_client(headers=headers) as http_client:
            async with streamable_http_client(
                connection.endpoint, http_client=http_client
            ) as streams:
                yield streams

    async with Client(
        authenticated_transport(),
        mode="legacy",
        read_timeout_seconds=timeout,
    ) as client:
        listed = await client.list_tools()
        server_info = client.server_info
        return GatewayProbe(
            protocol_version=str(client.protocol_version),
            tool_count=len(listed.tools),
            server_name=getattr(server_info, "name", None),
        )


def probe_gateway(connection: StrictMCPConnection, timeout: float = 10.0) -> GatewayProbe:
    """Verify health plus an authenticated initialize/list_tools exchange."""

    try:
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            response = client.get(_health_url(connection.endpoint))
            response.raise_for_status()
            health = response.json()
        if not isinstance(health, dict) or health.get("status") != "ok":
            raise DesktopConnectionError("the MCP health endpoint did not report ok")
        if health.get("transport") != "streamable-http":
            raise DesktopConnectionError("the gateway did not report Streamable HTTP")
        if health.get("scenario_id") != connection.scenario_id:
            raise DesktopConnectionError("MCP health and manifest disagree on the scenario")
        probe = asyncio.run(_authenticated_mcp_probe(connection, timeout))
        if probe.tool_count <= 0:
            raise DesktopConnectionError("authenticated MCP list_tools returned no tools")
        return probe
    except DesktopConnectionError:
        raise
    except Exception as exc:
        # Do not let an HTTP/MCP exception serialize the Authorization header.
        detail = str(exc).replace(connection.authorization, "<redacted>")
        token = connection.authorization.removeprefix("Bearer ")
        detail = detail.replace(token, "<redacted>")
        detail = " ".join(detail.split())[:240]
        suffix = f": {detail}" if detail else ""
        raise DesktopConnectionError(
            f"cannot complete the authenticated MCP probe ({type(exc).__name__}){suffix}"
        ) from exc


def _validated_ssh_target(value: str) -> str:
    if not _SSH_TARGET.fullmatch(value):
        raise DesktopConnectionError(
            "--ssh-target must be a plain user@host value without options or whitespace"
        )
    return value


def _private_empty_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.exists():
        if not resolved.is_dir():
            raise DesktopConnectionError(f"bundle output is not a directory: {resolved}")
        if any(resolved.iterdir()):
            raise DesktopConnectionError(
                f"bundle output is not empty; choose a new --out directory: {resolved}"
            )
    else:
        resolved.mkdir(parents=True, mode=0o700)
    try:
        resolved.chmod(0o700)
    except OSError as exc:
        raise DesktopConnectionError(f"cannot secure bundle directory: {resolved}") from exc
    return resolved


def prepare_desktop_bundle(
    connection: StrictMCPConnection,
    *,
    out_dir: Path,
    ssh_target: str | None,
    same_host: bool,
    desktop_port: int | None,
    timeout: float = 10.0,
) -> DesktopBundle:
    if same_host == (ssh_target is not None):
        raise DesktopConnectionError("select exactly one of --same-host or --ssh-target")
    target: str | None = None
    if same_host:
        if desktop_port is not None and desktop_port != connection.port:
            raise DesktopConnectionError("--desktop-port is only valid with --ssh-target")
    else:
        assert ssh_target is not None
        target = _validated_ssh_target(ssh_target)

    probe = probe_gateway(connection, timeout)
    output = _private_empty_directory(out_dir)

    tunnel_command: str | None = None
    copy_command: str | None = None
    if same_host:
        desktop_endpoint = connection.endpoint
    else:
        assert target is not None
        local_port = desktop_port or connection.port
        desktop_endpoint = f"http://127.0.0.1:{local_port}/mcp"
        tunnel_command = shlex.join(
            [
                "ssh",
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=30",
                "-L",
                f"127.0.0.1:{local_port}:127.0.0.1:{connection.port}",
                target,
            ]
        )

    config_path = output / "mcp.json"
    atomic_json_dump(
        config_path,
        {
            "mcpServers": {
                _SERVER_NAME: {
                    "type": "http",
                    "url": desktop_endpoint,
                    "headers": {"Authorization": connection.authorization},
                }
            }
        },
    )
    os.chmod(config_path, 0o600)

    if ssh_target is not None:
        assert target is not None
        copy_command = shlex.join(
            [
                "scp",
                f"{target}:{config_path}",
                "./lingmou-workbuddy.mcp.json",
            ]
        )

    atomic_json_dump(
        output / "connection.json",
        {
            "schema_version": "lingmou.workbuddy-desktop-connection.v1",
            "run_id": connection.run_id,
            "scenario_id": connection.scenario_id,
            "desktop_endpoint": desktop_endpoint,
            "config_file": "mcp.json",
            "gateway_probe": {
                "authenticated": True,
                "protocol_version": probe.protocol_version,
                "tool_count": probe.tool_count,
                "server_name": probe.server_name,
            },
            "ssh_tunnel_required": tunnel_command is not None,
            "ssh_tunnel_command": tunnel_command,
            "ephemeral": True,
            "contains_authorization": False,
        },
    )
    return DesktopBundle(
        config_path=config_path,
        desktop_endpoint=desktop_endpoint,
        tunnel_command=tunnel_command,
        copy_command=copy_command,
        probe=probe,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codexscope workbuddy-desktop",
        description=(
            "Verify a running Lingmou WorkBuddy MCP and prepare a protected config "
            "for the real WorkBuddy Desktop MCP client."
        ),
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--out",
        type=Path,
        help="new private bundle directory (default: RUN_DIR/workbuddy-desktop-connection)",
    )
    route = parser.add_mutually_exclusive_group(required=True)
    route.add_argument(
        "--ssh-target",
        metavar="USER@HOST",
        help="Linux host reached from the Windows/macOS Desktop over SSH",
    )
    route.add_argument(
        "--same-host",
        action="store_true",
        help="Desktop and the Lingmou MCP run on the same host",
    )
    parser.add_argument(
        "--desktop-port",
        type=_port,
        help="loopback port on the Desktop host (default: current MCP port)",
    )
    parser.add_argument("--timeout", type=_positive_timeout, default=10.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        connection = load_strict_connection(args.run_dir)
        out_dir = args.out or connection.run_dir / "workbuddy-desktop-connection"
        bundle = prepare_desktop_bundle(
            connection,
            out_dir=out_dir,
            ssh_target=args.ssh_target,
            same_host=args.same_host,
            desktop_port=args.desktop_port,
            timeout=args.timeout,
        )
    except (DesktopConnectionError, OSError) as exc:
        print(f"Cannot prepare WorkBuddy Desktop connection: {exc}", file=sys.stderr)
        return 2

    print(
        "Authenticated Lingmou MCP probe passed: "
        f"protocol={bundle.probe.protocol_version}, tools={bundle.probe.tool_count}"
    )
    print(f"Protected Desktop config: {bundle.config_path}")
    print("The generated config is mode 0600; its Bearer token was not printed.")
    if bundle.copy_command is not None:
        print("On the WorkBuddy Desktop computer, copy the protected config:")
        print(f"  {bundle.copy_command}")
    if bundle.tunnel_command is not None:
        print("On the same Desktop computer, keep this SSH tunnel running:")
        print(f"  {bundle.tunnel_command}")
    print("Then open WorkBuddy Desktop: Plugins -> MCP Servers -> Configure MCP.")
    print(
        "Merge the generated lingmou-workbuddy entry into the Desktop mcp.json; "
        "do not overwrite other existing MCP servers."
    )
    print("Success criterion: lingmou-workbuddy shows green/connected in Desktop.")
    print("This config expires when the selected Lingmou WorkBuddy run stops.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
