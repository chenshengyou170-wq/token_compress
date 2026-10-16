"""Keep the monitor endpoint stable while replacing a policy-bound Agent.

The authenticated workbench writes requests in a control directory mounted
read-only inside the Agent. A replacement always gets a fresh mount namespace.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from .atomic_policy import load_document
from .filesystem_guard import wrap_agent
from .storage import atomic_json_dump, json_load


def serve(workspace: Path, run_dir: Path, backend: Path, command: list[str]) -> int:
    control = run_dir / "agent-control"
    control.mkdir(mode=0o700, exist_ok=True)
    stopped = False
    child: subprocess.Popen | None = None
    last_request = ""

    def stop(_sig, _frame):
        nonlocal stopped
        stopped = True

    def terminate():
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        child = None

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        pending = {"id": "startup"}
        while not stopped:
            if pending:
                request_id = str(pending["id"])
                try:
                    _, revision = load_document(workspace)
                    if pending.get("revision", revision) != revision:
                        raise ValueError("策略版本已变化，请重新解析后启用")
                    wrapped, state = wrap_agent(
                        command, workspace=workspace, run_dir=run_dir, managed=True
                    )
                    state.update(
                        managed=True, request_id=request_id, supervisor_pid=os.getpid()
                    )
                    atomic_json_dump(
                        control / "status.json", {**state, "status": "applying"}
                    )
                    terminate()
                    backend.unlink(missing_ok=True)
                    env = os.environ.copy()
                    env.pop("TYPESAFE_API_KEY", None)
                    runtime_bin = Path.home() / ".local/share/codexscope/runtime/bin"
                    if (runtime_bin / "bwrap").is_file():
                        env["PATH"] = (
                            str(runtime_bin) + os.pathsep + env.get("PATH", "")
                        )
                    child = subprocess.Popen(
                        wrapped, cwd=workspace, env=env, stdin=subprocess.DEVNULL
                    )
                    deadline = time.monotonic() + 20
                    while not stopped and time.monotonic() < deadline:
                        if child.poll() is not None:
                            raise RuntimeError("受保护的 Agent 启动失败")
                        try:
                            with socket.socket(socket.AF_UNIX) as probe:
                                probe.settimeout(0.1)
                                probe.connect(str(backend))
                            break
                        except OSError:
                            time.sleep(0.1)
                    else:
                        raise RuntimeError("受保护的 Agent 启动超时")
                    atomic_json_dump(control / "status.json", state)
                except Exception as exc:
                    terminate()
                    atomic_json_dump(
                        control / "status.json",
                        {
                            "managed": True,
                            "request_id": request_id,
                            "status": "failed",
                            "error": str(exc),
                            "supervisor_pid": os.getpid(),
                        },
                    )
                    if request_id == "startup":
                        raise
                last_request = request_id
                pending = None
            if child is not None and child.poll() is not None:
                return child.returncode or 1
            try:
                request = json_load(control / "request.json")
                if isinstance(request, dict) and request.get("id") != last_request:
                    pending = request
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
    finally:
        terminate()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    raise SystemExit(serve(args.workspace, args.run_dir, args.socket, command))


if __name__ == "__main__":
    main()
