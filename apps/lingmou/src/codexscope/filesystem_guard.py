"""Linux directory boundaries, installed before the Agent process starts.

Commands and their descendants see read-only, inaccessible mounts in place of
denied directories. No command parsing or model cooperation is involved.
This protects paths, not copies/hard links outside those directory trees.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .atomic_policy import PolicyConfigError, config_path, load_document


def resolve_denied(workspace: Path, document: dict[str, Any]) -> list[str]:
    roots = []
    for value in document.get("filesystem", {}).get("deny", []):
        path = Path(value).expanduser()
        path = (path if path.is_absolute() else workspace / path).resolve()
        if path == Path("/") or workspace == path or workspace.is_relative_to(path):
            raise PolicyConfigError(f"不能禁止整个工作区或其祖先目录：{value}")
        if not path.is_dir():
            raise PolicyConfigError(f"禁止访问的目录不存在或不是目录：{value}")
        roots.append(path)
    # Mount only outermost roots; mounting below an inaccessible root would fail.
    return sorted(
        str(p)
        for p in set(roots)
        if not any(p != q and p.is_relative_to(q) for q in roots)
    )


def wrap_agent(
    command: list[str], *, workspace: Path, run_dir: Path, managed: bool = False
) -> tuple[list[str], dict[str, Any]]:
    document, revision = load_document(workspace)
    denied = resolve_denied(workspace, document)
    state = {
        "backend": "linux_bwrap",
        "denied_paths": denied,
        "configured": document.get("filesystem", {"deny": []}),
        "policy_revision": revision,
        "status": "disabled",
    }
    if not denied and not managed:
        return command, state
    bwrap = shutil.which("bwrap")
    if sys.platform != "linux" or not bwrap:
        raise PolicyConfigError(
            "目录禁访问需要 Linux 和 bubblewrap；未启动无保护的 Agent"
        )
    if managed:
        mask = Path(tempfile.mkdtemp(prefix="denied-", dir=run_dir / "agent-control"))
        mask.chmod(0o000)
    else:
        mask = run_dir / "filesystem-denied"
        mask.mkdir(mode=0o000)
    # Also mask the source location so commands cannot chmod the backing inode.
    args = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--bind",
        "/",
        "/",
        "--unshare-pid",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        str(mask),
        str(mask),
    ]
    for path in denied:
        if mask.is_relative_to(path):
            raise PolicyConfigError("禁止目录不能包含运行证据目录")
        args.extend(["--ro-bind", str(mask), path])
    if managed:
        control = str(run_dir / "agent-control")
        args.extend(["--ro-bind", control, control])
        policy_file = config_path(workspace)
        if policy_file.is_file():
            args.extend(["--ro-bind", str(policy_file), str(policy_file)])
    state["status"] = "active" if denied else "disabled"
    return [*args, "--", *command], state


def guard_status(run_dir: Path | None, document: dict[str, Any]) -> dict[str, Any]:
    active: dict[str, Any] = {}
    if run_dir is not None:
        try:
            active = json.loads((run_dir / "manifest.json").read_text()).get(
                "filesystem_guard", {}
            )
        except (OSError, ValueError):
            pass
        try:
            active = json.loads((run_dir / "agent-control/status.json").read_text())
        except (OSError, ValueError):
            pass
    configured = document.get("filesystem", {"deny": []})
    return {
        **active,
        "status": active.get("status", "disabled"),
        "restart_required": configured != active.get("configured", {"deny": []}),
        "configured": configured,
    }


def read_denials(
    run_dir: Path, workspace: Path, roots: list[str], offset: int
) -> tuple[list[dict[str, Any]], int]:
    """Consume bounded complete audit lines; only real kernel errors are hits."""
    found = []
    try:
        with (run_dir / "raw/os_audit.jsonl").open("rb") as stream:
            stream.seek(offset)
            for _ in range(2000):
                line = stream.readline(65536)
                if not line or not line.endswith(b"\n"):
                    break
                offset = stream.tell()
                try:
                    row = json.loads(line)
                    if (
                        row.get("synthetic")
                        or row.get("success") is not False
                        or row.get("errno") not in {"EACCES", "EPERM", "EROFS"}
                        or not row.get("path")
                    ):
                        continue
                    path = Path(row["path"])
                    path = (
                        workspace / path
                        if row.get("path_scope") == "workspace"
                        else path
                    ).resolve()
                    if any(path.is_relative_to(root) for root in roots):
                        found.append({**row, "resolved_path": str(path)})
                except (ValueError, OSError, RuntimeError):
                    continue
    except OSError:
        pass
    return found, offset
