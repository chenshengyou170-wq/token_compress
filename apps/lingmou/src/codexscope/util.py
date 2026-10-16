from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".py"}


def json_dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_checked(argv: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def safe_relpath(path: str | Path, repo: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = repo / candidate
    resolved = candidate.resolve()
    repo_resolved = repo.resolve()
    try:
        return resolved.relative_to(repo_resolved).as_posix()
    except ValueError as exc:
        raise ValueError(f"Path escapes repository: {path}") from exc


def is_source_path(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SOURCE_SUFFIXES


def ensure_clean_git_repo(repo: Path) -> tuple[str, str]:
    if not (repo / ".git").exists():
        raise RuntimeError(f"Not a Git repository: {repo}")
    head = run_checked(["git", "rev-parse", "HEAD"], cwd=repo)
    status = run_checked(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo)
    if status:
        raise RuntimeError(
            "Repository is not clean. Use a disposable clean clone/worktree for reproducible traces.\n"
            + status
        )
    branch = run_checked(["git", "branch", "--show-current"], cwd=repo)
    return head, branch


def shell_join_for_display(argv: list[str]) -> str:
    return " ".join(argv)


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
