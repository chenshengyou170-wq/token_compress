"""Codex token-usage reports via the open-source ccusage CLI.

ccusage (https://github.com/ccusage/ccusage, MIT) reads local Codex session
logs under ``$CODEX_HOME`` (default ``~/.codex``) and prints daily / monthly /
session token and cost tables. CodexScope does not reimplement the accounting;
this module resolves a ccusage executable and runs it as a subprocess.

Resolution order for the ccusage binary:

1. Explicit ``ccusage_bin`` argument or ``CODEXSCOPE_CCUSAGE_BIN``
2. ``ccusage`` on ``PATH``
3. ``npx --yes ccusage@latest`` when Node/npx are available
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


DEFAULT_CCUSAGE_PACKAGE = "ccusage@latest"
DEFAULT_REPORT = "daily"
REPORT_CHOICES = ("daily", "monthly", "session")


class UsageError(RuntimeError):
    """ccusage could not be resolved or executed."""


@dataclass(frozen=True, slots=True)
class CcusageCommand:
    """Resolved argv prefix that launches ccusage (without report args)."""

    argv: tuple[str, ...]
    source: str


def _env_override() -> str | None:
    value = os.environ.get("CODEXSCOPE_CCUSAGE_BIN", "").strip()
    return value or None


def resolve_ccusage_command(ccusage_bin: str | None = None) -> CcusageCommand:
    """Locate ccusage on PATH, via override, or through npx."""

    if ccusage_bin:
        path = Path(ccusage_bin).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return CcusageCommand((os.fspath(path.resolve()),), "explicit")
        found = shutil.which(ccusage_bin)
        if found:
            return CcusageCommand((found,), "explicit")
        raise UsageError(f"cannot find ccusage executable: {ccusage_bin}")

    env_bin = _env_override()
    if env_bin:
        return resolve_ccusage_command(env_bin)

    on_path = shutil.which("ccusage")
    if on_path:
        return CcusageCommand((on_path,), "path")

    npx = shutil.which("npx")
    if npx:
        return CcusageCommand(
            (npx, "--yes", DEFAULT_CCUSAGE_PACKAGE),
            "npx",
        )

    raise UsageError(
        "ccusage is not installed and npx is unavailable.\n"
        "Install Node.js and run `npm install -g ccusage`, or install\n"
        "ccusage so it is on PATH. See https://github.com/ccusage/ccusage"
    )


def build_ccusage_argv(
    report: str = DEFAULT_REPORT,
    *,
    extra_args: Sequence[str] = (),
    ccusage_bin: str | None = None,
    codex_home: str | Path | None = None,
) -> tuple[list[str], dict[str, str] | None]:
    """Build subprocess argv and optional env updates for a Codex report.

    Returns ``(argv, env_updates)``. ``env_updates`` is ``None`` when the
    parent environment should be used unchanged; otherwise merge it over
    ``os.environ`` before exec.
    """

    if report not in REPORT_CHOICES:
        raise UsageError(
            f"unknown report {report!r}; expected one of {', '.join(REPORT_CHOICES)}"
        )

    command = resolve_ccusage_command(ccusage_bin)
    argv = list(command.argv)
    argv.extend(["codex", report])
    argv.extend(str(arg) for arg in extra_args)

    env_updates: dict[str, str] | None = None
    if codex_home is not None:
        env_updates = {"CODEX_HOME": os.fspath(Path(codex_home).expanduser())}

    return argv, env_updates


def run_ccusage(
    report: str = DEFAULT_REPORT,
    *,
    extra_args: Sequence[str] = (),
    ccusage_bin: str | None = None,
    codex_home: str | Path | None = None,
    check: bool = False,
) -> int:
    """Run ccusage for Codex usage and return its exit code.

    stdout/stderr are inherited so interactive tables render normally.
    """

    argv, env_updates = build_ccusage_argv(
        report,
        extra_args=extra_args,
        ccusage_bin=ccusage_bin,
        codex_home=codex_home,
    )
    env = None
    if env_updates is not None:
        env = os.environ.copy()
        env.update(env_updates)

    try:
        completed = subprocess.run(argv, env=env, check=check)
    except FileNotFoundError as exc:
        raise UsageError(f"failed to execute ccusage: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        return int(exc.returncode)
    return int(completed.returncode)


def split_usage_argv(argv: Sequence[str]) -> tuple[str, list[str]]:
    """Split ``usage`` argv into report name and ccusage-forwarded args.

    Accepts::

        []                          -> daily, []
        ["daily"]                   -> daily, []
        ["monthly", "--json"]       -> monthly, ["--json"]
        ["--json"]                  -> daily, ["--json"]
        ["--", "--json"]            -> daily, ["--json"]
    """

    tokens = [str(item) for item in argv]
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    if tokens and tokens[0] in REPORT_CHOICES:
        return tokens[0], tokens[1:]
    return DEFAULT_REPORT, tokens


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry used by ``codexscope usage`` and direct module execution."""

    from argparse import ArgumentParser, REMAINDER

    parser = ArgumentParser(
        prog="codexscope usage",
        description=(
            "Show Codex token usage and cost via the open-source ccusage tool "
            "(reads local logs under $CODEX_HOME, default ~/.codex)."
        ),
    )
    parser.add_argument(
        "--ccusage-bin",
        default=None,
        help="ccusage executable, or leave unset to use PATH / npx ccusage@latest",
    )
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=None,
        help="Codex home directory (sets CODEX_HOME for ccusage; default: ~/.codex)",
    )
    parser.add_argument(
        "usage_args",
        nargs=REMAINDER,
        help=(
            "optional report (daily|monthly|session, default daily) plus args "
            "forwarded to ccusage (for example --json --since 2026-07-01)"
        ),
    )
    # parse_known_args keeps ccusage flags such as --json from being rejected
    # by this thin wrapper parser.
    args, unknown = parser.parse_known_args(
        list(argv) if argv is not None else None
    )
    combined = list(args.usage_args) + list(unknown)
    report, forwarded = split_usage_argv(combined)

    try:
        return run_ccusage(
            report,
            extra_args=forwarded,
            ccusage_bin=args.ccusage_bin,
            codex_home=args.codex_home,
        )
    except UsageError as exc:
        print(f"codexscope usage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
