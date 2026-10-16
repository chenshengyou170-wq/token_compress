"""Static command facts for composable policies. Never executes commands or DNS.

This deliberately recognises a bounded command vocabulary. Unknown constructs
produce warnings, so callers can route incomplete analysis to human review.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Keep raw quoting until operators have been separated: echo '>' is not a write.
_TOKEN = re.compile(
    r"""(?:[^\s;&|<>()'"\\]|\\.|"(?:\\.|[^"\\])*"|'[^']*')+|[;&|<>()]+"""
)
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
_FILE_COMMANDS = {
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "cp",
    "mv",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "tee",
    "chmod",
    "chown",
    "chgrp",
    "ls",
}
_NETWORK_COMMANDS = {"curl", "wget", "ssh", "scp", "nc", "ncat", "netcat"}
_DEFAULT_PORT = {"http": 80, "https": 443, "ftp": 21, "ftps": 990, "ssh": 22}


def command_facts(
    command: str, *, workspace: Path | str, cwd: Path | str | None = None
) -> dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    initial_cwd = Path(cwd).expanduser() if cwd else root
    if not initial_cwd.is_absolute():
        initial_cwd = root / initial_cwd
    warnings: list[str] = []
    network: dict[str, Any] = {
        k: [] for k in ("hosts", "ports", "schemes", "methods", "address_classes")
    }
    network.update(
        present=False, upload=False, download=False, tls_verify_disabled=False
    )
    file: dict[str, Any] = {
        k + "_paths": [] for k in ("read", "write", "delete", "permission")
    }
    file.update(
        recursive=False,
        force=False,
        read=False,
        write=False,
        delete=False,
        permission_change=False,
    )
    process: dict[str, Any] = {"executables": [], "elevated": False, "shell": False}

    def warn(reason: str) -> None:
        if reason not in warnings:
            warnings.append(reason)

    def add(target: dict[str, Any], key: str, value: Any) -> None:
        if value not in target[key]:
            target[key].append(value)

    def path(value: str, operation: str, base: Path) -> None:
        if not value or value == "-":
            return
        file["permission_change" if operation == "permission" else operation] = True
        if (
            any(c in value for c in "$*?[]{}\x00\n")
            or value.startswith("~")
            and not value.startswith("~/")
        ):
            warn("文件路径含动态展开，无法确定实际目标")
            return
        try:
            target = Path(value).expanduser()
            add(
                file,
                operation + "_paths",
                str((target if target.is_absolute() else base / target).resolve()),
            )
        except (OSError, ValueError, RuntimeError):
            warn("文件路径无法规范化")

    def destination(host: str, scheme: str, port: int | None = None) -> None:
        if not host or any(c in host for c in "$*?{}"):
            warn("网络目的地无法静态确定")
            return
        try:
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
            address = ipaddress.ip_address(host)
        except ValueError:
            kind = (
                "loopback"
                if host == "localhost" or host.endswith(".localhost")
                else "hostname"
            )
        except UnicodeError:
            warn("网络目的地格式无效")
            return
        else:
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            kind = (
                "loopback"
                if address.is_loopback
                else "link_local"
                if address.is_link_local
                else "private"
                if address.is_private
                else "public"
                if address.is_global
                else "reserved"
            )
        network["present"] = True
        add(network, "hosts", host)
        add(network, "address_classes", kind)
        add(network, "schemes", scheme)
        if port is not None and 1 <= port <= 65535:
            add(network, "ports", port)
        elif port is not None:
            warn("网络端口无效")

    def url(value: str) -> bool:
        if "://" not in value:
            return False
        try:
            parts = urlsplit(value)
            if not parts.hostname:
                raise ValueError()
            destination(
                parts.hostname,
                parts.scheme.lower(),
                parts.port or _DEFAULT_PORT.get(parts.scheme.lower()),
            )
            return True
        except ValueError:
            warn("URL 无法解析")
            return False

    def network_command(executable: str, args: list[str], base: Path) -> None:
        network["present"] = True
        if executable in {"curl", "wget"}:
            method, explicit_method = "GET", None
            wget_saves_file = executable == "wget"
            upload = False
            positionals: list[str] = []
            i = 0
            data_opts = {
                "-d",
                "--data",
                "--data-raw",
                "--data-binary",
                "--data-urlencode",
                "-F",
                "--form",
                "--form-string",
                "--post-data",
                "--post-file",
                "--body-data",
                "--body-file",
            }
            value_opts = data_opts | {
                "-X",
                "--request",
                "--method",
                "-T",
                "--upload-file",
                "-o",
                "--output",
                "-O" if executable == "wget" else "--output-document",
                "--output-document",
                "--url",
                "-H",
                "--header",
                "-u",
                "--user",
                "-A",
                "--user-agent",
                "--connect-timeout",
                "--max-time",
                "--timeout",
                "--retry",
                "-x",
                "--proxy",
                "--resolve",
                "--connect-to",
                "--cacert",
                "--cert",
                "--key",
                "-b",
                "--cookie",
                "-c",
                "--cookie-jar",
            }
            flags = {
                "-s",
                "-S",
                "-sS",
                "-fsSL",
                "-fsS",
                "-fs",
                "-f",
                "-L",
                "--location",
                "--silent",
                "--show-error",
                "--fail",
                "--compressed",
                "-v",
                "--verbose",
                "-q",
                "--quiet",
                "--no-check-certificate",
                "--insecure",
                "-k",
                "-I",
                "--head",
                "-G",
                "--get",
                "--globoff",
                "-g",
            }
            if executable == "curl":
                # These values describe curl's transport/output settings, not
                # additional URLs. Treating '=https' or '0' as hosts falsely
                # rejects requests to an otherwise approved source.
                value_opts.update(
                    {"--proto", "--proto-redir", "--noproxy", "--max-redirs", "--write-out", "-w"}
                )
                flags.add("--disable")
            while i < len(args):
                arg = args[i]
                key, sep, value = (
                    arg.partition("=") if arg.startswith("--") else (arg, "", "")
                )
                if (
                    not sep
                    and len(arg) > 2
                    and (
                        arg[:2] in {"-d", "-F", "-T", "-X", "-o", "-H", "-u", "-x"}
                        or executable == "curl" and arg[:2] == "-w"
                    )
                ):
                    key, sep, value = arg[:2], "=", arg[2:]
                if key in value_opts:
                    if not sep:
                        i += 1
                        if i >= len(args):
                            warn("网络选项缺少参数")
                            break
                        value = args[i]
                    if key in data_opts:
                        method, upload = "POST", True
                        if key in {"--post-file", "--body-file"}:
                            path(value, "read", base)
                        elif key not in {"--data-raw", "--form-string"}:
                            # Form fields support field=@file and field=<file.
                            candidate = (
                                value.split("=", 1)[-1]
                                if key in {"-F", "--form", "--data-urlencode"}
                                else value
                            )
                            if candidate.startswith(("@", "<")):
                                path(candidate[1:].split(";", 1)[0], "read", base)
                    elif key in {"-T", "--upload-file"}:
                        method, upload = "PUT", True
                        path(value, "read", base)
                    elif key in {"-X", "--request", "--method"}:
                        explicit_method = value.upper()
                    elif key in {"-o", "--output", "--output-document", "-O"}:
                        path(value, "write", base)
                        if executable == "wget" and key in {"--output-document", "-O"}:
                            wget_saves_file = value != "-"
                    elif key == "--url":
                        positionals.append(value)
                    elif key in {"-x", "--proxy", "--resolve", "--connect-to"}:
                        warn("代理或目标重映射可能改变实际网络出口")
                        if key in {"-x", "--proxy"}:
                            url(value if "://" in value else "http://" + value)
                    elif key in {"--cacert", "--cert", "--key", "-b", "--cookie"}:
                        warn("认证或 cookie 选项可能引用额外文件")
                    elif key in {"-c", "--cookie-jar"}:
                        path(value, "write", base)
                    elif executable == "curl" and key in {"-w", "--write-out"}:
                        if value.startswith("@"):
                            path(value[1:], "read", base)
                            warn("write-out 格式来自文件或标准输入，额外输出路径尚未确定")
                        elif "%output{" in value:
                            # curl can write to files through its format string.
                            # Keep those effects visible even though it is not a URL.
                            for target in re.findall(r"%output\{([^}]+)\}", value):
                                path(target.removeprefix(">>"), "write", base)
                            warn("write-out 含文件输出指令，格式语义不能完整静态解析")
                elif arg in {"-I", "--head"}:
                    method = "HEAD"
                elif arg in {"-G", "--get"}:
                    explicit_method = "GET"
                elif arg in {"-k", "--insecure", "--no-check-certificate"}:
                    network["tls_verify_disabled"] = True
                elif arg == "-O" and executable == "curl" or arg == "--remote-name":
                    file["write"] = True
                    warn("按远程文件名保存，写入路径尚未确定")
                elif arg in flags:
                    if arg in {"-L", "--location", "-fsSL"}:
                        warn("重定向后的网络目标尚未确定")
                elif executable == "curl" and re.fullmatch(r"-[sSfLkvIgG]+", arg):
                    network["tls_verify_disabled"] |= "k" in arg
                    if "I" in arg:
                        method = "HEAD"
                    if "G" in arg:
                        explicit_method = "GET"
                    if "L" in arg:
                        warn("重定向后的网络目标尚未确定")
                elif arg.startswith("-"):
                    warn("包含未支持的网络命令选项")
                else:
                    positionals.append(arg)
                i += 1
            for value in positionals:
                if not url(value):
                    # Bare curl/wget hosts are accepted with their default HTTP scheme.
                    url("http://" + value)
            if executable == "wget":
                file["write"] |= wget_saves_file
                warn("wget 默认落盘或跟随跳转，最终路径和目标可能变化")
            if not positionals:
                warn("未识别网络目的地")
            network["upload"] |= upload or explicit_method in {"POST", "PUT", "PATCH"}
            network["download"] |= not upload
            add(network, "methods", explicit_method or method)
            return
        # Conservative support for explicit ssh/scp/nc destinations.
        port = 22 if executable in {"ssh", "scp"} else None
        operands = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in (
                {"-p"}
                if executable == "ssh"
                else {"-P"}
                if executable == "scp"
                else {"-p", "-w"}
            ):
                i += 1
                if i < len(args) and args[i].isdigit():
                    if arg != "-w":
                        port = int(args[i])
                else:
                    warn("网络选项参数无法解析")
            elif arg.startswith("-"):
                warn("SSH / socket 选项可能改变目标或行为")
            else:
                operands.append(arg)
            i += 1
        if executable == "scp":
            for index, value in enumerate(operands):
                remote = re.fullmatch(r"(?:[^@/:]+@)?(\[[^]]+\]|[^/:]+):(.+)", value)
                if remote:
                    destination(remote[1].strip("[]"), "ssh", port)
                    network["upload"] |= index == len(operands) - 1
                    network["download"] |= index < len(operands) - 1
                else:
                    path(value, "write" if index == len(operands) - 1 else "read", base)
        elif operands:
            if (
                executable in {"nc", "ncat", "netcat"}
                and len(operands) > 1
                and operands[1].isdigit()
            ):
                port = int(operands[1])
            destination(
                operands[0].split("@")[-1].strip("[]"),
                "ssh" if executable == "ssh" else "tcp",
                port,
            )
        warn("远程命令、SSH 配置及 socket 数据流未展开分析")

    def parse(text: str, base: Path, depth: int = 0) -> None:
        if depth > 3:
            warn("Shell 嵌套过深")
            return
        if any(c in text for c in ("$", "`", "\n")):
            warn("命令含变量、替换或多行语法")
        if len(text) > 32000:
            warn("命令超过静态解析长度上限")
            text = text[:32000]
        raw = _TOKEN.findall(text)
        if len(raw) > 2048:
            warn("命令超过静态解析词数上限")
            raw = raw[:2048]
        # Detect unmatched quotes or other unconsumed syntax without echoing secrets.
        if re.sub(r"\s+", "", _TOKEN.sub("", text)):
            warn("命令含无法解析的语法")
        segments: list[list[str]] = [[]]
        for token in raw:
            if token in {";", "&&", "||", "|", "&", "(", ")"}:
                if token in {"||", "|", "&", "(", ")"}:
                    warn("包含管道、条件分支或子进程，后续行为需复核")
                segments.append([])
            else:
                segments[-1].append(token)
        for segment in segments[:128]:
            args: list[str] = []
            i = 0
            while i < len(segment):
                raw_arg = segment[i]
                if raw_arg in {">", ">>", "<", "<>"}:
                    i += 1
                    if i >= len(segment):
                        warn("文件重定向缺少目标")
                        break
                    try:
                        value = shlex.split(segment[i])[0]
                        if args and args[-1].isdigit():
                            args.pop()
                        path(value, "read" if raw_arg == "<" else "write", base)
                        if raw_arg == "<>":
                            path(value, "read", base)
                    except (ValueError, IndexError):
                        warn("重定向目标无法解析")
                elif re.fullmatch(r"[<>&|;()]+", raw_arg):
                    warn("未支持的 Shell 操作符")
                else:
                    try:
                        args.append(shlex.split(raw_arg)[0])
                    except (ValueError, IndexError):
                        warn("命令参数无法解析")
                i += 1
            if not args:
                continue
            while args and re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", args[0]):
                args.pop(0)
                warn("环境变量可能改变命令行为")
            if not args:
                continue
            executable = Path(args.pop(0)).name
            add(process, "executables", executable)
            if executable in {"sudo", "doas", "su", "env"}:
                process["elevated"] |= executable != "env"
                warn("执行包装器可能改变身份或环境")
                if args and not args[0].startswith("-"):
                    executable = Path(args.pop(0)).name
                    add(process, "executables", executable)
            if executable in _SHELLS:
                process["shell"] = True
                if len(args) >= 2 and args[0] in {"-c", "-lc"}:
                    parse(args[1], base, depth + 1)
                    if len(args) > 2:
                        warn("Shell 位置参数未展开")
                else:
                    warn("Shell 脚本内容未展开")
                continue
            if executable == "cd":
                if len(args) == 1 and not any(c in args[0] for c in "$*?[]{}"):
                    target = Path(args[0]).expanduser()
                    base = (target if target.is_absolute() else base / target).resolve()
                    warn("切换目录的成功状态需运行时确认")
                else:
                    warn("工作目录无法静态确定")
                continue
            if executable in _NETWORK_COMMANDS:
                network_command(executable, args, base)
            elif executable in _FILE_COMMANDS:
                operands = []
                options = True
                i = 0
                while i < len(args):
                    arg = args[i]
                    if arg == "--" and options:
                        options = False
                    elif options and arg.startswith("-") and arg != "-":
                        file["recursive"] |= (
                            arg == "--recursive"
                            or not arg.startswith("--")
                            and any(c in arg[1:] for c in "rR")
                        )
                        file["force"] |= (
                            arg == "--force"
                            or not arg.startswith("--")
                            and "f" in arg[1:]
                        )
                        if arg in {"-n", "-c"} and executable in {"head", "tail"}:
                            i += 1
                        elif not (
                            arg in {"--recursive", "--force", "--parents"}
                            or re.fullmatch(r"-[rRfpanvl]+", arg)
                        ):
                            warn("包含未支持的文件命令选项")
                    else:
                        operands.append(arg)
                    i += 1
                if executable in {"cp", "mv"}:
                    for value in operands[:-1]:
                        path(value, "read", base)
                        if executable == "mv":
                            path(value, "delete", base)
                    if operands:
                        path(operands[-1], "write", base)
                    # A directory destination may also create children, conservatively
                    # expose the destination directory and each derived target.
                    if len(operands) >= 2:
                        dest = Path(operands[-1])
                        dest = dest if dest.is_absolute() else base / dest
                        if dest.is_dir():
                            for source in operands[:-1]:
                                path(str(dest / Path(source).name), "write", base)
                else:
                    operation = (
                        "delete"
                        if executable in {"rm", "rmdir"}
                        else "write"
                        if executable in {"mkdir", "touch", "tee"}
                        else "permission"
                        if executable in {"chmod", "chown", "chgrp"}
                        else "read"
                    )
                    for value in (
                        operands[1:] if operation == "permission" else operands
                    ):
                        path(value, operation, base)
                    if executable == "ls" and not operands:
                        path(str(base), "read", base)
            elif executable not in {"echo", "printf", "true", "false", "pwd"}:
                warn("包含未支持的命令或脚本，内部文件与网络操作不可见")
        if len(segments) > 128:
            warn("命令段数超过解析上限")

    parse(command, initial_cwd.resolve())
    return {
        "command": {"workspace": str(root), "parse_complete": not warnings},
        "network": network,
        "file": file,
        "process": process,
        "parse_warnings": warnings,
    }
