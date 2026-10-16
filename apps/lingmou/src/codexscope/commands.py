from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class ReadSpec:
    """A best-effort description of the part of a file read by a command."""

    path: str
    start_line: int | None = None
    end_line: int | None = None
    # ``tail -n N`` is relative to the version being inspected, so it cannot be
    # converted to an absolute range until enrichment has loaded that version.
    tail_lines: int | None = None
    source: str = "shell_parse"
    confidence: float = 0.75
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class CommandInfo:
    family: str
    is_test: bool
    test_key: str | None
    reads: tuple[ReadSpec, ...]
    actions_source: str = "shell_parse"


_TEST_PATTERNS = (
    r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?pytest(?:\s|$)",
    r"(?:^|\s)ctest(?:\s|$)",
    r"(?:^|\s)cargo\s+test(?:\s|$)",
    r"(?:^|\s)go\s+test(?:\s|$)",
    r"(?:^|\s)(?:npm|pnpm|yarn)\s+(?:run\s+)?test(?:\s|$)",
    r"(?:^|\s)(?:make|ninja)\s+(?:test|check)(?:\s|$)",
    r"(?:^|\s)meson\s+test(?:\s|$)",
    r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?unittest(?:\s|$)",
)

_PYTHON_EXECUTABLE = re.compile(r"python(?:3(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _segments(command: str) -> list[list[str]]:
    """Split common shell pipelines without executing or fully parsing shell."""

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|;&")
        lexer.whitespace_split = True
        lexer.commenters = ""
        raw = list(lexer)
    except ValueError:
        raw = command.split()
    result: list[list[str]] = []
    current: list[str] = []
    for token in raw:
        if token and all(character in "|;&" for character in token):
            if current:
                result.append(current)
                current = []
        else:
            current.append(token)
    if current:
        result.append(current)
    return result


def _command_index(tokens: Sequence[str]) -> int | None:
    """Find the executable after common wrappers and environment assignments."""

    wrappers = {"env", "command", "exec", "sudo", "timeout", "stdbuf", "xargs"}
    for index, token in enumerate(tokens):
        if "=" in token and not token.startswith(("/", "./", "../")):
            name = token.split("=", 1)[0]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                continue
        base = Path(token).name.lower()
        if base in wrappers or token.startswith("-"):
            continue
        return index
    return None


def _shell_payload(command: str) -> str | None:
    """Return the script passed to a common ``shell -c`` wrapper."""

    tokens = _tokens(command)
    index = _command_index(tokens)
    if index is None or Path(tokens[index]).name.lower() not in {
        "sh",
        "bash",
        "dash",
        "zsh",
    }:
        return None
    arguments = tokens[index + 1 :]
    for offset, token in enumerate(arguments[:-1]):
        if token.startswith("-") and "c" in token[1:]:
            return arguments[offset + 1]
    return None


def _unwrapped_command(command: str, *, max_depth: int = 3) -> str:
    current = command
    for _ in range(max_depth):
        payload = _shell_payload(current)
        if payload is None or payload == current:
            break
        current = payload
    return current


def unwrap_shell_command(command: str, *, max_depth: int = 3) -> str:
    """Return the innermost script passed through common ``shell -c`` wrappers.

    This is intentionally a parser-only operation: the command is never
    executed.  Runtime security classifiers use it so an absolute shell path
    such as ``/usr/bin/zsh -lc 'rm -rf scratch'`` cannot hide the inner
    operation from pre-execution policy checks.
    """

    return _unwrapped_command(command, max_depth=max_depth)


def _family(command: str) -> str:
    segments = _segments(command)
    if not segments:
        return "unknown"
    index = _command_index(segments[0])
    if index is None:
        return "unknown"
    return Path(segments[0][index]).name.lower()


def _is_test_segment(segment: Sequence[str]) -> bool:
    index = _command_index(segment)
    if index is None:
        return False
    executable = Path(segment[index]).name.lower()
    arguments = [value.lower() for value in segment[index + 1 :]]
    if executable in {"pytest", "py.test", "ctest"}:
        return True
    if _PYTHON_EXECUTABLE.fullmatch(executable):
        for offset, value in enumerate(arguments[:-1]):
            if value == "-m" and arguments[offset + 1] in {"pytest", "unittest"}:
                return True
    if executable in {"cargo", "go"} and arguments[:1] == ["test"]:
        return True
    if executable in {"npm", "pnpm", "yarn"}:
        return arguments[:1] == ["test"] or arguments[:2] == ["run", "test"]
    if executable in {"make", "ninja"}:
        return any(value in {"test", "check"} for value in arguments)
    return executable == "meson" and arguments[:1] == ["test"]


def _test_invocations(command: str) -> list[str]:
    result: list[str] = []
    for segment in _segments(_unwrapped_command(command)):
        index = _command_index(segment)
        if index is not None and _is_test_segment(segment):
            invocation = shlex.join(list(segment[index:]))
            if invocation not in result:
                result.append(invocation)
    return result


def _is_test_command(command: str) -> bool:
    """Recognize test runners even when invoked through an absolute/venv path."""

    if _test_invocations(command):
        return True

    # Keep the permissive fallback for shell wrappers that the lightweight
    # tokenizer cannot fully model.
    lower = command.strip().lower()
    return any(re.search(pattern, lower) for pattern in _TEST_PATTERNS)


def _normalize_test_key(command: str) -> str | None:
    tokens = _tokens(command)
    if not tokens:
        return None
    ignored = {
        "-q",
        "-v",
        "-vv",
        "-vvv",
        "--quiet",
        "--verbose",
        "--color=yes",
        "--color=no",
        "--color=auto",
        "--disable-warnings",
    }
    compact: list[str] = []
    for index, token in enumerate(tokens):
        if token in ignored or re.fullmatch(r"-j\d*", token):
            continue
        # Make equivalent slash spellings compare consistently without resolving
        # the path or consulting the live filesystem.
        normalized = token.replace("\\", "/")
        if index == 0:
            executable = Path(normalized).name.lower()
            if _PYTHON_EXECUTABLE.fullmatch(executable):
                normalized = "python"
            elif executable in {"pytest", "py.test"}:
                normalized = "pytest"
            else:
                normalized = executable
        compact.append(normalized)
    return " ".join(compact)


def _path_arguments(tokens: Sequence[str], start: int) -> list[str]:
    result: list[str] = []
    option_needs_value = {"-n", "--lines", "-c", "--bytes"}
    skip_next = False
    options_done = False
    for token in tokens[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in option_needs_value and not options_done:
            skip_next = True
            continue
        if token == "--":
            options_done = True
            continue
        if not options_done and token.startswith("-"):
            continue
        if token.startswith((">", "<")):
            continue
        result.append(token)
    return result


def _positive_int(value: str) -> int | None:
    try:
        number = int(value)
    except ValueError:
        return None
    return number if number >= 0 else None


def _specs_from_shell(command: str, output: str) -> list[ReadSpec]:
    reads: list[ReadSpec] = []
    segments = _segments(_unwrapped_command(command))

    # A producer piped into sed reads only the displayed interval for semantic
    # purposes. Handle this before the per-command pass so the whole-file form is
    # not also emitted.
    narrowed_producers: set[tuple[int, str]] = set()
    for index in range(len(segments) - 1):
        producer = segments[index]
        consumer = segments[index + 1]
        pi = _command_index(producer)
        ci = _command_index(consumer)
        if pi is None or ci is None:
            continue
        producer_name = Path(producer[pi]).name
        consumer_name = Path(consumer[ci]).name
        if producer_name not in {"cat", "nl"} or consumer_name != "sed":
            continue
        script = next((token for token in consumer[ci + 1 :] if re.fullmatch(r"\d+(?:,\d+)?p", token)), None)
        if not script:
            continue
        match = re.fullmatch(r"(\d+)(?:,(\d+))?p", script)
        assert match is not None
        paths = _path_arguments(producer, pi + 1)
        for path in paths:
            reads.append(
                ReadSpec(
                    path,
                    int(match.group(1)),
                    int(match.group(2) or match.group(1)),
                    source="shell_parse",
                    confidence=0.9,
                    evidence=f"{producer_name}|sed",
                )
            )
            narrowed_producers.add((index, path))

    for segment_index, tokens in enumerate(segments):
        command_index = _command_index(tokens)
        if command_index is None:
            continue
        name = Path(tokens[command_index]).name.lower()
        args = tokens[command_index + 1 :]

        if name == "cat":
            for path in _path_arguments(tokens, command_index + 1):
                if (segment_index, path) not in narrowed_producers:
                    reads.append(ReadSpec(path, source="shell_parse", confidence=0.82, evidence="cat"))
            continue

        if name == "head":
            count = 10
            for index, token in enumerate(args):
                if token in {"-n", "--lines"} and index + 1 < len(args):
                    count = _positive_int(args[index + 1]) or count
                elif token.startswith("--lines="):
                    count = _positive_int(token.split("=", 1)[1]) or count
                elif re.fullmatch(r"-\d+", token):
                    count = int(token[1:])
            for path in _path_arguments(tokens, command_index + 1):
                reads.append(ReadSpec(path, 1, count, source="shell_parse", confidence=0.85, evidence="head"))
            continue

        if name == "tail":
            count_token = "10"
            for index, token in enumerate(args):
                if token in {"-n", "--lines"} and index + 1 < len(args):
                    count_token = args[index + 1]
                elif token.startswith("--lines="):
                    count_token = token.split("=", 1)[1]
                elif re.fullmatch(r"-[+]?[0-9]+", token):
                    count_token = token[1:]
            for path in _path_arguments(tokens, command_index + 1):
                if count_token.startswith("+") and count_token[1:].isdigit():
                    reads.append(
                        ReadSpec(path, int(count_token[1:]), None, source="shell_parse", confidence=0.9, evidence="tail_from")
                    )
                elif count_token.isdigit():
                    reads.append(
                        ReadSpec(path, tail_lines=int(count_token), source="shell_parse", confidence=0.88, evidence="tail_last")
                    )
            continue

        if name == "sed":
            script = next((token for token in args if re.fullmatch(r"\d+(?:,\d+)?p", token)), None)
            if script:
                match = re.fullmatch(r"(\d+)(?:,(\d+))?p", script)
                assert match is not None
                script_index = args.index(script)
                for path in _path_arguments(args, script_index + 1):
                    reads.append(
                        ReadSpec(
                            path,
                            int(match.group(1)),
                            int(match.group(2) or match.group(1)),
                            source="shell_parse",
                            confidence=0.9,
                            evidence="sed_print",
                        )
                    )

    # rg/grep line-number output is stronger evidence than merely seeing a path
    # in the command. It also supports paths containing colons by matching the
    # final ``:<line>:`` delimiter that can be interpreted unambiguously.
    if any(
        Path(segment[index]).name.lower() in {"rg", "grep"}
        for segment in segments
        if (index := _command_index(segment)) is not None
    ):
        for line in output.splitlines():
            match = re.match(r"^(.*?):(\d+)(?::\d+)?:", line)
            if match:
                line_number = int(match.group(2))
                reads.append(
                    ReadSpec(
                        match.group(1),
                        line_number,
                        line_number,
                        source="search_output",
                        confidence=0.88,
                        evidence="line_number_output",
                    )
                )
    return reads


def _same_path(left: str, right: str) -> bool:
    left_norm = os.path.normpath(left).replace("\\", "/")
    right_norm = os.path.normpath(right).replace("\\", "/")
    return left_norm == right_norm or Path(left_norm).name == Path(right_norm).name


def _from_command_actions(
    command_actions: Iterable[Mapping[str, Any]],
    output: str,
) -> tuple[list[ReadSpec], bool]:
    reads: list[ReadSpec] = []
    recognized = False
    for action in command_actions:
        action_type = str(action.get("type") or "")
        if action_type not in {"read", "search", "listFiles", "unknown"}:
            continue
        if action_type != "unknown":
            recognized = True
        action_command = str(action.get("command") or "")
        action_path = str(action.get("path") or "")
        if action_type == "read" and action_path:
            parsed = _specs_from_shell(action_command, output)
            matching = [spec for spec in parsed if _same_path(spec.path, action_path)]
            if not matching:
                matching = [ReadSpec(action_path, evidence="command_action:read")]
            for spec in matching:
                reads.append(
                    ReadSpec(
                        action_path,
                        spec.start_line,
                        spec.end_line,
                        spec.tail_lines,
                        source="command_action",
                        confidence=0.98,
                        evidence=spec.evidence or "command_action:read",
                    )
                )
        elif action_type == "search":
            parsed = _specs_from_shell(action_command or "rg", output)
            for spec in parsed:
                if (
                    action_path
                    and os.path.isabs(action_path)
                    and os.path.isabs(spec.path)
                    and not _same_path(spec.path, action_path)
                ):
                    # A search action path may be a directory. Preserve results
                    # beneath that directory, but discard unrelated output.
                    parent = action_path.rstrip("/\\")
                    if parent and not spec.path.replace("\\", "/").startswith(parent.replace("\\", "/") + "/"):
                        continue
                reads.append(
                    ReadSpec(
                        spec.path,
                        spec.start_line,
                        spec.end_line,
                        spec.tail_lines,
                        source="command_action",
                        confidence=0.95,
                        evidence="command_action:search",
                    )
                )
    return reads, recognized


def _resolve_lexically(path: str, cwd: str | Path | None) -> str:
    candidate = Path(path)
    if candidate.is_absolute() or cwd is None:
        return os.path.normpath(os.fspath(candidate))
    return os.path.normpath(os.fspath(Path(cwd) / candidate))


def _deduplicate(reads: Iterable[ReadSpec], cwd: str | Path | None) -> tuple[ReadSpec, ...]:
    dedup: dict[tuple[str, int | None, int | None, int | None], ReadSpec] = {}
    for spec in reads:
        resolved = _resolve_lexically(spec.path, cwd)
        normalized = ReadSpec(
            resolved,
            spec.start_line,
            spec.end_line,
            spec.tail_lines,
            spec.source,
            spec.confidence,
            spec.evidence,
        )
        key = (resolved, spec.start_line, spec.end_line, spec.tail_lines)
        previous = dedup.get(key)
        if previous is None or normalized.confidence > previous.confidence:
            dedup[key] = normalized
    return tuple(dedup.values())


def classify_command(
    command: str,
    output: str = "",
    *,
    command_actions: Iterable[Mapping[str, Any]] | None = None,
    cwd: str | Path | None = None,
) -> CommandInfo:
    """Classify a shell command and recover file reads.

    App Server ``commandActions`` are preferred when present because they are
    produced by Codex's own command parser. Shell parsing is deliberately a
    fallback and every inferred read carries its evidence and confidence.
    Relative paths are interpreted against the command's actual ``cwd``.
    """

    stripped = command.strip()
    is_test = _is_test_command(stripped)
    test_invocations = _test_invocations(stripped)
    source = "shell_parse"
    reads: list[ReadSpec]
    if command_actions:
        reads, recognized = _from_command_actions(command_actions, output)
        if recognized:
            source = "command_actions"
        else:
            fallback_commands = [
                str(action.get("command"))
                for action in command_actions
                if isinstance(action, Mapping)
                and action.get("type") == "unknown"
                and action.get("command")
            ]
            reads = []
            for fallback in fallback_commands or [stripped]:
                reads.extend(_specs_from_shell(fallback, output))
    else:
        reads = _specs_from_shell(stripped, output)

    normalized_test_keys = [
        key
        for invocation in test_invocations
        if (key := _normalize_test_key(invocation)) is not None
    ]
    family_command = test_invocations[0] if test_invocations else stripped

    return CommandInfo(
        family=_family(family_command),
        is_test=is_test,
        test_key=" && ".join(normalized_test_keys)
        if normalized_test_keys
        else (_normalize_test_key(stripped) if is_test else None),
        reads=_deduplicate(reads, cwd),
        actions_source=source,
    )
