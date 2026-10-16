from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    kind: str
    start_line: int
    end_line: int

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line

    def intersects(self, start_line: int, end_line: int) -> bool:
        return self.start_line <= end_line and start_line <= self.end_line


class SymbolIndex:
    def __init__(self, symbols: Iterable[Symbol], *, line_count: int | None = None) -> None:
        self.symbols = sorted(symbols, key=lambda symbol: (symbol.start_line, symbol.end_line, symbol.name))
        self.line_count = max(
            line_count or 0,
            max((symbol.end_line for symbol in self.symbols), default=0),
        )

    def symbols_for_lines(self, lines: Iterable[int]) -> list[Symbol]:
        """Map point locations to the smallest enclosing function."""

        found: dict[tuple[str, int, int], Symbol] = {}
        for line in sorted(set(lines)):
            candidates = [symbol for symbol in self.symbols if symbol.contains(line)]
            if candidates:
                selected = min(
                    candidates,
                    key=lambda symbol: (symbol.end_line - symbol.start_line, -symbol.start_line, symbol.name),
                )
                found[(selected.name, selected.start_line, selected.end_line)] = selected
        return sorted(found.values(), key=lambda symbol: (symbol.start_line, symbol.end_line, symbol.name))

    def symbols_for_range(self, start_line: int | None, end_line: int | None) -> list[Symbol]:
        """Return all functions intersecting a file-read interval.

        This is intentionally different from ``symbols_for_lines``: ``cat`` and
        open-ended ``tail`` operations should map every function they expose, not
        only the function containing the first line.
        """

        start = max(1, start_line or 1)
        end = max(start, end_line if end_line is not None else max(self.line_count, start))
        return [symbol for symbol in self.symbols if symbol.intersects(start, end)]

    @classmethod
    def from_bytes(cls, content: bytes, suffix: str) -> "SymbolIndex":
        suffix = suffix.lower()
        try:
            symbols = _tree_sitter_symbols(content, suffix)
        except (ImportError, RuntimeError, ValueError, TypeError):
            symbols = _fallback_symbols(content.decode("utf-8", errors="replace"), suffix)
        return cls(symbols, line_count=_line_count(content))

    @classmethod
    def from_file(cls, path: Path) -> "SymbolIndex":
        return cls.from_bytes(path.read_bytes(), path.suffix)


def _line_count(content: bytes) -> int:
    if not content:
        return 0
    return content.count(b"\n") + (0 if content.endswith(b"\n") else 1)


def _tree_sitter_symbols(content: bytes, suffix: str) -> list[Symbol]:
    from tree_sitter import Language, Parser

    if suffix == ".py":
        import tree_sitter_python as grammar
    elif suffix in {".c", ".h"}:
        import tree_sitter_c as grammar
    elif suffix in {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}:
        import tree_sitter_cpp as grammar
    else:
        return []

    parser = Parser(Language(grammar.language()))
    tree = parser.parse(content)
    symbols: list[Symbol] = []

    def text(node) -> str:
        return content[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    c_name_nodes = {
        "identifier",
        "field_identifier",
        "operator_name",
        "destructor_name",
        "qualified_identifier",
        "scoped_identifier",
    }

    def declarator_name(node):
        """Follow only declarator fields; never descend into parameters."""

        current = node
        visited: set[int] = set()
        while current is not None and current.id not in visited:
            visited.add(current.id)
            if current.type in c_name_nodes:
                return current
            nested = current.child_by_field_name("declarator")
            if nested is not None:
                current = nested
                continue
            named = current.child_by_field_name("name")
            if named is not None:
                current = named
                continue
            candidates = [
                child
                for child in current.named_children
                if child.type not in {"parameter_list", "type_qualifier", "trailing_return_type"}
            ]
            current = candidates[0] if len(candidates) == 1 else None
        return None

    def walk(node, class_stack: list[str], function_stack: list[str]) -> None:
        next_classes = class_stack
        next_functions = function_stack
        if suffix == ".py" and node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                next_classes = class_stack + [text(name_node)]

        if node.type == "function_definition":
            if suffix == ".py":
                name_node = node.child_by_field_name("name")
                simple_name = text(name_node) if name_node is not None else "<anonymous>"
                prefix = class_stack + function_stack
                name = ".".join(prefix + [simple_name]) if prefix else simple_name
                next_functions = function_stack + [simple_name]
            else:
                declarator = node.child_by_field_name("declarator")
                name_node = declarator_name(declarator) if declarator is not None else None
                # qualified_identifier text preserves C++ class/namespace scope,
                # while the declarator-only walk avoids the old "last parameter
                # name" failure (e.g. add(left, right) -> right).
                name = text(name_node).strip() if name_node is not None else "<anonymous>"
            symbols.append(
                Symbol(
                    name=name,
                    kind="function",
                    start_line=node.start_point.row + 1,
                    end_line=node.end_point.row + 1,
                )
            )

        for child in node.named_children:
            walk(child, next_classes, next_functions)

    walk(tree.root_node, [], [])
    return symbols


def _fallback_symbols(content: str, suffix: str) -> list[Symbol]:
    if suffix == ".py":
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        symbols: list[Symbol] = []

        def visit(body: list[ast.stmt], prefix: list[str]) -> None:
            for node in body:
                if isinstance(node, ast.ClassDef):
                    visit(node.body, prefix + [node.name])
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = ".".join(prefix + [node.name]) if prefix else node.name
                    symbols.append(
                        Symbol(
                            name,
                            "function",
                            int(node.lineno),
                            int(getattr(node, "end_lineno", node.lineno)),
                        )
                    )
                    visit(node.body, prefix + [node.name])

        visit(tree.body, [])
        return symbols

    return _fallback_c_symbols(content)


_C_FUNCTION = re.compile(
    r"(?:^|[;}]\s*)"
    r"(?:[A-Za-z_][\w:\s<>,*&~]*?\s+)?"
    r"(?P<name>(?:[A-Za-z_]\w*::)*(?:~?[A-Za-z_]\w*|operator\s*[^\s(]+))"
    r"\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept(?:\([^)]*\))?\s*)?(?:->[^{}]+)?\{",
    re.MULTILINE,
)


def _fallback_c_symbols(content: str) -> list[Symbol]:
    symbols: list[Symbol] = []
    line_starts = [0]
    for match in re.finditer("\n", content):
        line_starts.append(match.end())

    def line_number(offset: int) -> int:
        import bisect

        return bisect.bisect_right(line_starts, offset)

    for match in _C_FUNCTION.finditer(content):
        name = "".join(match.group("name").split())
        if name in {"if", "for", "while", "switch", "catch"}:
            continue
        brace = content.find("{", match.start(), match.end())
        if brace < 0:
            continue
        depth = 0
        end_offset = len(content)
        for offset in range(brace, len(content)):
            if content[offset] == "{":
                depth += 1
            elif content[offset] == "}":
                depth -= 1
                if depth == 0:
                    end_offset = offset
                    break
        symbols.append(Symbol(name, "function", line_number(match.start("name")), line_number(end_offset)))
    return symbols
