"""Declarative policy predicates and atomic, versioned workspace configuration.

Detectors produce facts; this module decides effects. No eval, plugins, arbitrary
Python, or user-supplied regular expressions are executed by the rule engine.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.resources
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from threading import RLock
from typing import Any

from .policy_primitives import (
    FACT_FIELDS, SPECIAL_OPS, builtin_atoms, special_match, validate_special_values,
)

SCHEMA = "lingmou.atomic-policies.v1"
MAX_BYTES = 256 * 1024
MODES = {"observe", "review", "deny"}
LEVELS = {"normal", "notice", "warning", "high", "critical"}
EVENTS = {"command.approval", "work.action"}
FIELDS = {
    "command.text",
    "command.cwd",
    "command.hosts",
    "detector.ids",
    "detector.blocking_ids",
    "principal.role",
    "principal.agent_id",
    "action.family",
} | FACT_FIELDS
OPS = {
    "eq",
    "ne",
    "contains",
    "in",
    "not_in",
    "intersects",
    "subset",
    "starts_with",
    "ends_with",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
} | SPECIAL_OPS
_LOCK = RLock()
_MISSING = object()


class PolicyConfigError(ValueError):
    pass


class PolicyConflict(PolicyConfigError):
    pass


def default_document() -> dict[str, Any]:
    return json.loads(
        importlib.resources.files("codexscope")
        .joinpath("policies/atomic_defaults.json")
        .read_text(encoding="utf-8")
    )


def empty_document() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "atoms": {},
        "lists": {},
        "rules": [],
        "overrides": {},
    }


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyConfigError(message)


def _identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", value) is not None
    )


def _scalar(value: Any) -> bool:
    return (
        value is None
        or type(value) in {str, bool, int, float}
        and (not isinstance(value, str) or len(value) <= 4096)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def validate_document(raw: Any) -> dict[str, Any]:
    _check(isinstance(raw, dict), "策略配置必须为对象")
    _check(
        not raw.keys() - {"schema_version", "atoms", "lists", "rules", "overrides", "filesystem", "semantic_atoms"},
        "策略配置包含未知字段",
    )
    _check(raw.get("schema_version") == SCHEMA, f"schema_version 必须为 {SCHEMA}")
    atoms, lists, rules, overrides = (
        raw.get(k, d)
        for k, d in (("atoms", {}), ("lists", {}), ("rules", []), ("overrides", {}))
    )
    _check(
        isinstance(atoms, dict) and len(atoms) <= 128, "atoms 必须为对象，最多 128 项"
    )
    _check(
        isinstance(lists, dict) and len(lists) <= 128, "lists 必须为对象，最多 128 项"
    )
    _check(
        isinstance(rules, list) and len(rules) <= 256, "rules 必须为列表，最多 256 项"
    )
    _check(isinstance(overrides, dict), "overrides 必须为对象")
    semantic_atoms = raw.get("semantic_atoms", {})
    _check(isinstance(semantic_atoms, dict) and len(semantic_atoms) <= 16,
           "semantic_atoms 必须为对象，最多 16 项")
    for name, definition in semantic_atoms.items():
        _check(_identifier(name) and isinstance(definition, dict)
               and set(definition) <= {"question", "fields", "min_probability"}, "语义条件定义无效")
        _check(isinstance(definition.get("question"), str)
               and 1 <= len(definition["question"].strip()) <= 2000, "语义条件需要明确的 question")
        fields = definition.get("fields")
        _check(isinstance(fields, list) and 1 <= len(fields) <= 16
               and all(isinstance(f, str) and (f in FIELDS or re.fullmatch(
                   r"action\.(request|impact)\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){0,3}", f)) for f in fields),
               "语义条件 fields 需要 1 至 16 个已支持的事实字段")
        minimum = definition.get("min_probability", 0.9)
        _check(type(minimum) in {int, float} and math.isfinite(minimum) and 0.8 <= minimum <= 1,
               "min_probability 必须在 0.8 至 1 之间")
    library = builtin_atoms()
    _check(not any(isinstance(name, str) and name.startswith("meta.") for name in atoms), "meta. 为内置元策略保留名称")
    available_atoms = {**library, **atoms}
    filesystem = raw.get("filesystem", {"deny": []})
    _check(isinstance(filesystem, dict) and set(filesystem) <= {"deny"}, "filesystem 仅支持 deny 目录列表")
    denied = filesystem.get("deny", [])
    _check(isinstance(denied, list) and len(denied) <= 64, "禁止访问目录最多 64 项")
    for path in denied:
        _check(isinstance(path, str) and 0 < len(path.strip()) <= 4096
               and not any(c in path for c in "\x00\n\r")
               and path.strip() not in {"/", ".", "..", "~"}, "禁止访问目录必须是具体目录路径")
    _check(len(set(denied)) == len(denied), "禁止访问目录不能重复")
    for name, values in lists.items():
        _check(
            _identifier(name)
            and isinstance(values, list)
            and len(values) <= 512
            and all(_scalar(v) for v in values),
            f"lists.{name} 不是有效值列表",
        )

    nodes_checked = 0

    def predicate(node: Any, trail: tuple[str, ...] = (), depth: int = 0) -> None:
        nonlocal nodes_checked
        nodes_checked += 1
        _check(nodes_checked <= 4096, "展开后的条件总数超过 4096")
        _check(depth <= 16 and isinstance(node, dict), "条件嵌套过深或不是对象")
        if set(node) == {"semantic"}:
            _check(isinstance(node["semantic"], str) and node["semantic"] in semantic_atoms,
                   "未知语义条件")
        elif set(node) == {"atom"}:
            name = node["atom"]
            _check(isinstance(name, str) and name in available_atoms, f"未知条件原子 {name}")
            _check(name not in trail, f"条件原子循环引用 {name}")
            predicate(available_atoms[name], (*trail, name), depth + 1)
        elif set(node) in ({"all"}, {"any"}):
            nodes = next(iter(node.values()))
            _check(
                isinstance(nodes, list) and 1 <= len(nodes) <= 32,
                "all/any 需要 1 至 32 个条件",
            )
            for child in nodes:
                predicate(child, trail, depth + 1)
        elif set(node) == {"not"}:
            predicate(node["not"], trail, depth + 1)
        else:
            _check(
                set(node) == {"field", "op", "value"},
                "条件需要 field、op、value，或 all/any/not/atom",
            )
            field, op, value = node["field"], node["op"], node["value"]
            _check(
                isinstance(field, str)
                and (
                    field in FIELDS
                    or re.fullmatch(
                        r"action\.(request|impact)\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){0,3}",
                        field,
                    )
                    is not None
                ),
                f"未知事实字段 {field}",
            )
            _check(isinstance(op, str) and op in OPS, f"未知运算符 {op}")
            if isinstance(value, dict):
                _check(
                    set(value) == {"list"}
                    and isinstance(value["list"], str)
                    and value["list"] in lists,
                    "未知列表引用",
                )
                value = lists[value["list"]]
            _check(
                _scalar(value)
                or isinstance(value, list)
                and len(value) <= 512
                and all(_scalar(v) for v in value),
                "条件值必须为标量或标量列表",
            )
            if op in {"in", "not_in", "intersects", "subset"}:
                _check(isinstance(value, list), f"{op} 需要列表")
            if op in {"gt", "gte", "lt", "lte"}:
                _check(type(value) in {int, float}, f"{op} 需要数值")
            if op in {"starts_with", "ends_with"}:
                _check(isinstance(value, str), f"{op} 需要字符串")
            if op == "exists":
                _check(type(value) is bool, "exists 需要布尔值")
            if op in SPECIAL_OPS:
                _check(validate_special_values(op, value), f"{op} 需要有效的域名、网段或目录列表")

    for name, node in atoms.items():
        _check(_identifier(name), f"无效条件原子名称 {name}")
        predicate(node, (name,))
    defaults = {rule["id"]: rule for rule in default_document()["rules"]}
    seen = set(defaults)
    for rule in rules:
        _check(
            isinstance(rule, dict)
            and not rule.keys()
            - {
                "id",
                "name",
                "enabled",
                "event",
                "mode",
                "risk_level",
                "priority",
                "when",
            },
            "规则包含未知字段",
        )
        rid = rule.get("id")
        _check(
            _identifier(rid) and rid not in seen,
            f"规则 ID 无效、重复或与内置冲突：{rid}",
        )
        seen.add(rid)
        _check(
            isinstance(rule.get("name"), str) and 0 < len(rule["name"].strip()) <= 160,
            "规则名称需要 1 至 160 个字符",
        )
        _check(type(rule.get("enabled", True)) is bool, "enabled 必须为布尔值")
        _check(
            isinstance(rule.get("event"), str) and rule["event"] in EVENTS, "未知事件"
        )
        _check(
            isinstance(rule.get("mode"), str) and rule["mode"] in MODES,
            "mode 必须为 observe/review/deny",
        )
        _check(
            isinstance(rule.get("risk_level", "warning"), str)
            and rule.get("risk_level", "warning") in LEVELS,
            "未知风险等级",
        )
        _check(
            type(rule.get("priority", 0)) is int
            and -10000 <= rule.get("priority", 0) <= 10000,
            "priority 需要 -10000 至 10000 整数",
        )
        predicate(rule.get("when"))
    for rid, override in overrides.items():
        _check(rid in defaults, f"未知内置规则 {rid}")
        _check(
            isinstance(override, dict)
            and bool(override)
            and not override.keys()
            - {"enabled", "mode", "when", "priority", "review_when"},
            f"{rid} 覆盖只允许 enabled/mode/when/priority/review_when",
        )
        if "enabled" in override:
            _check(type(override["enabled"]) is bool, "enabled 必须为布尔值")
        if "mode" in override:
            _check(
                isinstance(override["mode"], str)
                and (
                    override["mode"] in MODES
                    or override["mode"] == "transform"
                    and defaults[rid]["mode"] == "transform"
                ),
                "未知覆盖模式",
            )
        if "priority" in override:
            _check(
                type(override["priority"]) is int
                and -10000 <= override["priority"] <= 10000,
                "priority 越界",
            )
        if "when" in override:
            predicate(override["when"])
        if "review_when" in override:
            _check(
                defaults[rid]["mode"] == "transform", "review_when 仅适用于内容处理策略"
            )
            predicate(override["review_when"])
    document = copy.deepcopy(
        {
            "schema_version": SCHEMA,
            "atoms": atoms,
            "lists": lists,
            "rules": rules,
            "overrides": overrides,
        }
    )
    if "semantic_atoms" in raw:
        document["semantic_atoms"] = copy.deepcopy(semantic_atoms)
    if "filesystem" in raw:
        document["filesystem"] = {"deny": denied}
    _check(
        len(json.dumps(document, ensure_ascii=False).encode()) <= MAX_BYTES,
        "策略文件超过 256 KiB",
    )
    return document


def _value(facts: Mapping[str, Any], field: str) -> Any:
    value: Any = facts
    for part in field.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


def matches(node: Mapping[str, Any], facts: Mapping[str, Any], document: Mapping[str, Any]) -> bool:
    """Pure deterministic compatibility API. Semantic leaves need evaluate()."""
    return explain_condition(node, facts, document)["result"] == "true"


def _leaf_matches(node: Mapping[str, Any], facts: Mapping[str, Any], document: Mapping[str, Any]) -> bool:
    actual, op, expected = _value(facts, node["field"]), node["op"], node["value"]
    if isinstance(expected, dict):
        expected = document["lists"][expected["list"]]
    if op == "exists":
        return (actual is not _MISSING) == expected
    if actual is _MISSING:
        return False
    if op in SPECIAL_OPS:
        return special_match(op, actual, expected, facts)
    if op == "eq":
        return type(actual) is type(expected) and actual == expected
    if op == "ne":
        return type(actual) is not type(expected) or actual != expected
    if op == "contains":
        return (
            isinstance(actual, (str, list))
            and (isinstance(expected, str) if isinstance(actual, str) else True)
            and expected in actual
        )
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "intersects":
        return isinstance(actual, list) and any(v in expected for v in actual)
    if op == "subset":
        return isinstance(actual, list) and all(v in expected for v in actual)
    if op == "starts_with":
        return isinstance(actual, str) and actual.startswith(expected)
    if op == "ends_with":
        return isinstance(actual, str) and actual.endswith(expected)
    if type(actual) not in {int, float}:
        return False
    if op == "gt":
        return actual > expected
    if op == "gte":
        return actual >= expected
    if op == "lt":
        return actual < expected
    if op == "lte":
        return actual <= expected
    return False


def _combine(kind: str, results: list[str]) -> str:
    if kind == "not":
        return {"true": "false", "false": "true", "unknown": "unknown"}[results[0]]
    dominant = "false" if kind == "all" else "true"
    if dominant in results:
        return dominant
    return "unknown" if "unknown" in results else ("true" if kind == "all" else "false")


def explain_condition(node: Mapping[str, Any], facts: Mapping[str, Any],
                      document: Mapping[str, Any], semantic: Mapping[str, Any] | None = None,
                      path: str = "when") -> dict[str, Any]:
    """One complete traversal owns both the verdict and the explanation (no short circuit)."""
    from .redaction import redact_json
    base: dict[str, Any] = {"path": path}
    if "semantic" in node:
        name = node["semantic"]
        return {**base, "kind": "semantic", "name": name,
                **(semantic or {}).get(name, {"result": "unknown", "reason": "未执行语义判断"})}
    if "atom" in node:
        name = node["atom"]
        atom = builtin_atoms()[name] if name.startswith("meta.") else document["atoms"][name]
        child = explain_condition(atom, facts, document, semantic, path + ".atom")
        return {**base, "kind": "atom", "name": name, "result": child["result"], "children": [child]}
    for kind in ("all", "any", "not"):
        if kind in node:
            nodes = [node[kind]] if kind == "not" else node[kind]
            children = [explain_condition(n, facts, document, semantic, f"{path}.{kind}[{i}]") for i, n in enumerate(nodes)]
            return {**base, "kind": kind, "result": _combine(kind, [c["result"] for c in children]), "children": children}
    actual = _value(facts, node["field"])
    expected = node["value"]
    if isinstance(expected, dict):
        expected = document["lists"][expected["list"]]
    # Existing deterministic predicates retain v1 missing=false semantics. Show
    # this explicitly; new semantic unknowns never become true through NOT.
    safe_actual = redact_json({node["field"]: None if actual is _MISSING else actual})[node["field"]]
    safe_expected = redact_json({node["field"]: expected})[node["field"]]
    return {**base, "kind": "predicate", "field": node["field"], "op": node["op"],
            "expected": safe_expected, "actual": safe_actual, "value_present": actual is not _MISSING,
            "value_reference": node["value"] if isinstance(node["value"], dict) else None,
            "result": "true" if _leaf_matches(node, facts, document) else "false",
            "reason": "确定性字段比较" if actual is not _MISSING else
                      "字段缺失：exists 按存在性判断，其他 v1 比较为假（外层 not 会取反）"}


def _semantic_names(node: Mapping[str, Any], document: Mapping[str, Any]) -> set[str]:
    if "semantic" in node:
        return {node["semantic"]}
    if "atom" in node:
        name = node["atom"]
        return _semantic_names(builtin_atoms()[name] if name.startswith("meta.") else document["atoms"][name], document)
    if "not" in node:
        return _semantic_names(node["not"], document)
    return set().union(*(_semantic_names(n, document) for n in node.get("all", node.get("any", []))))


def effective_rules(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {**r, **document.get("overrides", {}).get(r["id"], {})}
        for r in default_document()["rules"]
    ] + copy.deepcopy(document.get("rules", []))


def evaluate(
    document: Mapping[str, Any],
    event: str,
    facts: Mapping[str, Any],
    *,
    revision: str = "preview",
    traces: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    decisions = []
    rules = effective_rules(document)
    active = [r for r in rules if r.get("enabled", True) and r["event"] == event]
    names = set().union(*(_semantic_names(r[key], document) for r in active for key in ("scope", "when", "review_when") if key in r))
    from .semantic_policy import judge_semantics
    semantic = judge_semantics({name: document["semantic_atoms"][name] for name in sorted(names)}, facts) if names else {}
    ruleset_revision = hashlib.sha256(
        json.dumps(
            {
                "rules": rules,
                "atoms": document.get("atoms", {}),
                "lists": document.get("lists", {}),
                "builtin_atoms": builtin_atoms(),
                "semantic_atoms": document.get("semantic_atoms", {}),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode()
    ).hexdigest()
    for rule in sorted(rules, key=lambda r: (-r.get("priority", 0), r["id"])):
        if not rule.get("enabled", True) or rule["event"] != event:
            continue
        condition = explain_condition(rule["when"], facts, document, semantic)
        scope = explain_condition(rule["scope"], facts, document, semantic, "scope") if "scope" in rule else None
        review = explain_condition(rule["review_when"], facts, document, semantic, "review_when") if "review_when" in rule else None
        result = _combine("all", [condition["result"], scope["result"] if scope else "true"])
        trace = {"schema_version": "lingmou.policy-trace.v1", "policy_id": rule["id"],
                 "policy_name": rule["name"], "result": result, "when": condition,
                 "scope": scope, "review_when": review, "policy_revision": revision,
                 "ruleset_revision": ruleset_revision, "configured_mode": rule["mode"]}
        if traces is not None:
            traces.append(trace)
        if result == "false":
            trace["effective_mode"] = "none"
            continue
        transform = rule["mode"] == "transform"
        uncertain = result == "unknown" or (transform and review is not None and review["result"] == "unknown")
        mode = "review" if (uncertain and rule["mode"] != "observe") or (transform and review is not None and review["result"] != "false") else rule["mode"]
        trace["effective_mode"] = mode
        decisions.append(
            {
                "schema_version": "lingmou.policy-decision.v1",
                "policy_id": rule["id"],
                "policy_name": rule["name"],
                "level": rule.get("risk_level", "warning"),
                "mode": mode,
                "stage": "pre_execution_approval"
                if event == "command.approval"
                else "commit",
                "action": {
                    "observe": "记录",
                    "review": "人工复核",
                    "deny": "执行前阻断",
                    "transform": "处理内容后继续",
                }[mode],
                "result": "blocked"
                if mode == "deny"
                else "review"
                if mode == "review"
                else "transformed"
                if mode == "transform"
                else "observed",
                "matched": result == "true",
                "uncertain": uncertain,
                "blocking": mode == "deny",
                "transform": transform,
                "reason": f"{rule['name']}：" + ("条件尚不能确定，需复核" if uncertain else "配置条件命中"),
                "evidence_source": "atomic_policy",
                "enforceable_now": True,
                "stateful": False,
                "tested": "unverified",
                "evidence": {
                    "policy_revision": revision,
                    "ruleset_revision": ruleset_revision,
                    "event": event,
                    "condition_trace": trace,
                },
            }
        )
    return decisions


def config_path(workspace: Path | str | None) -> Path | None:
    configured = os.environ.get("LINGMOU_POLICY_FILE")
    return (
        Path(configured).expanduser().absolute()
        if configured
        else Path(workspace).resolve() / ".lingmou-policy-rules.json"
        if workspace is not None
        else None
    )


def load_document(workspace: Path | str | None) -> tuple[dict[str, Any], str]:
    path = config_path(workspace)
    if path is None:
        return empty_document(), "default"
    try:
        _check(not path.is_symlink(), "策略配置不能是符号链接")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            _check(
                stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                "策略配置必须为普通文件",
            )
            data = stream.read(MAX_BYTES + 1)
        _check(len(data) <= MAX_BYTES, "策略文件超过 256 KiB")
        return validate_document(json.loads(data)), hashlib.sha256(data).hexdigest()
    except FileNotFoundError:
        return empty_document(), "default"
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise PolicyConfigError(f"无法读取策略配置：{exc}") from exc


def save_document(
    workspace: Path | str, raw: Any, revision: str
) -> tuple[dict[str, Any], str]:
    document = validate_document(raw)
    path = config_path(workspace)
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    with (
        _LOCK,
        os.fdopen(
            os.open(
                path.with_name(path.name + ".lock"),
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
            ),
            "a",
        ) as lock_file,
    ):
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        _, current = load_document(workspace)
        if revision != current:
            raise PolicyConflict("策略已被修改，请重新载入后合并更改")
        data = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".lingmou-policy-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return document, hashlib.sha256(data).hexdigest()
