"""Reusable policy vocabulary and bounded, non-executable matching operators."""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from collections.abc import Mapping
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

FACT_FIELDS = {
    "command.workspace",
    "command.parse_complete",
    "network.hosts",
    "network.ports",
    "network.schemes",
    "network.methods",
    "network.address_classes",
    "network.upload",
    "network.download",
    "network.tls_verify_disabled",
    "network.present",
    "file.read_paths",
    "file.write_paths",
    "file.delete_paths",
    "file.permission_paths",
    "file.read",
    "file.write",
    "file.delete",
    "file.permission_change",
    "file.recursive",
    "file.force",
    "process.executables",
    "process.elevated",
    "process.shell",
}
SPECIAL_OPS = {
    "domain_matches",
    "domains_subset",
    "ip_in_cidr",
    "any_path_under",
    "all_paths_under",
}


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    return json.loads(
        files("codexscope").joinpath("policies/meta_policies.json").read_text()
    )


def meta_catalog() -> dict[str, Any]:
    return copy.deepcopy(_catalog())


def builtin_atoms() -> dict[str, Any]:
    return {
        item["id"]: item["predicate"]
        for item in _catalog()["items"]
        if item["parameter"] is None
    }


def _domain(value: str) -> str:
    return value.rstrip(".").encode("idna").decode("ascii").lower()


def validate_special_values(op: str, values: Any) -> bool:
    if not isinstance(values, list) or not all(
        isinstance(v, str) and v for v in values
    ):
        return False
    try:
        for value in values:
            if op in {"domain_matches", "domains_subset"}:
                host = _domain(value.removeprefix("*."))
                # No URLs, credentials, ports or unrestricted wildcard patterns.
                if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", host):
                    return False
            elif op == "ip_in_cidr":
                ipaddress.ip_network(value, strict=False)
            elif "\x00" in value or any(c in value for c in "*$?[]{}\n\r"):
                return False
        return True
    except (ValueError, UnicodeError):
        return False


def special_match(
    op: str, actual: Any, expected: list[str], facts: Mapping[str, Any]
) -> bool:
    if not isinstance(actual, list) or not all(isinstance(v, str) for v in actual):
        return False

    def domain_match(host: str, pattern: str) -> bool:
        host = _domain(host)
        if pattern.startswith("*."):
            root = _domain(pattern[2:])
            return host.endswith("." + root)
        return host == _domain(pattern)

    def path_match(path: str, root: str) -> bool:
        command = facts.get("command")
        workspace = command.get("workspace") if isinstance(command, Mapping) else None
        base = Path(root).expanduser()
        if not base.is_absolute():
            if not workspace:
                return False
            base = Path(workspace) / base
        # Facts are resolved by the extractor; never interpret relative facts as cwd.
        target = Path(path)
        return target.is_absolute() and target.resolve().is_relative_to(base.resolve())

    try:
        if op in {"domain_matches", "domains_subset"}:
            hits = [any(domain_match(v, p) for p in expected) for v in actual]
            return all(hits) if op == "domains_subset" else any(hits)
        if op == "ip_in_cidr":
            networks = [ipaddress.ip_network(v, strict=False) for v in expected]
            for host in actual:
                try:
                    address = ipaddress.ip_address(host)
                except ValueError:
                    continue  # No DNS requests during evaluation.
                candidates = [address]
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    candidates.append(address.ipv4_mapped)
                if any(
                    candidate in net for candidate in candidates for net in networks
                ):
                    return True
            return False
        hits = [any(path_match(v, p) for p in expected) for v in actual]
        return all(hits) if op == "all_paths_under" else any(hits)
    except (OSError, ValueError, RuntimeError, UnicodeError):
        return False
