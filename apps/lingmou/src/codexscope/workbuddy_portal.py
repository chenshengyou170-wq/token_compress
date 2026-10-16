"""Secure discovery of already-running WorkBuddy scenario workbenches."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .workbuddy_scenarios import runnable_scenario_ids


WORKBUDDY_PORTAL_SCHEMA_VERSION = "lingmou.workbuddy-portal.v1"


def default_workbuddy_portal_path() -> Path:
    """Return the per-user registry path without broadening its trust boundary."""

    state_root = os.environ.get("XDG_STATE_HOME")
    if state_root:
        return Path(state_root).expanduser() / "codexscope" / "workbuddy-portal.json"
    return Path.home() / ".local" / "state" / "codexscope" / "workbuddy-portal.json"


def _read_private_json(path: Path) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"WorkBuddy registry is not a regular file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise OSError(f"WorkBuddy registry is owned by another user: {path}")
        if metadata.st_mode & 0o077:
            raise OSError(f"WorkBuddy registry permissions must be 0600 or stricter: {path}")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            return json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validated_launch_url(value: Any, *, scenario_id: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ValueError(f"invalid WorkBuddy launch URL for {scenario_id}")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid WorkBuddy launch URL for {scenario_id}")
    if parsed.username or parsed.password or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError(f"unsafe WorkBuddy launch URL for {scenario_id}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid WorkBuddy launch port for {scenario_id}") from exc
    if port is None:
        raise ValueError(f"WorkBuddy launch URL requires an explicit port for {scenario_id}")

    hostname = parsed.hostname.casefold()
    loopback = hostname == "localhost"
    if not loopback:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError(
                f"WorkBuddy launch URL must use localhost or a private IP for {scenario_id}"
            ) from exc
        loopback = address.is_loopback
        if not loopback and not address.is_private:
            raise ValueError(f"WorkBuddy launch URL must stay on a private network for {scenario_id}")
    if not loopback and parsed.scheme != "https":
        raise ValueError(f"LAN WorkBuddy launch URL must use HTTPS for {scenario_id}")

    query = parse_qs(parsed.query, keep_blank_values=True)
    if loopback:
        if query and set(query) != {"access_token"}:
            raise ValueError(f"unexpected WorkBuddy launch query for {scenario_id}")
    elif set(query) != {"access_token"} or len(query["access_token"]) != 1 or not query["access_token"][0]:
        raise ValueError(f"LAN WorkBuddy launch URL requires one access token for {scenario_id}")
    return value


def load_workbuddy_launch_urls(path: Path | None = None) -> dict[str, str]:
    """Load reviewed scenario links from one owner-only local registry.

    A missing registry is an ordinary empty state.  An existing but unsafe or
    malformed registry fails closed so the UI never becomes an arbitrary-link
    launcher.
    """

    registry_path = (path or default_workbuddy_portal_path()).expanduser()
    try:
        value = _read_private_json(registry_path)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid WorkBuddy registry JSON: {registry_path}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != WORKBUDDY_PORTAL_SCHEMA_VERSION:
        raise ValueError(f"unsupported WorkBuddy registry schema: {registry_path}")
    raw_scenarios = value.get("scenarios")
    if not isinstance(raw_scenarios, dict):
        raise ValueError(f"WorkBuddy registry scenarios must be an object: {registry_path}")

    runnable = set(runnable_scenario_ids())
    result: dict[str, str] = {}
    for raw_id, raw_entry in raw_scenarios.items():
        scenario_id = str(raw_id).strip().upper()
        if scenario_id not in runnable:
            raise ValueError(f"WorkBuddy registry contains a non-runnable scenario: {scenario_id}")
        if not isinstance(raw_entry, dict):
            raise ValueError(f"WorkBuddy registry entry must be an object: {scenario_id}")
        result[scenario_id] = _validated_launch_url(
            raw_entry.get("url"), scenario_id=scenario_id
        )
    return result


__all__ = [
    "WORKBUDDY_PORTAL_SCHEMA_VERSION",
    "default_workbuddy_portal_path",
    "load_workbuddy_launch_urls",
]
