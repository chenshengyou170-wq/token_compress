from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"


@dataclass(frozen=True, slots=True)
class RedactionLimits:
    """Bounds applied before an untrusted hook payload is persisted."""

    max_depth: int = 12
    max_fields: int = 512
    max_nodes: int = 2_048
    max_list_items: int = 128
    max_key_bytes: int = 256
    max_string_bytes: int = 8_192


DEFAULT_LIMITS = RedactionLimits()

_IDENTITY_KEYS = frozenset(
    {
        "session_id",
        "thread_id",
        "turn_id",
        "hook_event",
        "hook_event_name",
        "tool_use_id",
        "toolUseId",
    }
)

# Key matching is deliberately conservative: losing diagnostic detail is safer
# than writing a credential into a long-lived trace.  JSON token usage counters
# are kept because they cannot authenticate a request.
_SAFE_TOKEN_COUNTER_KEYS = re.compile(
    r"^(?:(?:input|output|cached|cached_?input|reasoning|reasoning_?output|total)_?)?"
    r"tokens?(?:_?(?:count|used))?$",
    re.IGNORECASE,
)
_SAFE_TOKEN_USAGE_CONTAINER_KEYS = frozenset({"tokenusage"})
_VALUE_NOT_PROVIDED = object()
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|passphrase|authorization|proxy[_-]?authorization|"
    r"cookie|set[_-]?cookie|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|secret)",
    re.IGNORECASE,
)

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_SENSITIVE_HEADER = re.compile(
    r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)"
    r"\s*:\s*[^\r\n]+"
)
_BEARER_OR_BASIC = re.compile(
    r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"
)
_OPENAI_KEY = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
_GITHUB_TOKEN = re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{8,}\b", re.IGNORECASE)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_URL_CREDENTIALS = re.compile(r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_ASSIGNED_SECRET = re.compile(
    r"(?i)(?P<label>\b(?:password|passwd|passphrase|authorization|api[_-]?key|"
    r"apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"secret)\b\s*(?::|=)\s*)(?P<quote>['\"]?)(?P<value>[^\s,;'\"]{3,})(?P=quote)"
)


def is_sensitive_key(key: str, value: Any = _VALUE_NOT_PROVIDED) -> bool:
    """Return whether values under *key* must be replaced wholesale."""

    if _SAFE_TOKEN_COUNTER_KEYS.fullmatch(key):
        # The protocol declares these as integers.  Retain the legacy
        # key-only classification API, but do not let a string value use a
        # counter-shaped key as a credential-smuggling escape hatch.
        return value is not _VALUE_NOT_PROVIDED and type(value) is not int
    # ``thread/tokenUsage/updated`` uses this exact container for numeric usage
    # counters.  Only dictionaries are admitted: a scalar under the same key
    # remains conservatively redacted, and recursive processing still removes
    # credentials hidden inside an otherwise valid-looking container.
    normalized_key = re.sub(r"[_-]", "", key).casefold()
    if normalized_key in _SAFE_TOKEN_USAGE_CONTAINER_KEYS and isinstance(value, dict):
        return False
    return _SENSITIVE_KEY.search(key) is not None or "token" in key.casefold()


def redact_text(value: str) -> str:
    """Remove common credential forms from free-form hook text."""

    value = _PRIVATE_KEY_BLOCK.sub(REDACTED, value)
    value = _SENSITIVE_HEADER.sub(lambda match: f"{match.group(1)}: {REDACTED}", value)
    value = _URL_CREDENTIALS.sub(lambda match: f"{match.group('scheme')}{REDACTED}@", value)
    value = _ASSIGNED_SECRET.sub(lambda match: f"{match.group('label')}{REDACTED}", value)
    value = _BEARER_OR_BASIC.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = _JWT.sub(REDACTED, value)
    value = _OPENAI_KEY.sub(REDACTED, value)
    value = _GITHUB_TOKEN.sub(REDACTED, value)
    return _AWS_ACCESS_KEY.sub(REDACTED, value)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    marker = f"{TRUNCATED}:{len(encoded)} bytes"
    marker_bytes = marker.encode("utf-8")
    if max_bytes <= len(marker_bytes):
        return TRUNCATED
    prefix = encoded[: max_bytes - len(marker_bytes)]
    return prefix.decode("utf-8", errors="ignore") + marker


@dataclass(slots=True)
class _Budget:
    fields_left: int
    nodes_left: int

    def take_node(self) -> bool:
        if self.nodes_left <= 0:
            return False
        self.nodes_left -= 1
        return True

    def take_field(self) -> bool:
        if self.fields_left <= 0:
            return False
        self.fields_left -= 1
        return True


def redact_json(value: Any, *, limits: RedactionLimits = DEFAULT_LIMITS) -> Any:
    """Recursively redact and bound a JSON-like value.

    The function is intentionally usable independently of the hook process so
    ingestion paths can apply exactly the same privacy policy.
    """

    budget = _Budget(fields_left=limits.max_fields, nodes_left=limits.max_nodes)
    return _redact(value, limits=limits, budget=budget, depth=0, top_level=True)


def _redact(
    value: Any,
    *,
    limits: RedactionLimits,
    budget: _Budget,
    depth: int,
    top_level: bool = False,
) -> Any:
    if not budget.take_node():
        return f"{TRUNCATED}: node limit"
    if depth > limits.max_depth:
        return f"{TRUNCATED}: depth limit"

    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _truncate_utf8(redact_text(value), limits.max_string_bytes)

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        keys = list(value)
        if top_level:
            # Identity fields remain available even if an attacker puts a huge
            # object before them in input order.
            keys.sort(key=lambda item: 0 if str(item) in _IDENTITY_KEYS else 1)
        omitted = 0
        for raw_key in keys:
            if not budget.take_field():
                omitted += 1
                continue
            key = _truncate_utf8(redact_text(str(raw_key)), limits.max_key_bytes)
            if key in result:
                # Truncation can collapse distinct hostile keys.  Never let one
                # silently replace another.
                suffix = 2
                candidate = f"{key}#{suffix}"
                while candidate in result:
                    suffix += 1
                    candidate = f"{key}#{suffix}"
                key = candidate
            item = value[raw_key]
            if is_sensitive_key(str(raw_key), item):
                result[key] = REDACTED
            else:
                result[key] = _redact(
                    item,
                    limits=limits,
                    budget=budget,
                    depth=depth + 1,
                )
        if omitted:
            result["_truncated_fields"] = omitted
        return result

    if isinstance(value, (list, tuple)):
        keep = min(len(value), limits.max_list_items)
        result = [
            _redact(item, limits=limits, budget=budget, depth=depth + 1)
            for item in value[:keep]
        ]
        if len(value) > keep:
            result.append(f"{TRUNCATED}: {len(value) - keep} list items")
        return result

    # Hook input comes from JSON, but keeping this total makes direct library
    # use safe too.  The representation is scrubbed like every other string.
    return _truncate_utf8(redact_text(repr(value)), limits.max_string_bytes)


# Friendly alias for callers that think in terms of complete events.
redact_event = redact_json
