#!/usr/bin/env python3
"""Run one real Codex image request through RequestTokenTap.

The Codex CLI reads its own existing ChatGPT login. This script never opens the
credential store, exports a bearer token, or persists request/response content.
Only an official ChatGPT upstream is allowed because the relay forwards the
CLI-provided Authorization header.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from codexscope.request_token_tap import RequestInputEstimate, RequestTokenTap


_UPSTREAM = "https://chatgpt.com/backend-api/codex"
_PROVIDER_ID = "codexscope_request_tap"
_PROMPT = "Inspect the attached image. Reply with exactly OK and use no tools."


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _safe_non_negative_int(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _safe_usage(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    for key in (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
    ):
        count = _safe_non_negative_int(value.get(key))
        if count is not None:
            result[key] = count
    for source_key, target_key in (
        ("input_tokens_details", "input_details"),
        ("output_tokens_details", "output_details"),
    ):
        details = value.get(source_key)
        if not isinstance(details, Mapping):
            continue
        safe_details = {
            str(key): count
            for key, raw in details.items()
            if (count := _safe_non_negative_int(raw)) is not None
        }
        if safe_details:
            result[target_key] = safe_details
    return result or None


def _usage_from_event(data: Mapping[str, Any]) -> dict[str, Any] | None:
    direct = _safe_usage(data.get("usage"))
    if direct is not None:
        return direct
    response = data.get("response")
    if isinstance(response, Mapping):
        return _safe_usage(response.get("usage"))
    return None


def _usage_from_codex_jsonl(value: str) -> dict[str, Any] | None:
    """Extract only numeric usage while discarding all JSONL content fields."""

    observed: dict[str, Any] | None = None
    for line in value.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, Mapping):
            continue
        usage = _safe_usage(event.get("usage"))
        if usage is not None:
            observed = usage
    return observed


def _provider_arguments(local_base_url: str, codex_version: str) -> list[str]:
    provider = (
        f"model_providers.{_PROVIDER_ID}={{"
        'name="OpenAI",'
        f"base_url={json.dumps(local_base_url)},"
        'wire_api="responses",'
        f"http_headers={{version={json.dumps(codex_version)}}},"
        "requires_openai_auth=true,"
        "supports_websockets=false,"
        "supports_standalone_web_search=false"
        "}"
    )
    return [
        "-c",
        f"model_provider={json.dumps(_PROVIDER_ID)}",
        "-c",
        provider,
        "-c",
        "features.enable_request_compression=false",
        "-c",
        'approval_policy="never"',
    ]


def _settled_stats(tap: RequestTokenTap, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    stats = tap.stats_dict()
    while time.monotonic() < deadline:
        stats = tap.stats_dict()
        if int(stats.get("provider_count_error_count") or 0) > 0:
            return stats
        if int(stats.get("provider_breakdown_success_count") or 0) > 0:
            return stats
        if int(stats.get("provider_breakdown_error_count") or 0) > 0:
            return stats
        time.sleep(0.05)
    return stats


def _write_evidence(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    for forbidden in ("Bearer ", "access_token", "refresh_token", _PROMPT):
        if forbidden in serialized:
            raise RuntimeError("evidence privacy invariant failed")
    path.write_text(f"{serialized}\n", encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send one image through CodexScope RequestTokenTap using the Codex "
            "CLI's existing ChatGPT login."
        )
    )
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path("artifacts/codex_image_tap_e2e.json"),
    )
    parser.add_argument("--request-timeout", type=float, default=180.0)
    parser.add_argument("--count-timeout", type=float, default=45.0)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    image_path = args.image.expanduser().resolve()
    try:
        metadata = image_path.lstat()
    except OSError:
        raise SystemExit("image is not readable")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 5 * 1024 * 1024:
        raise SystemExit("image must be a regular file no larger than 5 MiB")
    if args.request_timeout <= 0 or args.count_timeout <= 0:
        raise SystemExit("timeouts must be positive")

    upstream = urlsplit(_UPSTREAM)
    if upstream.scheme != "https" or upstream.hostname != "chatgpt.com":
        raise RuntimeError("OAuth relay upstream must remain official ChatGPT")

    login = subprocess.run(
        [args.codex_bin, "login", "status"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=15,
    )
    chatgpt_login = login.returncode == 0 and "ChatGPT" in login.stdout
    if not chatgpt_login:
        raise SystemExit("Codex CLI is not logged in with ChatGPT")
    version_result = subprocess.run(
        [args.codex_bin, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        timeout=15,
    )
    codex_version = (
        version_result.stdout.strip().rsplit(maxsplit=1)[-1]
        if version_result.returncode == 0 and version_result.stdout.strip()
        else "unknown"
    )

    estimates: list[RequestInputEstimate] = []
    final_usage: dict[str, Any] | None = None

    def observe_event(_name: str, data: Mapping[str, Any]) -> None:
        nonlocal final_usage
        usage = _usage_from_event(data)
        if usage is not None:
            final_usage = usage

    tap = RequestTokenTap(
        _UPSTREAM,
        on_input_estimate=estimates.append,
        on_sse_event=observe_event,
        timeout_s=args.request_timeout,
        provider_count_timeout_s=args.count_timeout,
    ).start()
    started_at = _utc_now()
    started_mono = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="codexscope-image-e2e-") as workspace:
        command = [
            args.codex_bin,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--json",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--cd",
            workspace,
            "--model",
            args.model,
            "--image",
            os.fspath(image_path),
            *_provider_arguments(tap.local_base_url, codex_version),
            _PROMPT,
        ]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=args.request_timeout,
            )
            return_code: int | None = completed.returncode
            subprocess_error: str | None = None
            cli_usage = _usage_from_codex_jsonl(completed.stdout)
            # Do not retain response/prompt-bearing JSONL after numeric extract.
            completed.stdout = ""
        except subprocess.TimeoutExpired:
            return_code = None
            subprocess_error = "TimeoutExpired"
            cli_usage = None
        except OSError as exc:
            return_code = None
            subprocess_error = type(exc).__name__
            cli_usage = None

    stats = _settled_stats(tap, args.count_timeout + 2.0)
    tap.stop()
    if cli_usage is not None:
        final_usage = cli_usage
    local = estimates[0] if estimates else None
    final = estimates[-1] if estimates else None
    provider_status = (
        final.provider_count_status if final is not None else "not_observed"
    )
    exact_full = (
        final.input_tokens
        if final is not None
        and final.source == "provider_preflight_exact"
        and provider_status in {"exact", "exact_with_breakdown"}
        else None
    )
    official_input = (
        final_usage.get("input_tokens") if final_usage is not None else None
    )
    reconciliation = None
    if type(exact_full) is int and type(official_input) is int:
        reconciliation = {
            "basis": "provider_preflight_exact",
            "preflight_minus_final_input_tokens": exact_full - official_input,
            "input_tokens_match": exact_full == official_input,
        }
    elif (
        local is not None
        and type(local.input_tokens) is int
        and type(official_input) is int
    ):
        reconciliation = {
            "basis": "local_text_estimate",
            "final_minus_local_input_tokens": official_input - local.input_tokens,
        }
    if return_code == 0 and provider_status == "unavailable":
        outcome = "generation_supported_preflight_fail_open"
    elif return_code == 0:
        outcome = "generation_supported"
    elif subprocess_error is not None:
        outcome = "cli_transport_or_timeout_error"
    else:
        outcome = "cli_rejected_or_failed"

    evidence = {
        "schema_version": 1,
        "suite": "codexscope-codex-oauth-image-tap-e2e",
        "started_at": started_at,
        "finished_at": _utc_now(),
        "elapsed_ms": round(1000.0 * (time.monotonic() - started_mono), 3),
        "real_provider_called": int(stats.get("request_count") or 0) > 0,
        "provider_origin": "https://chatgpt.com",
        "auth_owner": "codex_cli",
        "auth_mode_observed": "chatgpt",
        "credential_extracted_or_persisted": False,
        "authorization_header_forwarded_in_memory_by_relay": (
            int(stats.get("request_count") or 0) > 0
        ),
        "request_or_response_content_persisted": False,
        "model": args.model,
        "modality": "image",
        "sample": {
            "byte_count": metadata.st_size,
            "sha256": hashlib.sha256(image_path.read_bytes()).hexdigest(),
        },
        "outcome": outcome,
        "codex_cli": {
            "version": codex_version,
            "return_code": return_code,
            "error_type": subprocess_error,
            "ephemeral": True,
            "sandbox": "read-only",
        },
        "preflight": {
            "provider_status": provider_status,
            "local_text_estimate": (
                local.input_tokens if local is not None else None
            ),
            "full_input_tokens": exact_full,
            "text_only_input_tokens": (
                final.text_input_tokens if final is not None else None
            ),
            "multimodal_input_tokens_derived": (
                final.multimodal_input_tokens if final is not None else None
            ),
            "latency_ms": (
                final.provider_count_latency_ms if final is not None else None
            ),
            "modality_counts": (
                dict(local.modality_counts) if local is not None else {}
            ),
        },
        "final_usage": final_usage,
        "final_usage_source": (
            "codex_exec_turn_completed" if cli_usage is not None else None
        ),
        "reconciliation": reconciliation,
        "tap_stats": {
            key: stats.get(key)
            for key in (
                "request_count",
                "observed_request_count",
                "multimodal_request_count",
                "provider_count_attempt_count",
                "provider_count_success_count",
                "provider_count_error_count",
                "provider_breakdown_attempt_count",
                "provider_breakdown_success_count",
                "provider_breakdown_error_count",
                "sse_event_count",
                "error_count",
            )
        },
    }
    _write_evidence(args.evidence, evidence)
    print(os.fspath(args.evidence))
    return 0 if return_code == 0 and evidence["real_provider_called"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
