"""Turn-scoped PDF and image token accounting.

The tracker deliberately answers a narrow question: how many tokens has the
current PDF/image analysis turn used so far?  It does not infer page position
or model attention.  Completed model calls use provider usage, while the one
active call keeps the existing request/output estimate and its quality label.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_MEDIA_MODALITIES = frozenset({"pdf", "image"})
_TERMINAL_TURN_STATES = frozenset(
    {"completed", "failed", "declined", "cancelled", "interrupted"}
)
_PDF_COMMAND_RE = re.compile(
    r"(?:^|[\s/])(?:pdftotext|pdfinfo|pdftoppm|pdfimages|mutool|qpdf|"
    r"ocrmypdf)(?:\s|$)|\b(?:pypdf|pymupdf|fitz\.open)\b",
    re.IGNORECASE,
)
_IMAGE_COMMAND_RE = re.compile(
    r"(?:^|[\s/])(?:identify|magick|convert)(?:\s|$).*"
    r"\.(?:png|jpe?g|gif|webp|bmp|tiff?)(?:\s|$)",
    re.IGNORECASE,
)
_IMAGE_HEADER_LIMIT = 2 * 1024 * 1024
_PATCH_BUDGET_1536_MODELS = (
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.3-codex",
    "gpt-5.2-codex",
    "gpt-5.2-chat-latest",
    "gpt-5.2",
    "gpt-5.1-codex-mini",
    "gpt-5-codex-mini",
    "gpt-5-mini",
    "gpt-5-nano",
    "o4-mini",
)
_PATCH_TOKEN_MULTIPLIERS = {
    "gpt-5.4-mini": 1.62,
    "gpt-5.4-nano": 2.46,
    "gpt-5-mini": 1.62,
    "gpt-5-nano": 2.46,
    "o4-mini": 1.72,
}


def _as_int(value: object) -> int | None:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and value >= 0 and value == int(value):
        return int(value)
    return None


def _command_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return " ".join(str(item) for item in value)
    return ""


def image_dimensions_from_bytes(data: bytes) -> tuple[int, int] | None:
    """Read common image dimensions from a bounded header without decoding pixels."""

    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        return (width, height) if width > 0 and height > 0 else None
    if data[:6] in {b"GIF87a", b"GIF89a"} and len(data) >= 10:
        width = int.from_bytes(data[6:8], "little")
        height = int.from_bytes(data[8:10], "little")
        return (width, height) if width > 0 and height > 0 else None
    if data.startswith(b"BM") and len(data) >= 26:
        width = abs(int.from_bytes(data[18:22], "little", signed=True))
        height = abs(int.from_bytes(data[22:26], "little", signed=True))
        return (width, height) if width > 0 and height > 0 else None
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        if data[12:16] == b"VP8X":
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
            return (width, height)
        if data[12:16] == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
            b1, b2, b3, b4 = data[21:25]
            width = 1 + b1 + ((b2 & 0x3F) << 8)
            height = (
                1
                + ((b2 & 0xC0) >> 6)
                + (b3 << 2)
                + ((b4 & 0x0F) << 10)
            )
            return (width, height)
        if data[12:16] == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
            width = int.from_bytes(data[26:28], "little") & 0x3FFF
            height = int.from_bytes(data[28:30], "little") & 0x3FFF
            return (width, height) if width > 0 and height > 0 else None
    if not data.startswith(b"\xff\xd8"):
        return None

    # JPEG dimensions live in a Start Of Frame segment, usually near the start.
    offset = 2
    sof_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    while offset + 4 <= len(data):
        while offset < len(data) and data[offset] != 0xFF:
            offset += 1
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in {0x01, *range(0xD0, 0xDA)}:
            continue
        if offset + 2 > len(data):
            break
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(data):
            break
        if marker in sof_markers and segment_length >= 7:
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            return (width, height) if width > 0 and height > 0 else None
        offset += segment_length
    return None


def _bounded_patch_count(
    width: int,
    height: int,
    *,
    patch_budget: int,
    max_dimension: int,
) -> int:
    original = math.ceil(width / 32) * math.ceil(height / 32)
    if original <= patch_budget and max(width, height) <= max_dimension:
        return original

    scale = min(1.0, max_dimension / max(width, height))
    scaled_width = width * scale
    scaled_height = height * scale
    if math.ceil(scaled_width / 32) * math.ceil(scaled_height / 32) > patch_budget:
        shrink = math.sqrt(
            (32 * 32 * patch_budget) / (scaled_width * scaled_height)
        )
        width_in_patches = scaled_width * shrink / 32
        height_in_patches = scaled_height * shrink / 32
        adjustment = min(
            math.floor(width_in_patches) / width_in_patches,
            math.floor(height_in_patches) / height_in_patches,
        )
        scale *= shrink * adjustment

    resized_width = max(1, math.floor(width * scale))
    resized_height = max(1, math.floor(height * scale))
    return min(
        patch_budget,
        math.ceil(resized_width / 32) * math.ceil(resized_height / 32),
    )


def estimate_image_input_tokens(
    width: int,
    height: int,
    *,
    model: str | None,
    detail: str | None = None,
) -> int | None:
    """Estimate one image's input tokens using OpenAI's documented sizing rules."""

    if (
        type(width) is not int
        or type(height) is not int
        or width <= 0
        or height <= 0
    ):
        return None
    normalized_model = (model or "").strip().lower()
    normalized_detail = (detail or "auto").strip().lower()
    if normalized_detail not in {"low", "high", "original", "auto"}:
        normalized_detail = "auto"

    # Patch-tokenized model families. Low detail receives a 512 x 512 image.
    if normalized_model.startswith("gpt-5.6"):
        # The public guide defines original/auto exactly. It only describes
        # high as finite, so the prior family's high limits are a local fallback.
        patches = (
            256
            if normalized_detail == "low"
            else (
                _bounded_patch_count(
                    width,
                    height,
                    patch_budget=2_500,
                    max_dimension=2_048,
                )
                if normalized_detail == "high"
                else math.ceil(width / 32) * math.ceil(height / 32)
            )
        )
        return patches
    if normalized_model.startswith("gpt-5.5"):
        if normalized_detail == "low":
            return 256
        original_detail = normalized_detail in {"auto", "original"}
        return _bounded_patch_count(
            width,
            height,
            patch_budget=10_000 if original_detail else 2_500,
            max_dimension=6_000 if original_detail else 2_048,
        )
    if normalized_model.startswith("gpt-5.4") and not normalized_model.startswith(
        ("gpt-5.4-mini", "gpt-5.4-nano")
    ):
        if normalized_detail == "low":
            return 256
        original_detail = normalized_detail == "original"
        return _bounded_patch_count(
            width,
            height,
            patch_budget=10_000 if original_detail else 2_500,
            max_dimension=6_000 if original_detail else 2_048,
        )
    if normalized_model.startswith(_PATCH_BUDGET_1536_MODELS):
        patches = (
            256
            if normalized_detail == "low"
            else _bounded_patch_count(
                width,
                height,
                patch_budget=1_536,
                max_dimension=2_048,
            )
        )
        multiplier = next(
            (
                value
                for prefix, value in _PATCH_TOKEN_MULTIPLIERS.items()
                if normalized_model.startswith(prefix)
            ),
            1.0,
        )
        return math.ceil(patches * multiplier)

    # GPT-5 and the older 4o/4.1 families use fixed-base 512px tiles.
    if normalized_model == "gpt-5" or normalized_model.startswith(
        ("gpt-5-chat", "gpt-4o", "gpt-4.1", "gpt-4.5")
    ):
        base, per_tile = (
            (70, 140)
            if normalized_model.startswith(("gpt-5",))
            else (85, 170)
        )
        if normalized_detail == "low":
            return base
        fit_scale = min(1.0, 2_048 / max(width, height))
        fitted_width = width * fit_scale
        fitted_height = height * fit_scale
        shortest_scale = 768 / min(fitted_width, fitted_height)
        tiled_width = fitted_width * shortest_scale
        tiled_height = fitted_height * shortest_scale
        tiles = math.ceil(tiled_width / 512) * math.ceil(tiled_height / 512)
        return base + per_tile * tiles

    # Unknown future patch-based variants still get a useful local value.
    return math.ceil(width / 32) * math.ceil(height / 32)


def estimate_image_file_input_tokens(
    path: object,
    *,
    model: str | None,
    detail: str | None = None,
) -> int | None:
    """Estimate image input tokens from a local file while retaining no pixels."""

    if not isinstance(path, str) or not path.strip():
        return None
    try:
        with Path(path).expanduser().open("rb") as handle:
            dimensions = image_dimensions_from_bytes(handle.read(_IMAGE_HEADER_LIMIT))
    except OSError:
        return None
    if dimensions is None:
        return None
    return estimate_image_input_tokens(
        *dimensions,
        model=model,
        detail=detail,
    )


def detect_tool_media(
    item_type: str,
    item: Mapping[str, Any],
) -> dict[str, str]:
    """Return conservative media evidence without retaining command content."""

    if item_type == "imageView":
        return {"image": "image_view"}

    if item_type == "commandExecution":
        command = _command_text(item.get("command"))
        detected: dict[str, str] = {}
        if _PDF_COMMAND_RE.search(command):
            detected["pdf"] = "pdf_command"
        if _IMAGE_COMMAND_RE.search(command):
            detected["image"] = "image_command"
        return detected

    if item_type not in {"mcpToolCall", "dynamicToolCall", "functionCall"}:
        return {}
    identity = " ".join(
        str(item.get(key) or "")
        for key in ("tool", "toolName", "name", "title")
    ).lower()
    detected = {}
    if "pdf" in identity and any(
        verb in identity for verb in ("read", "parse", "extract", "render", "view")
    ):
        detected["pdf"] = "structured_tool"
    if "image" in identity and any(
        verb in identity for verb in ("read", "inspect", "view", "analyze")
    ):
        detected["image"] = "structured_tool"
    return detected


@dataclass(slots=True)
class MediaTokenTaskTracker:
    """Keep privacy-safe evidence that the current turn is a media task."""

    turn_id: str | None = None
    modalities: set[str] = field(default_factory=set)
    detection_sources: set[str] = field(default_factory=set)
    request_modalities: dict[str, dict[str, int]] = field(default_factory=dict)
    tool_evidence_ids: set[str] = field(default_factory=set)
    image_token_estimates: dict[str, int] = field(default_factory=dict)
    detected_at: float | None = None
    detected_slice_index: int | None = None

    def start_turn(self, turn_id: str) -> None:
        self.turn_id = turn_id
        self.modalities.clear()
        self.detection_sources.clear()
        self.request_modalities.clear()
        self.tool_evidence_ids.clear()
        self.image_token_estimates.clear()
        self.detected_at = None
        self.detected_slice_index = None

    def _note_detection(
        self,
        modalities: Mapping[str, object],
        *,
        source: str,
        mono: float | None,
        slice_index: int | None,
    ) -> bool:
        before = (
            set(self.modalities),
            set(self.detection_sources),
            self.detected_at,
            self.detected_slice_index,
        )
        for modality in _MEDIA_MODALITIES:
            count = _as_int(modalities.get(modality))
            if count:
                self.modalities.add(modality)
        if not self.modalities:
            return False
        self.detection_sources.add(source)
        if self.detected_at is None:
            self.detected_at = mono if mono is not None else time.monotonic()
        if slice_index is not None and (
            self.detected_slice_index is None
            or slice_index < self.detected_slice_index
        ):
            self.detected_slice_index = slice_index
        return before != (
            set(self.modalities),
            set(self.detection_sources),
            self.detected_at,
            self.detected_slice_index,
        )

    def observe_request(
        self,
        modality_counts: Mapping[str, object],
        *,
        request_id: str | None,
        slice_index: int,
        mono: float | None = None,
    ) -> bool:
        filtered = {
            modality: count
            for modality in _MEDIA_MODALITIES
            if (count := _as_int(modality_counts.get(modality)))
        }
        if not filtered:
            return False
        key = request_id or f"slice:{slice_index}"
        changed = self.request_modalities.get(key) != filtered
        self.request_modalities[key] = filtered
        return (
            self._note_detection(
                filtered,
                source="request_body",
                mono=mono,
                # Request-local estimates already cover direct media. Only a
                # media tool starts attribution of later tool-output context.
                slice_index=None,
            )
            or changed
        )

    def observe_tool(
        self,
        item_id: str,
        item_type: str,
        item: Mapping[str, Any],
        *,
        mono: float | None = None,
        slice_index: int | None = None,
        model: str | None = None,
    ) -> bool:
        detected = detect_tool_media(item_type, item)
        if not detected:
            return False
        evidence_key = f"{item_id}:{','.join(sorted(detected))}"
        is_new = evidence_key not in self.tool_evidence_ids
        self.tool_evidence_ids.add(evidence_key)
        counts = {modality: 1 for modality in detected}
        changed = self._note_detection(
            counts,
            source="tool",
            mono=mono,
            slice_index=slice_index,
        )
        if item_type == "imageView":
            estimate = estimate_image_file_input_tokens(
                item.get("path"),
                model=model,
                detail=(
                    item.get("detail")
                    if isinstance(item.get("detail"), str)
                    else None
                ),
            )
            if estimate is not None and self.image_token_estimates.get(item_id) != estimate:
                self.image_token_estimates[item_id] = estimate
                self.detection_sources.add("local_image_patch")
                changed = True
        for source in detected.values():
            if source not in self.detection_sources:
                self.detection_sources.add(source)
                changed = True
        return changed or is_new

    def _media_occurrence_counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for counts in self.request_modalities.values():
            for modality, count in counts.items():
                result[modality] = result.get(modality, 0) + count
        for modality in self.modalities:
            result.setdefault(modality, 1)
        return result

    def to_dict(
        self,
        *,
        turn_status: str | None,
        reconciliation_history: Sequence[Mapping[str, Any]],
        inflight: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not self.modalities or self.turn_id is None:
            return {"detected": False}

        completed_rows = [
            row for row in reconciliation_history if row.get("turn_id") == self.turn_id
        ]

        def completed_sum(key: str) -> int:
            return sum(_as_int(row.get(key)) or 0 for row in completed_rows)

        official_input = completed_sum("official_input_tokens")
        official_output = completed_sum("official_output_tokens")
        official_reasoning = completed_sum("official_reasoning_output_tokens")
        official_total = completed_sum("official_total_tokens")
        current_active = bool(
            inflight.get("active") is True and inflight.get("turn_id") == self.turn_id
        )

        current_input_p50 = (
            _as_int(inflight.get("input_tokens_estimated_p50")) or 0
            if current_active
            else 0
        )
        current_input_p90 = (
            _as_int(inflight.get("input_tokens_estimated_p90")) or current_input_p50
            if current_active
            else 0
        )
        current_output_observed = (
            _as_int(inflight.get("output_tokens_observed")) or 0
            if current_active
            else 0
        )
        current_output_p50 = (
            _as_int(inflight.get("output_tokens_likely_p50"))
            or current_output_observed
            if current_active
            else 0
        )
        current_output_p90 = (
            _as_int(inflight.get("output_tokens_likely_p90")) or current_output_p50
            if current_active
            else 0
        )
        current_total_lower = (
            _as_int(inflight.get("live_tokens_lower_bound"))
            or current_input_p50 + current_output_observed
            if current_active
            else 0
        )
        current_total_p50 = current_input_p50 + current_output_p50
        current_total_p90 = current_input_p90 + current_output_p90

        media_entries: list[Mapping[str, Any]] = []
        for row in completed_rows:
            counts = row.get("input_modality_counts")
            if isinstance(counts, Mapping) and any(
                _as_int(counts.get(modality)) for modality in _MEDIA_MODALITIES
            ):
                media_entries.append(row)
        if current_active:
            counts = inflight.get("input_modality_counts")
            if isinstance(counts, Mapping) and any(
                _as_int(counts.get(modality)) for modality in _MEDIA_MODALITIES
            ):
                media_entries.append(inflight)

        def provider_exact_media(row: Mapping[str, Any]) -> bool:
            quality = row.get("input_multimodal_tokens_quality")
            if quality is not None:
                return quality == "provider_exact"
            source = row.get("input_estimate_source") or row.get(
                "input_estimate_observation_source"
            )
            return source == "provider_preflight_exact"

        exact_media_values = [
            value
            for row in media_entries
            if provider_exact_media(row)
            and (
                value := _as_int(row.get("input_multimodal_tokens_derived"))
            )
            is not None
        ]
        local_media_values = [
            value
            for row in media_entries
            if not provider_exact_media(row)
            and (
                value := _as_int(row.get("input_multimodal_tokens_derived"))
            )
            is not None
        ]

        def after_tool_detection(row: Mapping[str, Any]) -> bool:
            slice_index = _as_int(row.get("slice_index"))
            return (
                self.detected_slice_index is not None
                and slice_index is not None
                and slice_index > self.detected_slice_index
            )

        tool_context_tokens = sum(
            _as_int(row.get("tool_context_tokens_estimated")) or 0
            for row in completed_rows
            if after_tool_detection(row)
        )
        if current_active and after_tool_detection(inflight):
            tool_context_tokens += (
                _as_int(inflight.get("input_tool_context_tokens")) or 0
            )

        provider_media_tokens = sum(exact_media_values)
        request_local_media_tokens = sum(local_media_values)
        image_file_media_tokens = sum(self.image_token_estimates.values())
        direct_media_tokens = max(
            provider_media_tokens + request_local_media_tokens,
            image_file_media_tokens,
        )
        media_input_tokens = tool_context_tokens + direct_media_tokens

        has_local_component = bool(
            tool_context_tokens
            or request_local_media_tokens
            or image_file_media_tokens > provider_media_tokens
        )
        if exact_media_values and not has_local_component and (
            len(exact_media_values) == len(media_entries)
        ):
            media_breakdown_quality = "provider_exact"
        elif exact_media_values:
            media_breakdown_quality = "provider_exact_plus_local_estimate"
        else:
            media_breakdown_quality = "local_estimate"

        terminal = str(turn_status or "") in _TERMINAL_TURN_STATES
        if terminal and not current_active:
            quality = "official_completed" if completed_rows else "unavailable"
        elif current_active:
            quality = "estimated_active"
        else:
            quality = "official_so_far"

        provider_statuses = sorted(
            {
                str(status)
                for row in media_entries
                if (status := row.get("input_provider_count_status"))
            }
        )
        return {
            "detected": True,
            "turn_id": self.turn_id,
            "running": not terminal,
            "quality": quality,
            "modalities": sorted(self.modalities),
            "modality_counts": self._media_occurrence_counts(),
            "detection_sources": sorted(self.detection_sources),
            "direct_media_request_count": len(self.request_modalities),
            "tool_evidence_count": len(self.tool_evidence_ids),
            "model_call_count": len(completed_rows) + int(current_active),
            "completed_model_call_count": len(completed_rows),
            "current_call_active": current_active,
            "input_tokens_p50": official_input + current_input_p50,
            "input_tokens_p90": official_input + current_input_p90,
            "output_tokens_observed": official_output + current_output_observed,
            "output_tokens_p50": official_output + current_output_p50,
            "output_tokens_p90": official_output + current_output_p90,
            "total_tokens_lower_bound": official_total + current_total_lower,
            "total_tokens_p50": official_total + current_total_p50,
            "total_tokens_p90": official_total + current_total_p90,
            "official_input_tokens_so_far": official_input,
            "official_output_tokens_so_far": official_output,
            "official_reasoning_output_tokens_so_far": official_reasoning,
            "official_total_tokens_so_far": official_total,
            "media_input_tokens_derived": media_input_tokens,
            "media_input_breakdown_quality": media_breakdown_quality,
            "media_input_breakdown_call_count": len(exact_media_values),
            "media_input_provider_exact_tokens": provider_media_tokens,
            "media_input_local_estimate_tokens": (
                media_input_tokens - provider_media_tokens
            ),
            "media_input_tool_context_tokens_estimated": tool_context_tokens,
            "media_input_image_patch_tokens_estimated": image_file_media_tokens,
            "provider_count_statuses": provider_statuses,
            "estimate_not_billable": quality == "estimated_active",
        }
