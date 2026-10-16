"""In-flight usage estimation for proxies in front of remote model APIs.

The proxy can know the request payload and observe streamed output, but it
cannot see provider-internal reasoning or formatting tokens.  This module
therefore keeps three qualities separate:

* exact input tokens returned by a provider token-count endpoint;
* observed visible text plus model-authored tool-argument tokens, using streamed
  logprobs for text and a tokenizer fallback when logprobs are unavailable;
* a calibrated interval for provider-internal output tokens.

Only a completed response is treated as authoritative total usage.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


class ProxyUsageError(ValueError):
    """A remote stream or estimator input violated the expected protocol."""


def _non_negative_int(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ProxyUsageError(f"{field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class CompletedUsage:
    """Authoritative usage extracted from ``response.completed``."""

    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_tokens: int

    def __post_init__(self) -> None:
        for name, value in (
            ("input_tokens", self.input_tokens),
            ("cached_input_tokens", self.cached_input_tokens),
            ("output_tokens", self.output_tokens),
            ("reasoning_tokens", self.reasoning_tokens),
        ):
            _non_negative_int(value, name)
        if self.cached_input_tokens > self.input_tokens:
            raise ProxyUsageError("cached_input_tokens cannot exceed input_tokens")
        if self.reasoning_tokens > self.output_tokens:
            raise ProxyUsageError("reasoning_tokens cannot exceed output_tokens")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @classmethod
    def from_wire(cls, value: object) -> CompletedUsage:
        if not isinstance(value, Mapping):
            raise ProxyUsageError("completed response usage must be an object")
        input_details = value.get("input_tokens_details")
        output_details = value.get("output_tokens_details")
        if not isinstance(input_details, Mapping):
            raise ProxyUsageError("input_tokens_details must be an object")
        if not isinstance(output_details, Mapping):
            raise ProxyUsageError("output_tokens_details must be an object")
        usage = cls(
            input_tokens=_non_negative_int(value.get("input_tokens"), "input_tokens"),
            cached_input_tokens=_non_negative_int(
                input_details.get("cached_tokens"), "cached_tokens"
            ),
            output_tokens=_non_negative_int(
                value.get("output_tokens"), "output_tokens"
            ),
            reasoning_tokens=_non_negative_int(
                output_details.get("reasoning_tokens"), "reasoning_tokens"
            ),
        )
        total = _non_negative_int(value.get("total_tokens"), "total_tokens")
        if total != usage.total_tokens:
            raise ProxyUsageError(
                "total_tokens must equal input_tokens + output_tokens"
            )
        return usage


TokenCounter = Callable[[str], int]


def _heuristic_text_tokens(text: str) -> int:
    """Last-resort language-aware estimate when no model tokenizer exists.

    ASCII text is weighted at roughly four characters per token.  Non-ASCII
    code points receive at least one unit so Chinese text is not drastically
    under-counted by the usual ``len(text) / 4`` rule.  The result remains an
    estimate and is labelled as such by :class:`ProxyUsageMeter`.
    """

    if not text:
        return 0
    units = 0.0
    for character in text:
        if ord(character) < 128:
            units += 0.25
        else:
            units += max(1.0, len(character.encode("utf-8")) / 3.0)
    return max(1, math.ceil(units))


def default_token_counter(model: str) -> tuple[TokenCounter, str]:
    """Prefer an installed model tokenizer and fall back without dependency.

    ``tiktoken`` is intentionally optional so the demo remains runnable with
    CodexScope's base dependencies.  Production adapters should inject the
    tokenizer that matches their provider and model snapshot.
    """

    try:
        import tiktoken  # type: ignore[import-not-found]
    except ImportError:
        return _heuristic_text_tokens, "heuristic-est"

    try:
        encoding = tiktoken.encoding_for_model(model)
        source = "tokenizer-est"
    except KeyError:
        # tiktoken 0.13 knows the GPT-5 base family but does not yet map
        # dotted API names such as ``gpt-5.4``/``gpt-5.6``.  tiktoken's GPT-5
        # base mapping uses o200k_base; keep the family fallback explicitly
        # labelled as an estimate so a future tokenizer change cannot masquerade
        # as provider-authoritative usage.
        if not model.startswith(("gpt-5.", "gpt-6", "kimi-", "k3")):
            return _heuristic_text_tokens, "heuristic-est"
        try:
            encoding = tiktoken.get_encoding("o200k_base")
        except Exception:
            # Some tiktoken distributions download merge tables lazily.  A
            # live status callback must not fail merely because the cache is
            # cold or the monitor host is offline.
            return _heuristic_text_tokens, "heuristic-est"
        source = "tokenizer-family-est" if model.startswith("gpt-5.") else "tokenizer-proxy-o200k-est"
    except Exception:
        return _heuristic_text_tokens, "heuristic-est"
    # API text treats marker-looking strings as ordinary user content.  Using
    # encode_ordinary also avoids dropping an observation when a prompt or
    # tool schema happens to contain a tokenizer special-token spelling.
    return lambda text: len(encoding.encode_ordinary(text)), source


def _nearest_rank(samples: list[int], quantile: float) -> int:
    if not samples:
        return 0
    ordered = sorted(samples)
    rank = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[rank]


@dataclass(slots=True)
class ResidualCalibrator:
    """Small empirical model for hidden reasoning and formatting tokens.

    A production proxy should keep one instance per provider/model/reasoning
    effort/tool-mode cohort.  The seeded samples merely make the local demo
    useful before it has observed completed calls of its own.
    """

    residual_samples: list[int] = field(
        default_factory=lambda: [38, 45, 49, 52, 58, 66, 78]
    )
    typical_first_text_s: float = 1.25
    queue_grace_s: float = 0.15
    max_samples: int = 512

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in self.residual_samples):
            raise ValueError("residual samples must be non-negative integers")
        if self.typical_first_text_s <= 0:
            raise ValueError("typical_first_text_s must be positive")
        if self.queue_grace_s < 0:
            raise ValueError("queue_grace_s cannot be negative")
        if self.max_samples <= 0:
            raise ValueError("max_samples must be positive")

    def current_hidden_interval(
        self,
        *,
        elapsed_s: float,
        visible_started: bool,
    ) -> tuple[int, int, str]:
        """Return current hidden-token p50/p90 estimates and confidence."""

        p50 = _nearest_rank(self.residual_samples, 0.50)
        p90 = max(p50, _nearest_rank(self.residual_samples, 0.90))
        if visible_started:
            confidence = "medium" if len(self.residual_samples) >= 5 else "low"
            return p50, p90, confidence

        # Before the first visible token, elapsed time mixes queueing, network
        # delay, and hidden decoding.  It is useful only as a low-confidence
        # progress signal, so never promote it to an exact lower bound.
        active_s = max(0.0, elapsed_s - self.queue_grace_s)
        progress = min(1.0, active_s / self.typical_first_text_s)
        hidden_p50 = round(p50 * progress)
        hidden_p90 = max(hidden_p50, round(p90 * min(1.0, progress * 1.50)))
        return hidden_p50, hidden_p90, "low"

    def observe(self, hidden_residual: int) -> None:
        _non_negative_int(hidden_residual, "hidden_residual")
        self.residual_samples.append(hidden_residual)
        if len(self.residual_samples) > self.max_samples:
            del self.residual_samples[: len(self.residual_samples) - self.max_samples]


@dataclass(frozen=True, slots=True)
class OutputEstimate:
    observed_tokens: int
    observed_source: str
    likely_p50_tokens: int
    likely_p90_tokens: int
    max_output_tokens: int | None
    confidence: str


@dataclass(slots=True)
class ProxyUsageMeter:
    """Reducer for the fields observable to a remote-API proxy."""

    model: str = "demo-remote-model"
    token_counter: TokenCounter | None = None
    token_counter_source: str | None = None
    calibrator: ResidualCalibrator = field(default_factory=ResidualCalibrator)

    response_id: str | None = None
    phase: str = "connecting"
    max_output_tokens: int | None = None
    preflight_input_tokens: int | None = None
    input_tokens: int | None = None
    cached_input_tokens: int | None = None
    final_usage: CompletedUsage | None = None
    completed: bool = False
    input_reconciled: bool = False
    last_sequence_number: int = -1
    last_event_elapsed_s: float | None = None
    last_delta_elapsed_s: float | None = None
    calibration_residual: int | None = None

    _counter_was_default: bool = field(init=False, repr=False)
    _text_parts: list[str] = field(default_factory=list, init=False, repr=False)
    _tool_parts: dict[str, list[str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _all_text_deltas_have_logprobs: bool = field(
        default=True, init=False, repr=False
    )
    _text_logprob_tokens: int = field(default=0, init=False, repr=False)
    _text_estimated_tokens: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        self._counter_was_default = self.token_counter is None
        if self.token_counter is None:
            self.token_counter, source = default_token_counter(self.model)
            self.token_counter_source = source
        elif self.token_counter_source is None:
            self.token_counter_source = "custom-tokenizer-est"

    def set_model(self, model: str) -> bool:
        """Update a default tokenizer when the provider model becomes known."""

        normalized = model.strip()
        if not normalized or normalized == self.model:
            return False
        self.model = normalized
        if self._counter_was_default:
            self.token_counter, self.token_counter_source = default_token_counter(
                normalized
            )
            if self._text_parts and not self._all_text_deltas_have_logprobs:
                self._text_estimated_tokens = self._count_text(self.text)
        return True

    @property
    def text(self) -> str:
        return "".join(self._text_parts)

    @property
    def visible_chars(self) -> int:
        return len(self.text)

    def _count_text(self, text: str) -> int:
        if self.token_counter is None:  # Defensive; __post_init__ installs one.
            raise ProxyUsageError("token counter is unavailable")
        count = self.token_counter(text)
        return _non_negative_int(count, "estimated token count")

    @property
    def text_tokens(self) -> int:
        if not self._text_parts:
            return 0
        if self._all_text_deltas_have_logprobs:
            return self._text_logprob_tokens
        return self._text_estimated_tokens

    @property
    def tool_argument_tokens(self) -> int:
        return sum(self._count_text("".join(parts)) for parts in self._tool_parts.values())

    @property
    def observed_output_tokens(self) -> int:
        return self.text_tokens + self.tool_argument_tokens

    @property
    def observed_source(self) -> str:
        if not self._text_parts and not self._tool_parts:
            return "none"
        counter_source = self.token_counter_source or "tokenizer-est"
        if self._tool_parts:
            return f"mixed/{counter_source}"
        if self._all_text_deltas_have_logprobs:
            return "logprobs-observed"
        return counter_source

    def set_exact_input_tokens(self, input_tokens: object) -> bool:
        """Apply an asynchronous provider input-token-count result."""

        count = _non_negative_int(input_tokens, "input_tokens")
        changed = self.preflight_input_tokens != count
        self.preflight_input_tokens = count
        if self.final_usage is None:
            self.input_tokens = count
        return changed

    def consume(
        self,
        event_name: str,
        data: Mapping[str, Any],
        *,
        elapsed_s: float = 0.0,
    ) -> bool:
        """Consume one documented-style Responses SSE event."""

        event_type = data.get("type")
        if event_type != event_name:
            raise ProxyUsageError("SSE event name and data.type must match")
        sequence_number = _non_negative_int(
            data.get("sequence_number"), "sequence_number"
        )
        if sequence_number <= self.last_sequence_number:
            return False
        self.last_sequence_number = sequence_number
        self.last_event_elapsed_s = elapsed_s

        if event_type == "response.created":
            response = data.get("response")
            if not isinstance(response, Mapping) or not response.get("id"):
                raise ProxyUsageError("response.created is missing response.id")
            self.response_id = str(response["id"])
            response_model = response.get("model")
            if isinstance(response_model, str) and response_model:
                self.set_model(response_model)
            maximum = response.get("max_output_tokens")
            if maximum is not None:
                self.max_output_tokens = _non_negative_int(
                    maximum, "max_output_tokens"
                )
            self.phase = "waiting_model"
            return True

        if event_type == "response.in_progress":
            self.phase = "waiting_model"
            return True

        if event_type == "response.output_text.delta":
            delta = data.get("delta")
            if not isinstance(delta, str):
                raise ProxyUsageError("output_text.delta is missing delta text")
            logprobs = data.get("logprobs")
            if not isinstance(logprobs, list) or (delta and not logprobs):
                self._all_text_deltas_have_logprobs = False
            elif any(not isinstance(item, Mapping) for item in logprobs):
                raise ProxyUsageError("delta.logprobs entries must be objects")
            if self._all_text_deltas_have_logprobs:
                self._text_logprob_tokens += len(logprobs)
            self._text_parts.append(delta)
            if not self._all_text_deltas_have_logprobs:
                # Re-tokenize the complete prefix.  Tokenizing each SSE chunk
                # independently over-counts tokens split across chunk edges.
                self._text_estimated_tokens = self._count_text(self.text)
            self.last_delta_elapsed_s = elapsed_s
            self.phase = "streaming"
            return True

        if event_type == "response.function_call_arguments.delta":
            delta = data.get("delta")
            item_id = data.get("item_id")
            if not isinstance(delta, str) or not isinstance(item_id, str):
                raise ProxyUsageError(
                    "function_call_arguments.delta requires item_id and delta"
                )
            self._tool_parts.setdefault(item_id, []).append(delta)
            self.last_delta_elapsed_s = elapsed_s
            self.phase = "streaming_tool"
            return True

        if event_type == "response.completed":
            response = data.get("response")
            if not isinstance(response, Mapping):
                raise ProxyUsageError("response.completed is missing response")
            if self.response_id is not None and response.get("id") != self.response_id:
                raise ProxyUsageError("completed response id does not match active response")
            usage = CompletedUsage.from_wire(response.get("usage"))
            if (
                self.preflight_input_tokens is not None
                and self.preflight_input_tokens != usage.input_tokens
            ):
                self.input_reconciled = True
            self.input_tokens = usage.input_tokens
            self.cached_input_tokens = usage.cached_input_tokens
            self.final_usage = usage
            observed = self.observed_output_tokens
            if usage.output_tokens >= observed:
                self.calibration_residual = usage.output_tokens - observed
                # Only logprob-backed visible text gives a clean residual.
                if self.observed_source == "logprobs-observed":
                    self.calibrator.observe(self.calibration_residual)
            self.completed = True
            self.phase = "completed"
            return True

        if event_type in {"response.failed", "response.incomplete"}:
            self.phase = "failed"
            return True

        return False

    def estimate_output(self, elapsed_s: float) -> OutputEstimate:
        if elapsed_s < 0:
            raise ValueError("elapsed_s cannot be negative")
        observed = self.observed_output_tokens
        if self.final_usage is not None:
            return OutputEstimate(
                observed_tokens=observed,
                observed_source="official-final",
                likely_p50_tokens=self.final_usage.output_tokens,
                likely_p90_tokens=self.final_usage.output_tokens,
                max_output_tokens=self.max_output_tokens,
                confidence="exact",
            )

        hidden_p50, hidden_p90, confidence = (
            self.calibrator.current_hidden_interval(
                elapsed_s=elapsed_s,
                visible_started=bool(self._text_parts or self._tool_parts),
            )
        )
        likely_p50 = observed + hidden_p50
        likely_p90 = max(likely_p50, observed + hidden_p90)
        if self.max_output_tokens is not None:
            effective_cap = max(observed, self.max_output_tokens)
            likely_p50 = min(effective_cap, likely_p50)
            likely_p90 = min(effective_cap, likely_p90)
        return OutputEstimate(
            observed_tokens=observed,
            observed_source=self.observed_source,
            likely_p50_tokens=likely_p50,
            likely_p90_tokens=likely_p90,
            max_output_tokens=self.max_output_tokens,
            confidence=confidence,
        )

    def status_key(self, elapsed_s: float) -> tuple[object, ...]:
        estimate = self.estimate_output(elapsed_s)
        return (
            self.phase,
            self.input_tokens,
            self.cached_input_tokens,
            estimate.observed_tokens,
            estimate.observed_source,
            estimate.likely_p50_tokens,
            estimate.likely_p90_tokens,
            estimate.confidence,
            self.completed,
        )

    def format_line(self, elapsed_s: float) -> str:
        if self.final_usage is not None:
            usage = self.final_usage
            return (
                f"{elapsed_s:5.2f}s  completed      "
                f"in {usage.input_tokens} (cached {usage.cached_input_tokens}) exact | "
                f"out {usage.output_tokens} (reason {usage.reasoning_tokens}) exact | "
                f"total {usage.total_tokens} | official exact/final"
            )

        input_label = (
            f"in {self.input_tokens} exact"
            if self.input_tokens is not None
            else "in - counting"
        )
        estimate = self.estimate_output(elapsed_s)
        cap = (
            f" | cap {estimate.max_output_tokens}"
            if estimate.max_output_tokens is not None
            else ""
        )
        if self.last_delta_elapsed_s is None:
            liveness = "no visible delta"
        else:
            age = max(0.0, elapsed_s - self.last_delta_elapsed_s)
            liveness = f"last delta {age:.2f}s ago"
        return (
            f"{elapsed_s:5.2f}s  {self.phase:<14} {input_label} | "
            f"out >= {estimate.observed_tokens} {estimate.observed_source} | "
            f"likely {estimate.likely_p50_tokens}-{estimate.likely_p90_tokens} "
            f"estimated incl hidden ({estimate.confidence}){cap} | {liveness}"
        )
