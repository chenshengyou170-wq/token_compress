"""Compatibility with the existing RequestTokenTap proxy and usage ledger."""
from codexscope.input_compression import CompressionObservation, ResponsesInputCompressor


class CompressionTransport(ResponsesInputCompressor):
    supports_chat_completions = True

    def __init__(self, engine, *, on_observation=None):
        super().__init__(token_counter=engine.count, on_observation=on_observation)
        self.engine = engine
        self._stats["mode"] = engine.config.method

    def _compress(self, raw):
        output, result = self.engine.compress_bytes(raw)
        if result is None:
            return raw, CompressionObservation("skipped", "invalid_or_unsupported_input")
        changed = output != raw
        return output, CompressionObservation(
            status="compressed" if changed else "skipped",
            reason=",".join(result.issues) or ("unified_pipeline" if changed else "no_savings"),
            tokenizer_source=result.tokenizer,
            full_request_tokens_before_estimate=result.tokens_before,
            full_request_tokens_after_estimate=result.tokens_after,
            compression_model_calls=len(result.calls), compression_calls=tuple(result.calls),
            local_model_calls=result.backend_attempts if result.method in {"llmlingua2", "caveman_mlm"} else 0,
            cache_hits=result.cache_hits, lossy_fields=int(result.lossy),
            changed_fields=result.changed_fields, changed_roles=tuple(result.changed_roles),
        )
