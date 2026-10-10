"""Minimal authenticated Codex probe shared by the Lingmou benchmarks."""
import json

from codexscope.compression_models import normalize_usage
from codexscope.request_token_tap import RequestTokenTap

_UPSTREAM = 'https://chatgpt.com/backend-api/codex'
_PROVIDER_ID = 'lingmou_compression_probe'


def _provider_arguments(local_base_url: str, codex_version: str) -> list[str]:
    provider = (f'model_providers.{_PROVIDER_ID}={{name="OpenAI",'
                f'base_url={json.dumps(local_base_url)},wire_api="responses",'
                f'http_headers={{version={json.dumps(codex_version)}}},'
                'requires_openai_auth=true,supports_websockets=false,'
                'supports_standalone_web_search=false}')
    return ['-c', f'model_provider={json.dumps(_PROVIDER_ID)}', '-c', provider,
            '-c', 'features.enable_request_compression=false', '-c', 'approval_policy="never"']


def _usage_from_codex_jsonl(value: str) -> dict | None:
    result = None
    for line in value.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get('type') == 'turn.completed':
            usage = event.get('usage')
            result = normalize_usage(usage)
            if result and isinstance(usage, dict):
                for key in ('cached_input_tokens', 'reasoning_output_tokens'):
                    if type(usage.get(key)) is int and usage[key] >= 0:
                        result[key] = usage[key]
    return result
