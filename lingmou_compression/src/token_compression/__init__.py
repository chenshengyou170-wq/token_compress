"""Unified token compression API; optional algorithms load only when selected."""
from codexscope.compression_boundary import reference_text
from codexscope.context_tools import build_source_server
from codexscope.deferred_tools import DeferredToolRegistry, with_prompt_cache_key
from codexscope.reference_selection import SourceStore
from codexscope.request_usage_ledger import RequestUsageLedger, compare_tasks, summarize_task
from codexscope.structural_compression import decode_tool_result

from .engine import CompressionConfig, CompressionResult, TokenCompressor
from .methods import available_methods
from .transport import CompressionTransport

__all__ = [
    "CompressionConfig", "CompressionResult", "TokenCompressor", "SourceStore",
    "DeferredToolRegistry", "with_prompt_cache_key", "reference_text", "decode_tool_result",
    "build_source_server", "RequestUsageLedger", "compare_tasks", "summarize_task", "available_methods", "CompressionTransport",
]
__version__ = "0.2.0"
