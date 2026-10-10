# 工具懒加载 / 按需绑定

此前已实现这套机制，核心类是
[`DeferredToolRegistry`](lingmou_compression/src/codexscope/deferred_tools.py)。
它位于宿主调用流程中，负责根据模型选择提供工具定义。

## 调用流程

1. 宿主注册可信工具及其完整参数定义。
2. `catalog()` 生成只有名称和简介的目录；`responses_tools()` 生成 client `tool_search` 定义。
3. 模型返回带工具名称的 `tool_search_call`。
4. `handle_search()` 校验名称，通过 `load()` 取出完整原始 schema，返回对应 `call_id` 的 `tool_search_output`，工具带 `defer_loading: true`。
5. 宿主把返回结果加入上下文，处理后续工具调用。示例只执行已经加载的工具。

目录及搜索工具本身仍占用输入 token。收益取决于工具数量、参数定义长度和实际需要的工具；
现有模拟示例没有给出通用节省率。

```python
from codexscope.deferred_tools import DeferredToolRegistry

registry = DeferredToolRegistry(trusted_tool_definitions)
initial_tools = registry.responses_tools()
# 模型返回搜索调用后：
search_output = registry.handle_search(tool_search_call)
# 宿主将 search_output 加入后续上下文，并执行已加载工具。
```

完整的“发现工具 → 加载定义 → 按行补读 → 回答”流程见
[context_compression_host.py](lingmou_compression/examples/context_compression_host.py)。
默认使用本地模拟传输，usage 为未知；加 `--live` 才会调用外部接口。

## 与压缩代理的关系

- `DeferredToolRegistry` 是显式宿主接口；压缩代理不会自动删除工具定义或注入搜索工具。
- 原灵眸监控器保留 Codex 自带的工具发现行为；独立宿主示例用于展示这套接口。
- `lingmou_source_read` 是原文补读工具，完整参数定义由 `context_tools.py` 提供。
- `with_prompt_cache_key()` 是同文件中的另一项优化：稳定缓存路由键，不等同于输入长度压缩。

## 验证证据

| 层次 | 已有证据 |
| --- | --- |
| 代码实现 | 目录、加载、原始 schema 保留、已有 tool search 保留、未知名称拒绝 |
| 本地/模拟 | [测试](lingmou_compression/tests/test_compression_v2.py)及[历史宿主往返记录](lingmou_compression/evidence/context_compression_v2_20261009/host_demo.json) |
| 历史真实上游 | Codex 使用自身工具发现完成来源补读，见 [v2 报告](lingmou_compression/evidence/context_compression_v2_20261009/REPORT.md) |
| 本次整理验证 | 见 [VALIDATION.md](VALIDATION.md)；不把模拟往返当作独立宿主适配器的真实上游验收 |

独立宿主适配器没有另外完成付费 OpenAI Platform 验收；该项不是本项目的新增阻塞要求。
