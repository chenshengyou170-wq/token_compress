# 统一 Token 压缩模块

`token_compression` 是应用入口，`codexscope` 保留现有算法和代理兼容接口。
从根目录和 `lingmou_compression/` 安装得到相同的两个 Python 包，无需启动灵眸产品。
每个会话或租户使用自己的 `TokenCompressor`、`SourceStore` 和缓存命名空间。

## 方法和来源

所有启用的材料方法先尝试已有的可还原结构压缩；有损候选必须连同来源标记一起更短，
整个请求也不得增长。表中的方法名称表示结构压缩后的候选策略，并非互相排斥的单一变换。

| 方法 / 能力 | 集成方式及来源 | 性质 |
| --- | --- | --- |
| `off` | 原请求基线 | 字节不变 |
| `structure` / `hybrid` | `codexscope.structural_compression`：JSON 表格、日志模板、重复引用、同工具同参数快照差量 | 解码验证；JSON 保留数值字面量、类型和顺序 |
| `caveman` | 现有 `compress_prose` 规则，新增条件保护和原文补读 | 有损、本地 |
| `extract` | 现有 `LexicalSelector` 和 `extract_source`，复制原文段落及相邻条件 | 有损、本地 |
| `jev` | 现有 `JevSelector`，批量 Noul 段落相关性判断 | 有损、远程；不确定时保留原文 |
| `kimi` | 现有 `KimiSelector`，选择段落 ID 后复制原文 | 有损、远程 |
| `llmlingua2` | 现有 `LLMLingua2Rewriter`，显式本地权重、标记保护 | 有损、本地模型 |
| `llm_rewrite` | 历史 Kimi 自由改写提示词，通过统一客户端与保护校验接入 | 有损、远程；不恢复旧版改写指令正文的行为 |
| `caveman_llm` | 读取 Caveman 的 `prompts/compression.txt`，使用统一客户端、JSON 输出和 usage 记录 | 有损、远程；按材料调用，不复刻旧脚本逐句请求与 embedding 评测 |
| `caveman_nlp` | 直接加载参考项目 `caveman_compress_nlp.py`，注入已安装的 spaCy 模型 | 有损、本地；受保护片段由程序复制 |
| `caveman_mlm` | 直接加载 `caveman_compress_mlm.py`，注入本地 RoBERTa 和 spaCy 模型 | 有损、本地；不会隐式下载权重 |
| `headroom` | 安装包 `ContentRouter` + Rust 原生核心，路由 JSON、日志、搜索、表格、配置和 HTML | 有损候选；原文由本模块 SourceStore 保存 |
| `generic_agent` | 依据 `GenericAgent/llmcore.py` 的首尾保留与历史窗口思路重新实现 | 显式材料标签裁剪；可选按完整用户轮次裁剪历史 |
| `auto` | `structure → extract`，结合补读反馈 | 本地；不会自动选择收费服务 |
| 工具懒加载 | 现有 `DeferredToolRegistry`，统一入口增加常驻工具集合和宿主能力开关 | 返回完整原始 schema，宿主负责加载和调用 |
| 前缀复用与缓存键 | 新会话前缀记录 + 现有 `with_prompt_cache_key`；参考 Headroom 前缀机制 | 只复用完全匹配的历史；缓存命中不计为 token 减少 |
| 原文补读与反馈 | 现有 `SourceStore` / MCP，统一会话记录补读 | 同一工具至少 5 次压缩且补读比例超过 50% 时只做结构压缩 |
| 完整任务计量 | 现有 `RequestUsageLedger` / `compare_tasks`，新适配器传递所有远程压缩调用 | 缺少任一官方 usage 时，净节省率为 null |

历史快照、旧脚本和参考项目中的同类方法按上表收敛到公共入口，保留来源以便对照。
GenericAgent 的外部长期记忆系统、Headroom 的完整代理和图像优化不属于本模块的文本输入压缩流程。
Headroom 的 Kompress、语义 embedding 下载和图像变换默认关闭；可通过 `backend=` 注入已配置的
ContentRouter 使用其其他策略。输出侧指令改写和 reasoning effort 调节没有作为输入 token 节省混入。

## API

```python
from token_compression import (
    CompressionConfig, TokenCompressor, SourceStore, CompressionTransport,
    decode_tool_result, with_prompt_cache_key, compare_tasks,
)

engine = TokenCompressor(CompressionConfig(method="extract"), source_store=SourceStore())
result = engine.compress_request(request_dict)  # 深拷贝，不修改调用方对象
wire_bytes, observation = engine.compress_bytes(request_bytes)
material_result = engine.compress_text(source_text, task="核对 B42 的退款条件")
original_lines = engine.read_source(result.source_ids[0], start_line=1, end_line=5)
```

`compress_text()` 返回一个含显式参考块的请求结果。`result.body` 是请求，`result.to_dict()`
包含统一指标：压缩前后本地 token、耗时、阶段、远程调用、问题原因、source ID、是否有损、
缓存命中和前缀复用数量。无来源时不要索引 `source_ids[0]`。
`compress_bytes()` 对无效、重复键、超大或不支持的 JSON 返回原字节和 `None`；
未发生变换时也保留原字节。字节入口的数值字面量在转发时不经浮点数重新格式化。

`CompressionConfig` 支持：

- `method`、`model`：算法与本地 tokenizer 选择；未知模型可能回退估算器，结果会注明。
- `model_path`、`rate`、`device`：LLMLingua-2 的本地目录、保留率和设备。
- `reference_path`、`spacy_model`、`mlm_model_path`、`language`：Caveman 参考源码及模型。
- `stable_prefix=True`：保存原始历史和转发历史。只有旧历史完整匹配且消息外字段未变时复用；编辑、分支、截短或工具 schema 改变都会失效。
- `adaptive=True`：使用补读反馈；`auto` 默认启用。反馈来自当前实例的 `read_source()`，独立 MCP 进程直接读磁盘不会自动回传反馈。
- `history_max_tokens`、`history_keep_turns`：可选历史窗口。保留开头系统/开发者消息和最近轮次；跨轮工具依赖无法安全处理时不裁剪。删除前展开本模块生成的差量依赖，旧轮次存入原文库，archive ID 由 `stages` 返回，宿主可据此展示或补读。
- `max_backend_calls=4`、`cache_entries=128`、`failure_backoff_s=300`：单请求候选调用上限、缓存容量和失败退避。

历史预算是目标而非强制截断：固定指令、保留轮次或展开后的结果可能超过预算。
`off` 不允许搭配历史裁剪或前缀变换。材料模式只处理工具结果和显式 `<lingmou-reference>` 块；
系统/开发者指令、当前任务、输出 schema、工具定义、调用参数及未知多模态块保持原值。

来源库有容量限制；达到配额、算法异常、占位符丢失、无收益或远程不可用时保留原文或较短的
可还原结构候选。`issues` 区分依赖不可用、后端失败、退避、反馈限流和完整请求未节省，
不会把回退伪装为该算法成功压缩。

## 工具与代理接入

```python
visible_tools, registry = engine.prepare_tools(
    full_definitions, resident=["read_file"], supports_tool_search=True,
)
loaded_output = registry.handle_search(tool_search_call)
# 宿主将 loaded_output 放回上下文，并执行随后被请求的已加载工具。

from codexscope.request_token_tap import RequestTokenTap
adapter = CompressionTransport(engine)
tap = RequestTokenTap(upstream_url, input_compressor=adapter).start()
# 使用完毕调用 tap.stop()。
```

`supports_tool_search` 默认 False，此时完整工具定义保持原样。宿主必须实际处理发现协议，
不能只删掉 schema。工具常驻、目录成本和重新加载成本应单独记录；不能重复计入材料压缩的节省。
`with_prompt_cache_key(request, namespace="tenant/run")` 显式设置稳定路由键，真实命中仍要读上游 usage。

独立 MCP 来源服务：

```bash
token-compress serve --store .compression_sources
token-compress read SOURCE_SHA256 --store .compression_sources --start-line 1 --end-line 20
```

代理兼容入口保留已有 request usage 账本结构；完整任务包括生成、补读、重试和远程压缩开销。
本地算法推理耗时不产生服务商 token usage，但不代表没有算力成本。

## 可选依赖

```bash
# LLMLingua-2 / Caveman MLM：CPU 环境示例
uv pip install --python .venv/bin/python -e '.[compression,nlp]' --torch-backend cpu
uv pip install --python .venv/bin/python -e '.[headroom]'
```

spaCy 需要另行安装相应语言模型。LLMLingua-2 和 RoBERTa 使用调用方给出的本地目录；
模型权重不进入 Git。本次精确版本和缓存 revision 见实验配置。
Python 构建缺少 `_sqlite3` 时使用 `pysqlite3-binary`；普通 Python 不需要该兼容替换。
仅安装基础包也能使用 `off/structure/caveman/extract/auto/generic_agent` 以及 HTTP 远程选择器。

Jev 使用 `TYPESAFE_API_KEY`；Kimi 使用 `KIMI_API_KEY`、`MOONSHOT_API_KEY` 或
`KIMI_API_KEY_FILE`。这些方法会发送当前任务和材料给所选服务。新模块复用现有客户端；
Jev 接口按 [TypeSafe API 文档](https://docs.typesafe.ai/api)核对。
若使用其他兼容客户端，可注入 `backend=RemoteRewriter(client=...)`；其返回值需包含文本、
finish reason 和归一化 usage，参见 `backends.py`。

## 实验复现

```bash
token-compress benchmark --out /tmp/compression-local-new --repeats 3 \
  --methods off structure caveman extract auto generic_agent headroom

token-compress benchmark --out /tmp/compression-models-new --repeats 2 \
  --methods off llmlingua2 caveman_nlp --cases reference_en reference_zh code \
  --model-path /path/to/llmlingua2 --reference-path reference_projects/caveman-compression

token-compress benchmark --out /tmp/compression-mlm-new --repeats 2 \
  --methods off caveman_mlm --cases prose_short \
  --mlm-model-path /path/to/roberta-base --reference-path reference_projects/caveman-compression

# 显式远程问答实验，使用环境中的 Kimi 凭据；包括 Jev / Kimi 压缩额外用量。
python -m token_compression.live_experiment --out /tmp/compression-live-new \
  --methods off structure caveman extract jev kimi llm_rewrite caveman_llm headroom \
  --cases reference_en reference_zh json_table --reference-path reference_projects/caveman-compression
```

输出目录必须为空，防止覆盖旧证据。基准输出 fixtures、每次实际请求、逐次 JSONL、汇总 CSV、
依赖版本及源码哈希。重复运行复用同一算法缓存，第一轮包含加载开销；不能用中位耗时冒充冷启动耗时。
远程问答保存所有尝试、真实答案和完整任务比较，来源补读使用明确的 JSON 宿主协议。

## 来源和许可

原有 794 个收录文件保持原字节，`verify_collection.py` 仍可核对。
GenericAgent 的窗口策略为本项目重写，原 MIT 许可位于
[`reference_projects/GenericAgent/LICENSE`](../reference_projects/GenericAgent/LICENSE)。
Headroom 通过可选依赖调用，参考源码的 Apache-2.0 LICENSE 和 NOTICE 留在子模块中。
Caveman NLP/MLM 从显式传入的源码目录加载，LLM 适配读取该目录提示词，不将第三方脚本复制进 wheel；
参考源码仍按其原有声明保留。安装包中的 Headroom 与参考 Git 提交有差异，本次证据同时记录发行版和
实际路由文件、原生扩展 SHA-256，不能将两者视为逐字同一实现。
