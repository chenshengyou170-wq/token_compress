# Headroom 源码评估

2026-10-10。结论：值得借鉴，优先考虑**稳定历史前缀、按补读反馈调整压缩、工具常驻与延迟加载的兼容判断**。这些能补充现有实现；本次完成源码收录和离线核对，尚未接入我们的压缩链路。

源码在 [headroom/](headroom/README.md)，上游为 [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom)。固定提交 [`8c1beb20aeb8f0576095ae4893176ce16c2ede2a`](https://github.com/headroomlabs-ai/headroom/tree/8c1beb20aeb8f0576095ae4893176ce16c2ede2a)，`pyproject.toml` 版本为 `0.40.0`。以浅克隆 Git 子模块保存 2,635 个已跟踪文件，上游 LICENSE（Apache-2.0）和 NOTICE 均保留。

| 优先级 | 可以借鉴的机制 | 当前集合已有能力 | 建议用途与边界 |
| --- | --- | --- | --- |
| P0 | 记录原始历史和实际转发历史；下一轮只处理新增内容，重放此前转发的压缩前缀 | 稳定 `prompt_cache_key`、指令/工具边界保护、压缩结果复用 | 增加按会话保存的前缀状态，减少重复压缩对缓存的干扰；缓存命中和费用仍需官方 usage 验证 |
| P0 | 记录每种工具的压缩次数、补读次数、全文补读比例，产生更保守的压缩提示 | 原文保存、按行补读、完整任务 usage 账本 | 补读频繁时保留更多材料，必要时停止有损压缩；不能把“未补读”直接当作回答正确 |
| P1 | 基础工具常驻，长尾工具延迟加载；检查客户端、模型和已有搜索机制 | `DeferredToolRegistry` 已有目录、精确加载原 schema、宿主工具往返 | 增加能力矩阵和常驻集合，减少常用工具的搜索往返；当前 Headroom 的 OpenAI 自动注入明确跳过 Codex |
| P1 | 根据 JSON、日志、搜索结果、代码、文本选择专用压缩器，先尝试无损结构变换 | JSON 列去重、日志模板、快照差量、原文选段、可选 LLMLingua-2 | 先补日志/搜索结果专用规则；行号、标识符、异常、数字及任务所需证据继续受保护 |
| P1 | 将材料压缩与工具定义节省分别归因，工具重新加载后扣回原先记账 | 官方 usage、远程选段、补读和重试的任务总账 | 增加分项解释，防止同一工具定义既计入结构压缩又计入延迟加载；本地估算不替代官方净收益 |

**历史前缀是最值得先做的小实验。** [prefix_tracker.py](headroom/headroom/cache/prefix_tracker.py) 的 `extract_cache_stable_delta()` / `overlay_cached_prefix()` 区分客户端原始内容和上轮真正发给模型的内容。假设第一轮把 2,000 行结果压成摘要，第二轮客户端又传入原始 2,000 行：应该复用上轮摘要的相同内容，避免重新选段后使前缀变化。历史被编辑、分支改变或消息不再对应时，需要停止复用，不能覆盖新内容。我们的 [with_prompt_cache_key()](../lingmou_compression/src/codexscope/deferred_tools.py) 主要生成稳定路由键，尚不包含这套历史重放机制。Headroom 的 `cache` / `token` 模式及冷前缀处理有不同策略，因此不能泛称它在所有设置下都不会改历史。

**补读机制我们已经有，反馈策略可以补上。** [compression_feedback.py](headroom/headroom/cache/compression_feedback.py) 按工具聚合事件，至少 5 次压缩后才给出建议；补读率大于 50% 时降低压缩强度，其中全文补读比例大于 80% 时建议跳过压缩。这些是源码中的启发式阈值，不是经本任务证明的最优参数。我们的 [SourceStore](../lingmou_compression/src/codexscope/reference_selection.py) 和 [source reader](../lingmou_compression/src/codexscope/context_tools.py) 已经能保留并按行读取原文，适合在现有账本上增加这类信号。

CCR（Compress–Cache–Retrieve）“可取回原文”也有存储边界：[compression_store.py](headroom/headroom/cache/compression_store.py) 的默认 TTL 常量为 1,800 秒，存在容量限制和淘汰机制；部署可以覆盖配置。因此可恢复性依赖原文仍在、检索工具可用、模型知道需要补读，不能等同于模型眼前的摘要没有信息损失。现有 SourceStore 的活动来源不自动淘汰，超配额则保留完整输入，这一边界值得保留。

**工具懒加载可以参考设计，Codex 接法需要另行验证。** [helpers.py](headroom/headroom/proxy/helpers.py) 的 `inject_tool_search_deferral_openai()` 默认工具数达到 12 才考虑注入，核心工具保持常驻，已有延迟加载机制时不重复插入。`_OPENAI_TOOL_SEARCH_UNSUPPORTED_CLIENTS` 明确包含 `codex` 和 `opencode`，并有 [对应测试](headroom/tests/test_openai_tool_search_deferral.py)。这是该版本 Headroom 对自己注入路径的限制，不代表 Codex 不具备任何工具懒加载能力。我们当前的 [DeferredToolRegistry](../lingmou_compression/src/codexscope/deferred_tools.py) 是宿主明确处理搜索和加载协议，继续沿用该入口更合适。模型名称的匹配规则只能当作该项目的实现，不能据此证明所有上游部署都支持同一协议。

**内容路由适合拆开借鉴。** [content_router.py](headroom/headroom/transforms/content_router.py) 按来源提示、混合内容、格式检测分流；JSON 数组交给 SmartCrusher，日志、搜索和代码另有策略。SmartCrusher 的默认路径先尝试表格紧凑表示，收益不足时可能走保留/删除行的有损策略，也提供 `lossless_only`。本提交的 [Python 配置](headroom/headroom/transforms/smart_crusher.py) 和 [Rust 配置](headroom/crates/headroom-core/src/transforms/smart_crusher/config.rs) 将 `lossless_min_savings_ratio` 设为 **0.15**，但 [说明文档](headroom/docs/content/docs/smart-crusher.mdx) 仍写 30%；参数应以该版本代码为准。这里衡量的是字节比例，也不能直接当作 token 比例。

**计账方式比首页百分比更有参考价值。** [tool_schema_savings_policy.py](headroom/headroom/proxy/tool_schema_savings_policy.py) 区分已经进入 token 前后差额的定义压缩与额外估算的延迟加载，`reconcile_deferred_tokens()` 还会在工具恢复常驻或 schema 缩短后降低原先的节省记录。我们的 [request_usage_ledger.py](../lingmou_compression/src/codexscope/request_usage_ledger.py) 已要求完整任务的官方 usage 才能算净收益，应保留该要求，并增加上述归因。最终应比较整个任务的输入、输出、缓存、补读、重试和压缩开销。

本次不建议直接迁入整套代理。它已经包含 Rust/PyO3 核心、多个供应商的转发协议、CCR 存储、可选 Kompress 模型及输出控制。`SmartCrusher` 的 Python 层依赖 `headroom._core`，不能只复制一个 `.py` 文件使用。输出控制还可能调整指令或 reasoning effort，应与输入材料压缩单独评测。首页和文档的节省率均属于上游自己的场景，本次没有复现为我们的任务收益。

本地验证结果如下；完整日志保留在 [validation/headroom_20261010/](../validation/headroom_20261010/)。

| 检查 | 实际结果 |
| --- | --- |
| 源码与版本 | 固定提交已拉取；子模块源码未修改 |
| 前缀跟踪与历史重放 | 上游两组测试共 98 项通过 |
| 补读反馈 | 20 项通过；1 项存储集成测试因当前 Python 缺少 `_sqlite3` 而失败 |
| 工具定义节省量计账 | 9 项通过；依赖供应商 tokenizer 的 1 项未选择执行 |
| OpenAI 工具搜索及客户端兼容 | 已核对源码；两份测试文件在导入阶段遇到同一 `_sqlite3` 缺失，未执行 |
| 完整原生压缩、模型质量、真实上游 usage | 未运行；当前环境没有 `headroom._core`，没有构建 Rust 扩展、下载模型或发起真实模型请求 |

因此本次是 **127 项离线断言通过、1 项环境相关失败、另有未执行范围**，不是全仓测试通过或真实上游验收。测试环境另提示缺少 `pytest-asyncio` 对应的 `asyncio_mode` 配置支持；本次选择的是同步测试。

后续最小对照可以先使用同一批多轮工具轨迹，比较现有方案、增加前缀重放、再增加补读反馈三个版本。先检查原文一致性、消息对应关系、工具往返及任务正确性，再比较完整任务的 usage 和耗时；缺少官方 usage 时仅报告离线变换结果。
