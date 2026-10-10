# Token 压缩与工具懒加载

2026-10-10 整理。这里集中保存此前的输入压缩、工具懒加载、前缀缓存、实验记录和参考项目。
采用实际文件副本；原灵眸运行目录继续使用原文件，两边不会自动同步。

| 入口 | 内容 |
| --- | --- |
| [工具懒加载说明](TOOL_LAZY_LOADING.md) | 已实现的工具目录、按需加载完整参数定义、调用及来源补读流程 |
| [lingmou_compression/](lingmou_compression/README.md) | 可单独运行本地测试、CLI 和示例的压缩代码包 |
| [v2 实现说明](lingmou_compression/doc/INPUT_COMPRESSION_V2.md) | 结构压缩、原文选段、LLMLingua-2、补读、完整任务计量 |
| [四轮实验记录](lingmou_compression/evidence/) | 10 月 8 日初版、请求代理接入、10 月 9 日多模型对比及 v2 验收 |
| [Caveman 源码](reference_projects/caveman-compression/README.md) | 自然语言简写参考项目；保留完整已跟踪文件 |
| [GenericAgent 源码](reference_projects/GenericAgent/README.md) | 上下文裁剪与记忆管理参考项目；保留完整已跟踪文件 |
| [LLMLingua-2 接入和模型记录](reference_projects/llmlingua2/README.md) | 本地模型适配器、历史环境和已有权重位置 |
| [v2 改造前源码快照](history/README.md) | 从临时目录保留下来的旧实现备份 |
| [产品接入快照](integration_snapshot/INTEGRATION.md) | 灵眸 monitor、CLI、依赖锁及原 README，供核对接入位置 |
| [整理验证](VALIDATION.md) | 本次文件校验、本地回归和模拟工具往返结果 |
| [来源清单](MANIFEST.json) | 每个复制文件的原路径、SHA-256、参考项目版本和去重记录 |

## 方法与代码

| 方法 | 实际实现 | 入口 |
| --- | --- | --- |
| 工具懒加载 / 按需绑定 | 先提供名称、简介；选中后返回完整原始参数 schema，再允许执行 | [deferred_tools.py](lingmou_compression/src/codexscope/deferred_tools.py)、[完整宿主示例](lingmou_compression/examples/context_compression_host.py) |
| 可还原结构压缩 | JSON 列名去重、日志模板、重复结果引用、快照差量；先解码校验，再比较长度 | [structural_compression.py](lingmou_compression/src/codexscope/structural_compression.py) |
| 按任务抽取原文 | 本地词项加权、Jev 相关性判断或 Kimi 段落编号选择；代码复制原文，支持按行补读 | [reference_selection.py](lingmou_compression/src/codexscope/reference_selection.py)、[context_tools.py](lingmou_compression/src/codexscope/context_tools.py) |
| LLMLingua-2 | 可选本地有损删词；保护代码、数字、字面量和识别到的条件 | [llmlingua_compression.py](lingmou_compression/src/codexscope/llmlingua_compression.py) |
| Caveman 规则 | 删除部分客套词、冠词和系词，缩短冗长表达；保留为旧方案对照 | [input_compression.py](lingmou_compression/src/codexscope/input_compression.py) |
| 前缀缓存 | 宿主显式生成稳定缓存键，保持稳定前缀；是否命中由官方 usage 确认 | [deferred_tools.py](lingmou_compression/src/codexscope/deferred_tools.py) |
| 完整任务计量 | 汇总所有生成、远程选段、补读和重试；缺失 usage 时不计算净节省 | [request_usage_ledger.py](lingmou_compression/src/codexscope/request_usage_ledger.py) |

当前 `hybrid` 是 `structure` 的兼容名称。新版仅处理工具结果和显式参考块，默认关闭。
工具懒加载减少需要发送的工具定义；前缀缓存可能减少重复计算，但不减少输入长度。

## 实验记录

| 原实验目录 | 说明 |
| --- | --- |
| [token_compression_20261008](lingmou_compression/evidence/token_compression_20261008/) | Caveman 提示词、GPT 压缩与英文/中文 A/B 记录 |
| [codex_input_compression_20261008](lingmou_compression/evidence/codex_input_compression_20261008/) | 请求边界本地规则压缩、工具往返记录 |
| [input_compression_20261009](lingmou_compression/evidence/input_compression_20261009/REPORT.md) | 旧 hybrid 和 Kimi 自由改写的多模型对照 |
| [context_compression_v2_20261009](lingmou_compression/evidence/context_compression_v2_20261009/REPORT.md) | 更严格材料边界、结构压缩、选段、补读、LLMLingua-2 和工具懒加载 |

历史文件按原字节保留，其中的时间、路径、模型及成功/失败记录不改写。
旧策略实验不能用当前 v2 行为解释。旧脚本使用当前代码运行时，也不等于复现了旧策略。
`media_token_task.py`、`proxy_usage.py` 和旧 usage helper 仅作为压缩代码的运行依赖收录；
独立多模态/隐藏 Token 统计调研的成果与验收仍由原工作区的 `PROJECT_MAP.md` 管理，不纳入本仓库。

## 文件与版本

- Caveman：`2a11efbf74863449e3392322ea0bf8d7ebe55357`。
- GenericAgent：`f308ee7eb079cc402edf5a934fa65f6d71a4c7ad`。
- 两个项目各自的普通目录和 `analysis` 目录内容一致，逐文件核对后只保留一份源码。
- 模型权重仍位于本机 Hugging Face 缓存，位置见 LLMLingua-2 说明。安装依赖与下载权重不属于这次复制整理。
- 新增包配置、索引和验证文件用于独立运行；复制脚本中仅 `compare_prompt_compression.py` 的两个默认路径调整为集合内部位置，差异记在清单中。
- MCP 子进程测试显式传入副本的源码路径，避免 MCP 的环境过滤使子进程回落到原产品安装位置；测试断言保持不变。

校验复制文件：

```bash
python3 verify_collection.py
```

本次整理记录的是已有实现和历史上游证据；新的本地验证另列于 `VALIDATION.md`。
