# Token 压缩模块

现在可以从仓库根目录安装，通过 `token_compression` Python API 或 `token-compress` CLI
使用统一模块。材料压缩、工具懒加载、原文补读、历史窗口、前缀复用和任务计量均有公共入口。
原有代码与历史证据继续保留；原灵眸产品目录不会自动同步。

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/token-compress methods
.venv/bin/token-compress compress request.json --method extract \
  --store .compression_sources --output compressed.json --report metrics.json
.venv/bin/python -m pytest -q
```

`request.json` 可以是 Responses 或 Chat Completions 请求。默认 `structure`；有损方法的 CLI
必须指定原文存储目录。API 支持内存或磁盘存储，可用 `read_source()` 按行补读。

```python
from pathlib import Path
from token_compression import CompressionConfig, SourceStore, TokenCompressor, reference_text

compressor = TokenCompressor(
    CompressionConfig(method="auto", stable_prefix=True),
    source_store=SourceStore(Path(".compression_sources")),
)
request = {
    "model": "gpt-4o",
    "input": "核对 B42 的退款条件。\n" + reference_text(source_text),
}
result = compressor.compress_request(request)
compressed_request = result.body
print(result.tokens_saved, result.issues)  # 本地估算；不等于官方用量或费用
```

方法包括 `off`、`structure`、`caveman`、`extract`、`jev`、`kimi`、`llmlingua2`、
`llm_rewrite`、`caveman_llm`、`caveman_nlp`、`caveman_mlm`、`headroom`、`generic_agent`、`auto`；
`hybrid` 是 `structure` 的兼容名称。可选依赖和模型只在选择对应方法时加载。

- [完整 API、依赖与方法来源](docs/UNIFIED_MODULE.md)
- [本次实验与结果](experiments/20261011_unified/REPORT.md)
- [统一模块源码](lingmou_compression/src/token_compression/)
- [当前与历史验证](VALIDATION.md)

下面保留原集合导航。2026-10-10 的收录说明、测试数量和模型环境均属于当时记录。

2026-10-10 整理。这里集中保存此前的输入压缩、工具懒加载、前缀缓存、实验记录和参考项目。
原有材料采用实际文件副本；新增 Headroom 以固定版本的 Git 子模块收录。
原灵眸运行目录继续使用原文件，两边不会自动同步。

| 入口 | 内容 |
| --- | --- |
| [工具懒加载说明](TOOL_LAZY_LOADING.md) | 已实现的工具目录、按需加载完整参数定义、调用及来源补读流程 |
| [lingmou_compression/](lingmou_compression/README.md) | 可单独运行本地测试、CLI 和示例的压缩代码包 |
| [v2 实现说明](lingmou_compression/doc/INPUT_COMPRESSION_V2.md) | 结构压缩、原文选段、LLMLingua-2、补读、完整任务计量 |
| [四轮实验记录](lingmou_compression/evidence/) | 10 月 8 日初版、请求代理接入、10 月 9 日多模型对比及 v2 验收 |
| [Caveman 源码](reference_projects/caveman-compression/README.md) | 自然语言简写参考项目；保留完整已跟踪文件 |
| [GenericAgent 源码](reference_projects/GenericAgent/README.md) | 上下文裁剪与记忆管理参考项目；保留完整已跟踪文件 |
| [Headroom 源码](reference_projects/headroom/README.md) · [源码评估](reference_projects/HEADROOM_REVIEW.md) | 按内容类型压缩、缓存前缀保护、CCR 补读与反馈、工具定义延迟加载；固定版本子模块 |
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

`hybrid` 是 `structure` 的兼容名称。材料压缩仅处理工具结果和显式参考块；
旧 `codexscope` 请求代理默认关闭，新的统一 API 默认使用 `structure`。
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
- 上述两个项目各自的普通目录和 `analysis` 目录内容一致，逐文件核对后只保留一份源码。
- Headroom 参考源码：`8c1beb20aeb8f0576095ae4893176ce16c2ede2a`，保留 LICENSE 和 NOTICE。新模块通过 `headroom-ai==0.40.0` 的原生包适配器运行；PyPI 包中的路由源码与该参考提交并非逐字相同，实验另记包版本及文件哈希。
- 模型权重仍位于本机 Hugging Face 缓存，位置见 LLMLingua-2 说明。安装依赖与下载权重不属于这次复制整理。
- 新增包配置、索引和验证文件用于独立运行；复制脚本中仅 `compare_prompt_compression.py` 的两个默认路径调整为集合内部位置，差异记在清单中。
- MCP 子进程测试显式传入副本的源码路径，避免 MCP 的环境过滤使子进程回落到原产品安装位置；测试断言保持不变。

校验原有 794 个复制文件（不遍历 Headroom 子模块）：

```bash
python3 verify_collection.py
```

已有集合检出后，初始化并核对 Headroom 固定版本：

```bash
git submodule update --init --depth 1 reference_projects/headroom
git submodule status reference_projects/headroom
```

子模块当前工作目录已完整拉取，浅克隆仅省略旧历史。不要用 `--remote` 作为上述
初始化命令的替代；它会选择上游新版本，偏离这次评估的提交。

本次整理记录的是已有实现和历史上游证据；新的本地验证另列于 `VALIDATION.md`。
