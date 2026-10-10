# 灵眸 Token 压缩代码包

这是从当前灵眸源码抽出的可运行副本，包含压缩、工具懒加载、来源补读、请求代理和计量的完整本地模块依赖。
Python 包名仍为 `codexscope`。安装时使用独立虚拟环境；原产品从原目录运行，两份源码不自动同步。

## 使用当前工作区环境

从本目录执行，`PYTHONPATH` 指向这里的副本代码：

```bash
PYTHONPATH="$PWD/src" ../../.venv/bin/python -m pytest tests -q
PYTHONPATH="$PWD/src" ../../.venv/bin/python examples/context_compression_host.py --store /tmp/token-compression-host-sources
PYTHONPATH="$PWD/src" ../../.venv/bin/python scripts/evaluate_context_compression.py --provider local --out /tmp/token-compression-local-evaluation
PYTHONPATH="$PWD/src" ../../.venv/bin/python -m codexscope.context_tools --help
```

这些默认命令执行本地检查和模拟，不发起远程模型调用。
选用 `jev`、`kimi`、`--provider codex` 或示例的 `--live` 时才涉及相应远程服务。

## 单独安装

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test,proxy]'
.venv/bin/python -m pytest tests -q
.venv/bin/codexscope-context --help
```

`codexscope-context` 直接对应原 `codexscope context` 子命令，支持 `compress`、`read`、`serve`、`report`。
此包提供压缩功能；完整 monitor 和产品界面仍由原灵眸项目运行。
LLMLingua-2 的额外依赖及本地权重见 [模型说明](../reference_projects/llmlingua2/README.md)。

## 代码入口

| 文件 | 作用 |
| --- | --- |
| [context_compression.py](src/codexscope/context_compression.py) | 模式选择、结构压缩优先、保护与回退、选段缓存 |
| [deferred_tools.py](src/codexscope/deferred_tools.py) | 工具懒加载及稳定前缀缓存键 |
| [structural_compression.py](src/codexscope/structural_compression.py) | JSON、日志、重复结果和快照差量 |
| [reference_selection.py](src/codexscope/reference_selection.py) | 本地/Jev/Kimi 选段及完整原文存储 |
| [context_tools.py](src/codexscope/context_tools.py) | CLI、MCP 原文补读 |
| [request_token_tap.py](src/codexscope/request_token_tap.py) | 转发前压缩、本地估算与官方 usage 捕获 |
| [request_usage_ledger.py](src/codexscope/request_usage_ledger.py) | 整个任务的开销、重试、补读和净节省核算 |

完整行为见 [v2 说明](doc/INPUT_COMPRESSION_V2.md)，工具机制见 [懒加载说明](../TOOL_LAZY_LOADING.md)。
v2 说明中的 monitor 命令属于原产品；在本代码包中使用上面的独立 CLI。

## 脚本与历史结果

- `scripts/evaluate_context_compression.py`：当前 v2 的本地或 Codex 对照入口。
- `examples/context_compression_host.py`：工具发现、补读和回答的宿主示例。
- `scripts/compare_prompt_compression.py`：早期 Caveman 提示词实验；默认参考源码和 usage helper 已改成集合内部路径。
- 其他 `benchmark_*`、`verify_*`、`report_*` 脚本随原记录保留。历史脚本使用当前模块时，行为以当前实现为准。
- `doc/BANK_RECONCILIATION_SCENARIO.md` 是早期实验读取的合成材料；文中产品操作路径保留原样。
- `scripts/legacy_codex_usage_probe.py` 是早期实验动态加载的原 helper 副本，只作为历史依赖保留。
- `evidence/` 保留四轮原始实验；新的运行结果请输出到新目录，避免覆盖历史记录。

## Codex 输入侧压缩（实验功能）

压缩默认关闭；模式、保护边界及历史验收见 [INPUT_COMPRESSION_V2.md](doc/INPUT_COMPRESSION_V2.md)。
`hybrid` 现在只对应可还原的 `structure`；旧报告中的 hybrid/Kimi 自由改写属于旧实现。
压缩前后本地估算、完成后的官方 usage 和模型选段额外开销分别记录。
