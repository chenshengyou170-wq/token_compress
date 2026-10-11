# 集合整理验证

## 2026-10-11 统一模块

根目录现在可直接安装 `lingmou-token-compression 0.2.0`，提供统一 API、CLI、
14 个方法入口、工具懒加载、来源补读、会话前缀和历史窗口。旧验证记录保留在下文。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 当前完整回归 | **139 passed**（原 106 项 + 新增 33 项） | [pytest.txt](validation/unified_20261011/pytest.txt) |
| 本地基准 | 当前代码 210 次，另 22 次本地模型对照；输出哈希、长度、关键证据与来源一致性通过 | [实验报告](experiments/20261011_unified/REPORT.md) |
| 真实远程问答 | 修正单位后的 30/30 通过；27 项官方完整任务比较已重算；初轮失败保留 | [任务比较](experiments/20261011_unified/final/live/results.json) |
| 打包和独立安装 | wheel 成功；在仓库外新环境安装、压缩和补读通过；打包源码与当前文件相同 | [构建日志](validation/unified_20261011/wheel-build.txt)、[审计](validation/unified_20261011/audit.json) |
| 依赖与静态检查 | `uv pip check`、Ruff F 规则及 `git diff --check` 通过 | [依赖快照](validation/unified_20261011/environment.txt) |
| 历史文件 | 原 794 个复制文件的 SHA-256 全部保持一致 | `python3 verify_collection.py` |

本地估算、实际模型推理和官方 usage 分别记录。远程实验使用合成材料及 JSON 补读宿主协议，
未证明真实 Codex 客户端的自动工具搜索、生产流量收益或供应商缓存命中。
Headroom 的旧参考源码评估与新原生包实验属于不同证据，详细版本差异见实验报告。

## 2026-10-10 集合整理

日期：2026-10-10。这里记录本次复制整理的检查，历史真实上游结果仍以各实验目录为准。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 已收录文件完整性 | 794 个文件，42,163,476 字节；全部与清单中的 SHA-256 一致 | [file_integrity.json](validation/file_integrity.json)、[MANIFEST.json](MANIFEST.json) |
| 原始文件保留 | 原代码、实验及参考源码保持原样；原产品 README 仅增加集合导航 | [source_preservation.json](validation/source_preservation.json) |
| 副本模块依赖 | 14 个模块均从集合自己的 `src` 导入；语法、包元数据和 CLI 入口通过检查 | [module_audit.json](validation/module_audit.json) |
| 现有本地回归 | **106 passed in 9.58s** | [pytest.txt](validation/pytest.txt) |
| 工具懒加载和补读 | 模拟传输完成 `load → reread → answer`；补读第二行原文，内容一致 | [host_demo.json](validation/host_demo.json) |
| 本地压缩对照 | 4 个场景 × off/structure/extract，共 12 组；保护指令均保持一致 | [local/](validation/local/)、[执行输出](validation/local_evaluation.txt) |
| 历史脚本输入 | 英文 API 与中文银行材料都可从集合内部读取 | [module_audit.json](validation/module_audit.json) |
| 独立 CLI | `compress/read/serve/report` 帮助和入口核对通过 | [context_cli_help.txt](validation/context_cli_help.txt) |

## 测试执行

从 `lingmou_compression/` 执行：

```bash
PYTHONPATH="$PWD/src" PYTHONDONTWRITEBYTECODE=1 ../../.venv/bin/python \
  -m pytest tests -q -p no:cacheprovider
```

测试使用现有虚拟环境中的依赖，但导入集合副本的代码。MCP 子进程测试显式传入集合的 `src` 路径，
避免 SDK 的默认环境过滤丢弃 `PYTHONPATH` 后导入原产品代码。
此次没有重新安装依赖或构建发行 wheel。

最初在受限沙箱内执行时，14 个回环 socket 测试被 `Operation not permitted` 拒绝，
91 项通过，另 1 项 stdio MCP 检查被单独诊断并超时。
随后获准在沙箱外运行同一组本地检查，106 项全部通过。
原诊断日志保留在 [pytest_without_stdio.txt](validation/pytest_without_stdio.txt) 和
[mcp_diagnostic.txt](validation/mcp_diagnostic.txt)。

## 内容调整

生产算法代码、历史 evidence 和参考项目源码没有改写。副本中两处与目录迁移有关的调整是：

1. `compare_prompt_compression.py` 的参考仓库、旧 usage helper 两个默认路径指向集合内部。
2. `test_compression_v2.py` 的 MCP 子进程显式使用副本源码；既有断言不变。

清单同时保留调整前的来源 SHA-256 和调整后的副本 SHA-256。
原产品只增加 README 导航；独立包配置、说明和校验器是本次新增。

## 验收范围

- 本次完成文件整理、本地回归和模拟工具往返，没有发起新的付费或真实上游模型调用。
- 本地对照只检查变换和协议边界，官方 usage 和真实答题质量保持未知。
- 历史真实 Codex、Jev、Kimi 和 LLMLingua-2 结果按原记录保留，不能当作本次重新验收。
- LLMLingua-2 权重继续使用仓库外的既有缓存；本次不重新推理，当前产品虚拟环境也未安装其可选依赖。
- 集合与原运行代码是两个副本，后续修改需要明确选择位置；本节记录整理验证，提交和推送状态以 Git 仓库为准。

## Headroom 追加收录

2026-10-10 拉取 `reference_projects/headroom` 子模块，固定在
`8c1beb20aeb8f0576095ae4893176ce16c2ede2a`，原有 794 个复制文件未变。
来源、比较结论及范围见 [源码评估](reference_projects/HEADROOM_REVIEW.md)。

使用现有 Python 3.11 环境运行上游同步测试：前缀跟踪、前缀重放、补读反馈与工具定义
计账共 **127 passed、1 failed、1 deselected**。失败原因是当前 Python 缺少 `_sqlite3`；
工具搜索的两份测试也因该依赖缺失在收集阶段退出。当前没有 `headroom._core`，
本次没有运行原生压缩或真实上游请求，也没有将 Headroom 接入原产品。

- [通过及失败的完整输出](validation/headroom_20261010/offline-tests.log)
- [执行命令与环境覆盖项](validation/headroom_20261010/offline-tests.json)
- [最初工具搜索测试的收集错误](validation/headroom_20261010/upstream-tests.log)
- [源码版本与环境记录](validation/headroom_20261010/source.json)

上述结果独立于前述集合自身的 106 项回归，不合并为同一套测试通过率。
