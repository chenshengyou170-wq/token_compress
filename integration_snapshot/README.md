# 灵眸（Lingmou）

灵眸的独立产品代码目录，包含 Agent 运行观测、跨层证据、风险策略、有限阻断、
调查回放、React 工作台和 Electron 桌面端。

2026-10-01 从当前工作区整理，包含原仓库已有的未提交修改。采用复制整理，
原 `../codexscope/` 及其他原始目录保留。此目录包含实际源码，不依赖指向原仓库
的软链接；Python 包名和命令仍为 `codexscope`，避免破坏既有接口。

## 目录

| 路径 | 内容 |
|---|---|
| `src/codexscope/` | Python 后端、采集、策略、阻断、回放、运行时插桩及页面资源 |
| `web/` | React + TypeScript 工作台源代码及依赖锁文件 |
| `desktop/` | Electron 桌面端、启动器及打包脚本 |
| `demo/` | 安全演示，以及从工作区汇入的普通业务与观测演示 |
| `examples/policies/` | 自定义策略示例 |
| `tests/`、`test/` | 自动化测试、测试夹具及运行时演示源码 |
| `scripts/`、`config/`、`deploy/` | 启动、调查回放、配置及部署模板 |
| `doc/` | 灵眸功能、使用与验收文档 |
| `evidence/` | 目录访问、自然语言策略及工作台的历史验收证据 |
| `presentation/` | 产品事实包、截图；根目录原有 BP 材料收于 `workspace_materials/` |
| `ORGANIZATION_MANIFEST.json` | 每个整理文件的原路径、目标路径与校验值 |
| `README_CODEXSCOPE.md` | 原共享仓库的完整说明，含未纳入本目录的研究功能 |

## 安装与启动

需要 Python 3.11+；开发前端还需要满足 `web/package-lock.json` 要求的 Node.js。
从本目录执行：

```bash
uv sync --locked --extra test
source .venv/bin/activate
codexscope --help
```

已包含工作台生产静态资源。使用已经安装、登录的 Codex 启动受观测会话：

```bash
# 终端一：将 /path/to/project 换成要观测的项目
codexscope monitor -C /path/to/project

# 终端二：仍在 lingmou 目录，并激活本目录虚拟环境
codexscope workbench --open-browser
```

工作台默认地址为 `http://127.0.0.1:8766`。完整参数和策略配置见
[工作台说明](doc/LINGMOU_WORKBENCH.md)及[原子策略说明](doc/LINGMOU_ATOMIC_POLICIES.md)。
网络、文件等 34 项可组合元策略见[元策略库](doc/LINGMOU_META_POLICIES.md)，可在策略中心选择条件、试算并保存。
Jev 语义条件、第二模型复核接口及逐节点解释树见[语义策略说明](doc/LINGMOU_SEMANTIC_POLICY.md)。
普通业务网络场景见[发布前依赖版本核对](demo/network-dependency-review/README.md)：查询真实上游资料，按批准域名限制网络访问，并在报告中列明无法核验的依赖。
银行综合场景见[日终对账与支付渠道排障](doc/BANK_RECONCILIATION_SCENARIO.md)，包含合成数据、组合策略、业务提示词和真实 Jev 审批试算验收。
一键演示可运行 `scripts/restart_lingmou_clean.sh --help` 查看选项，新的演示工作区
保存到本目录 `runs/clean/`。该脚本启动时会重启同名灵眸专用 tmux 会话。

前端开发与验证：

```bash
cd web
npm ci
npm test
npm run build
```

后端和桌面启动器验证（从本目录执行）：

```bash
.venv/bin/python -m pytest tests -m 'not external'
npm --prefix desktop test
```

桌面应用安装、开发与打包见 [desktop/README.md](desktop/README.md)。

## Codex 输入侧压缩（实验功能）

默认关闭。新版只处理工具结果和显式标记的参考材料；系统/开发者指令、任务正文、
输出格式、工具定义与调用参数保持原值。`hybrid` 现在是 `structure` 的兼容名称。

| 模式 | 行为 |
|---|---|
| `off` | 只观测 |
| `structure` / `hybrid` | 可还原的 JSON 表格、日志模板、重复结果及快照差量；不调用模型 |
| `extract` | 结构压缩后，按当前任务做本地原文选段，保留来源位置及补读入口 |
| `jev` / `kimi` | 分别用 TypeSafe / Kimi 选择原文段落编号，程序复制原文 |
| `llmlingua2` | 可选的本地 LLMLingua-2 有损对照，保护代码、字面量和识别到的条件 |
| `caveman` | 旧简写规则对照，也遵守新的材料边界 |

```bash
codexscope monitor -C /path/to/project \
  --request-token-tap-upstream https://chatgpt.com/backend-api/codex \
  --input-compression structure
# 另一终端：codexscope attach
```

选段模式会自动注册 `lingmou_source_read` MCP 工具，原文存于本次运行的私有
`compression_sources/`，便于按行补读。Jev 使用仓库外的 `TYPESAFE_API_KEY`；
Kimi 使用 `KIMI_API_KEY` 或 `KIMI_API_KEY_FILE`。这两种模式会将待选材料及当前任务
发送给相应服务。LLMLingua-2 需要可选依赖及事先下载的本地权重，不自动下载模型。
失败、无法补读或没有预计收益时保留原文。

完整用法、工具按需加载接口、缓存键及逐任务开销统计见
[新版压缩说明](doc/INPUT_COMPRESSION_V2.md)。
本次验证见 [实现与验收记录](evidence/context_compression_v2_20261009/REPORT.md)。
旧版历史结果保留在 [2026-10-09 原实验](evidence/input_compression_20261009/REPORT.md)，
它使用旧压缩边界，不代表新版行为。

`request_usage.jsonl` 记录完整请求的压缩前/后**本地估算**及最终**官方 usage**。
任务汇总包括所有上游尝试和远程选段开销，另列补读、重试、输出增长、缓存命中及未知 usage。
Codex 有 turn 元数据时按 turn 归组；否则标为整次运行，宿主也可显式指定 task_id。
重复请求识别出的重试会注明是推断。缺少任一调用的官方 usage 时，不报告净节省率。
缓存命中不等于输入长度减少，token 降幅也不等于费用或延迟改善。

## 整理边界

- 保留 `usage.py`、`proxy_usage.py`、`request_token_tap.py`、`media_token_task.py`：
  当前监控器和实时页面直接依赖这些模块，它们在此作为产品运行依赖。
- `live_status_scenario.py`、`usage_stream_demo.py` 及对应测试作为监控和 usage
  回归测试依赖保留，不作为灵眸新增产品能力或研究验收结果。
- 独立的隐藏 Token 估计器、PALACE/BB-PLP 训练评测、论文、
  调研报告与评测证据继续留在原位置，未混入灵眸产品目录。
- `codex/` 是可选的外部 Codex 源码工程，`AgentGuard/`、`AI-Infra-Guard/`、
  `agent-insight/` 等是独立项目；未作为灵眸源码复制。
- 原 Git 历史、虚拟环境、依赖目录、缓存和大体积历史运行日志没有复制。
  `../lingmou-clean-runs/` 与 `../codexscope/evidence/lingmou_workbuddy/runs/`
  的历史记录仍在原位置。
- 历史证据与 BP 中的时间、原路径和结果保持原样；它们不代表本次整理后的重新验收。
  操作说明、部署模板及新运行输出路径已调整到本目录。
- 原目录与本目录后续不会自动同步。灵眸产品开发使用本目录，避免两边交叉修改。

整理后的本地验证结果见 [VALIDATION.md](VALIDATION.md)。
