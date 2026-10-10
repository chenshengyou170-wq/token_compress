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

可在 Codex 组装好请求后、发往上游前压缩输入，并按请求关联本地估算与最终官方 usage。
借鉴 Caveman 的简写和 GenericAgent 的上下文整理，当前提供四种模式，默认关闭：

| 模式 | 行为 | 额外模型调用 |
|---|---|---|
| `off` | 只观测 | 无 |
| `caveman` | 原有本地简写规则，保留作为对照 | 无 |
| `hybrid` | 条件/字面量保护、本地简写、工具 JSON 空白整理、相同工具结果引用 | 无 |
| `kimi` | 在 hybrid 的结构整理基础上，尝试 Kimi 改写自然语言 | Kimi 官方 API |

使用已有 ChatGPT 登录时可显式开启：

```bash
# 终端一：启动带输入压缩的监控器
codexscope monitor -C /path/to/project \
  --request-token-tap-upstream https://chatgpt.com/backend-api/codex \
  --input-compression hybrid

# 终端二：连接 Codex TUI；也可沿用上面的 workbench 启动方式
codexscope attach
```

`hybrid` / `kimi` 处理 instructions、各角色文本及工具结果，支持 HTTP JSON
`POST /responses` 和 `POST /chat/completions`；原 `caveman` 仅支持 Responses。
工具定义、调用参数、ID、消息 phase、多模态和加密 reasoning 项保持原值。
识别到的代码、引号字面量、路径、URL、数值、表格、日志及条件句受保护。
工具 JSON 仅去除字符串外的空白，重复的长工具结果用明确的 tool call ID 引用保留项。
没有照搬 GenericAgent 的 FIFO 历史淘汰、记忆系统或长程 Agent 调度。

Kimi 模式需在仓库外设置 `KIMI_API_KEY` 或 `KIMI_API_KEY_FILE`，可选
`KIMI_BASE_URL`、`KIMI_COMPRESSION_MODEL`（默认 `kimi-for-coding`）。例如：

```bash
KIMI_API_KEY_FILE=/secure/path/kimi-key.txt codexscope monitor -C /path/to/project \
  --request-token-tap-upstream https://chatgpt.com/backend-api/codex \
  --input-compression kimi
```

启用 `kimi` 会将待改写文本发送到配置的 Kimi 服务；本地内存缓存保存最近的改写结果，
不写入磁盘。单次改写读取超时为 45 秒，每个请求最多尝试 4 次模型改写。
任务正文和工具结果优先于固定提示词；同一文本改写失败后退避 5 分钟，避免每轮重复等待。
解析失败、保护项丢失、超时、没有预计收益时保留原文；服务端历史引用、签名请求及
不支持的编码原样转发。保护检查不能证明任意文本语义等价，这仍是需要任务验证的实验功能。

`manifest.json` 的 `request_token_tap.input_compression` 记录累计压缩统计，
`request_token_tap.usage_ledger` 保存最近 200 条逐请求记录及累计官方计数，
同目录 `request_usage.jsonl` 保留完整的数值记录。这些记录不保存请求正文和认证头。
每条分别记录压缩前/后的完整请求估算、压缩状态、最终 input/output/total、可用的
cached/reasoning 数量和响应状态；未取得官方 usage 时明确为 `null`。
Kimi 压缩调用不计入这里的下游 usage，评测脚本另列其 usage。

本地 tiktoken 计数包含请求封装估算；不支持模型时使用标注的替代分词器或启发式估算。
Kimi 与 GPT-6 的 `o200k_base` 替代计数不是其官方分词器。最终官方 usage 是验收依据；
单次运行只能取得压缩后官方值，官方节省比例需另做相同任务的 off/on 对照。
输入 token 含缓存部分，压缩率不等同于费用或延迟改善，也不是运行中的官方精确计数。

真实对照脚本与证据：

```bash
.venv/bin/python scripts/verify_codex_input_compression.py --out /tmp/codex-compression-ab
.venv/bin/python scripts/verify_codex_input_compression.py --tool-probe-only --out /tmp/codex-compression-tool

# 四模型、三场景、三种模式，每组重复两次；会调用真实上游
KIMI_API_KEY_FILE=/secure/path/kimi-key.txt .venv/bin/python scripts/benchmark_input_compression.py \
  --out /tmp/lingmou-compression-ab --repeats 2
```

脚本会真实调用当前 Codex 登录的官方上游，默认模型为 `gpt-6-astra`，可用 `--model` 指定。
每次使用新的输出目录。首轮结果见
[官方 usage 对照](evidence/codex_input_compression_20261008/results.json)。
新脚本支持中断后使用同一目录续跑，已保存的请求（包括失败）不会被覆盖。
可用 `--models`、`--cases`、`--modes` 缩小范围；`--summarize-only` 只重新生成 JSON/CSV 表格。
多模型新结果见 [2026-10-09 评测记录](evidence/input_compression_20261009/REPORT.md)。

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
