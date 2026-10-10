# 灵眸输入压缩 v2：实现与验收

已实现需求文件中的结构压缩、可补读原文筛选、LLMLingua-2 对照、宿主工具按需加载、
更严格的材料边界，以及完整任务开销记录。默认关闭。改动位于灵眸产品目录，未回写共享仓库，未提交或发布。
使用方法见 [说明](../../doc/INPUT_COMPRESSION_V2.md)。

## 需求与证据

| 需求 | 当前实现 | 验证证据 |
|---|---|---|
| JSON 表格字段去重、日志模板/变量/次数、快照基准及变化 | `structural_compression.py`；保留类型、数字字面量、顺序；采用前先解码校验 | [本地测试](../../tests/test_compression_v2.py)、英文表格真实答题 |
| 按任务抽取原文，保留条件、例外及位置 | `reference_selection.py`；本地匹配、Jev、Kimi 三种选段器；模型仅决定段落编号 | 中文原枚举、布尔值、金额、审批条件的真实检查 |
| 漏选时补读 | 私有 SourceStore、`lingmou_source_read` stdio MCP；监控器自动注册 | 独立 MCP 进程测试、[真实补读结果](reread_final/reread.extract.json) |
| LLMLingua-2 独立模块对照 | 可选依赖、本地权重、保护标记、校验及回退；代码单元/字面量/条件不删词 | 真实 Microsoft 多语言模型推理及 [Codex 结果](llmlingua_codex/results.json) |
| 工具定义按需加载 | `DeferredToolRegistry` 提供目录、完整定义加载和 client tool search 应答；Codex 已有搜索保持原样 | [完整宿主例子](../../examples/context_compression_host.py)、[本地往返记录](host_demo.json)；实际 Codex 补读使用自身工具发现 |
| 指令、任务、输出格式、工具参数保持原样 | `compression_boundary.py`；只处理显式参考块及工具结果，包含 Codex custom tool output | Responses / Chat 两类载荷、各模式、数字/枚举/布尔/多模态/协议不变性测试 |
| 稳定前缀缓存 | 旧结果仅向前引用；宿主可显式生成稳定缓存键，保留现有键与定义顺序 | 缓存键和追加历史测试；usage 中缓存 detail 单列，不当作输入长度下降 |
| 整个任务累计官方 usage | 所有尝试及远程选段调用入账；按 Codex turn 或宿主 task_id 归组 | [usage 逐项核对](usage_audit.json)、[CLI 任务报告](task_report_cli.json) |
| 补读、重试、输出增长、压缩开销与任务正确性分别检查 | 补读/重试是下游调用子集；缺失值保持未知；单独的答案类型/枚举检查 | [汇总](acceptance_summary.json)；真实重试含缺失 usage 时净节省为 null |

## 本地与模拟验证

- 后端全量回归：**684 passed in 52.16s**，命令 `.venv/bin/python -m pytest tests -m 'not external' -q --disable-warnings`，见 [完整输出](pytest.txt)。
- 随后增加打包程序的补读 CLI 分支；该新用例及独立 stdio MCP 测试 **2 passed**。原 684 项和新增用例合计覆盖 685 项；未把它描述成又一次全量运行。
- `uv lock --check` 通过；monitor/context 帮助及 task report CLI 实际执行通过。
- 测试包括数值精度、false/字符串/null 区分、字段顺序、日志 CRLF、重复与差量复原、伪造标记、坏 JSON、补读来源完整性、配额、并发缓存、模型坏响应、完整任务漏计与签名/编码转发边界。
- 宿主 tool search 示例执行了“目录 → 完整参数定义 → 补读 → 回答”的本地往返。该独立宿主示例是模拟传输，官方 usage 保持 null；未声称通过了它的 OpenAI Platform 真实调用。

## 真实上游与本地模型

下游使用现有 ChatGPT 登录的 Codex 0.161.0、GPT-6 Astra。英文表格、中文审批约束、代码和实际补读均检查
JSON 字段集合、值及类型。Jev 使用实际 `jev-1.13.0`，Kimi 使用实际 `kimi-for-coding`，凭据从环境读取，未写入证据。

LLMLingua-2 使用 `microsoft/llmlingua-2-xlm-roberta-large-meetingbank`，revision
`ebaba9b0e874dadd3003ffcff828e4397e568089`，本地 CPU、保留率 0.6。权重位于仓库外的模型缓存。
依赖及模型记录见 [环境](llmlingua_environment.json)。中文场景实际发生一次本地模型调用；
代码场景优先使用可还原结构压缩，没有调用 LLMLingua 删代码，不能把它算作模型代码删词质量验收。

以下降幅按**完整任务的官方 input + output + 远程选段调用**计算；补读和重试不剔除。
全是合成材料，许多段落刻意冗余，只证明这些场景，不代表日常平均收益，也不等于费用下降。

| 场景及方案 | 下游官方 input：前 → 后 | 远程选段额外 token | 官方总 token 净降幅 | 答案 |
|---|---:|---:|---:|---|
| 英文 JSON 表格 / structure | 22,067 → 18,505 | 0 | 16.12% | 两侧通过 |
| 中文材料 / 本地 extract | 19,959 → 17,058 | 0 | 14.51% | 两侧通过 |
| 代码参考 / structure | 18,555 → 17,117 | 0 | 7.74% | 两侧通过 |
| 补读往返 / extract，修复只读声明后的对照 | 60,796 → 52,036 | 0 | 14.39% | 两侧通过，均 3 请求 |
| 补读往返 / extract，加入最终请求分类后的复测 | 60,796 → 已知 52,068 | 0 | **不可计算** | 两侧通过；压缩侧 4 请求，其中 1 次缺少 usage |
| 中文材料 / LLMLingua-2 | 19,971 → 18,403 | 0（本地推理） | 7.84% | 两侧通过 |
| 中文材料 / Jev 选段 | 19,968 → 17,067 | 6,498 | **−17.99%** | 两侧通过 |
| 中文材料 / Kimi 选段 | 19,968 → 17,067 | 4,570 | **−8.35%** | 两侧通过 |

Jev/Kimi 在这个单次任务上虽然减少了下游输入，但加入选段调用后，官方总 token 增加。
因此默认推荐先使用无需模型调用的 `structure` 或本地 `extract`，不能仅按下游输入宣称远程选段省资源。
缓存复用后的收益需要独立的多轮任务对照，不能从本表推导。

以上数字和每条请求分别保存在 [汇总 JSON](acceptance_summary.json)、各子目录 `results.json`、
`*.usage.jsonl` 及 `*.json` 中。输出增长在机器报告中单列；有完整 usage 的调用组，
代理汇总的 input/output/total 与 Codex `turn.completed` 相符，见 [核对记录](usage_audit.json)。

## 失败与修复保留

1. 首轮 `codex/table_en.off.json` 有一次重试缺少 usage：原样保留，该组未给净降幅。之后新目录的完整对照另列，不覆盖旧记录。
2. 首轮补读工具遗漏 MCP 只读声明，Codex 在 `approval_policy=never` 下拒绝调用。增加真实只读/非破坏/封闭来源声明后，补读返回原始第 38 行，答案检查通过。原始失败仍在 `codex/reread.*.json`。
3. Codex 实际通过 `custom_tool_call` 的 exec 执行 MCP。补齐该输出类型的压缩支持和补读分类，并明确代码表达式分类属于推断；工具目录搜索不当成补读。
4. 最终 `reread_final` 的压缩侧又出现一次上游重试，其 usage 不可得。新账本记录补读 2 次、其中推断重试 1 次，总量未知，净节省保持 null。答案通过没有覆盖这个计量限制。

## 适用边界

- 代码实现、模拟协议验证和真实答题已分别列出；没有以模拟 usage 充当官方数据。
- 有损选段和 LLMLingua 不能保证任意材料语义等价，补读入口、保守条件保留和任务验收仍有必要。
- 原生 client tool search 的独立宿主适配器已通过本地协议往返；当前产品使用 Codex 已有的真实工具发现，没有另行要求付费 OpenAI Platform key 验收。
- 当前真实上游没有返回的失败调用 usage 无法补造；它会阻止净节省声明，不阻断生成。
- 本次未部署、提交或合并。最终实现指纹见 [SHA-256 清单](implementation_sha256.json)。
