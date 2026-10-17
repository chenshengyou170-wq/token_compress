# Full 压缩后端接入

2026-10-12 重接。入口仍是 `--input-compression full`，只改后端。此前支付、采购、文档分享三场景的 0.77% 结果保留为历史证据；那组三项不是用户指定视频的完整任务集。

## 实际执行顺序

1. **整轮旧历史裁剪**：完整请求超过 24,000 个本地估算 token 时，删除最早的完整用户轮次，保留最近两轮、系统和开发者指令、调用与返回配对。归档放在本次运行的 SourceStore，发送内容携带补读入口。中途插入指令、工具发现项、服务端引用、opaque reasoning 等情况不猜测裁剪边界。预算是目标，受保护内容可能使其无法达到。
2. **可还原结构压缩**：传入真实调用 ID 和工具名称/参数分组，启用重复结果引用、快照差量、JSON 表格和日志模板。不同请求不共享引用基线；被引用的基线不再选段或改写。嵌套 MCP 文本中的 JSON 可继续整理。参数仅做保值的 JSON 去空白。
3. **按任务保留原文**：工具文本及 `<lingmou-reference>` 先以整份材料做本地选段，再考虑分片改写。放宽为保留任务命中的段落及邻段，不再强制保留全材料中的每一条事实、数字或无关条件。保留的段落逐字复制，带来源位置及 `lingmou_source_read` 入口。所有匹配段落都保留，不受 top-4 排名截断。未命中、材料太短、原文无法保存或没有收益时回退。
4. **技能说明按需加载**：识别宿主 `<skills_instructions>` 中的标准技能目录，保留全部技能名、路径、根目录映射和目录外的使用规则。用户点名的技能及排名靠前的词项匹配保留完整说明，其余说明存入 SourceStore 并提供补读入口。未知格式、归档失败或没有收益时保留原文。技能路由依赖描述时可能增加补读，关闭此项可保留完整路由上下文。
5. **有预算的措辞改写**：先试规则，再按需要调用 Kimi；LLMLingua/Caveman 模型只处理材料及助手历史，不再用删词模型处理严格指令。用户任务原文保留。Jev 对有明确任务的工具/参考材料检查任务必要证据，默认门槛 0.75；指令和其他文本仍检查全部要求与事实，门槛 0.9。工具描述同时覆盖顶层 `tools` 与 Codex 的 `input[].additional_tools.tools`；后者也单独计入工具定义用量。改写后的字面量和代码必须能精确还原，相关条件、例外、失败和矛盾不能丢失。
6. **工具按需加载**：请求已有 hosted `tool_search` 时，给可延迟的函数定义设置 `defer_loading`。保留完整 schema、显式常驻设置、原文补读工具和强制工具选择。没有 hosted search、只有 client search 或使用 Chat Completions 时保留原工具定义；代理没有相应宿主处理器，不能直接删掉定义。HTTP 仍传完整 schema，因此不把这一阶段记成本地请求长度减少，实际收益要看服务商 usage。

任务相关选段属于有损压缩，本地词项匹配可能漏掉语义相关但没有共同词项的远距离证据；来源可补读并不等于已经证明任务答案质量。它不再经过“保留全部事实”的 Jev 等价性检查。需要保持全部证据时使用 `structure`。

## 控制额外消耗

每个流水线实例（通常对应一个 Run）默认提供一次 **3,000 个估算 token** 的启动额度，允许没有现成材料收益时尝试可复用的改写；不会随每次请求重置。除此之外，只使用本次本地估算节省量的 **25%**，每个请求仍受 **4 次调用、6,000 个估算 token** 的上限约束。估算包括校验状态和输出预留；已返回的官方用量高于预留时按较大值扣减额度。此预算跨 Kimi/Jev 共享，失败调用也占名额。启动额度可能无法回本，不能将预算当成净节省保证；设为 0 可恢复仅以已取得收益支付远程调用的模式。

少于 256 token 的片段默认不做模型改写。候选至少减少 32 token 且达到 10% 才送检。材料缓存按角色、当前任务和原文分开，重复请求可直接复用已核对结果；已付费否决的本地候选也缓存原文，避免逐请求重复送检。预算不足且未发出调用时不缓存否决。

默认关闭生成后的付费回答整理，避免为已经产生的输出再次付费；SSE 与主模型官方 usage 不变。若显式启用，整理仍只代表后续复用长度变化，不减少本次输出账单。

## 后端配置

以下环境变量在创建 `full` 流水线时读取，无需修改前端。

| 环境变量 | 默认值 | 作用 |
|---|---:|---|
| `LINGMOU_FULL_HISTORY_MAX_TOKENS` | 24000 | 完整请求裁剪目标；0 关闭历史裁剪 |
| `LINGMOU_FULL_HISTORY_KEEP_TURNS` | 2 | 至少保留的最近用户轮次 |
| `LINGMOU_FULL_MATERIAL_THRESHOLD` | 0.75 | 有任务上下文的工具/参考改写校验门槛 |
| `LINGMOU_FULL_INSTRUCTION_THRESHOLD` | 0.9 | 其他文本改写校验门槛 |
| `LINGMOU_FULL_MIN_MODEL_TOKENS` | 256 | 进入模型改写的片段下限 |
| `LINGMOU_FULL_MIN_SAVED_TOKENS` | 32 | 候选绝对节省下限 |
| `LINGMOU_FULL_MIN_SAVED_RATIO` | 0.1 | 候选相对节省下限 |
| `LINGMOU_FULL_MAX_REMOTE_CALLS` | 4 | 单请求远程调用上限；0 表示只运行本地阶段 |
| `LINGMOU_FULL_MAX_REMOTE_TOKENS` | 6000 | 单请求远程用量估算上限 |
| `LINGMOU_FULL_STARTUP_REMOTE_TOKENS` | 3000 | 每个流水线实例仅一次的启动额度；0 关闭 |
| `LINGMOU_FULL_DEFER_SKILL_DESCRIPTIONS` | true | 技能目录描述按需加载；名称、路径、规则保留 |
| `LINGMOU_FULL_REMOTE_BUDGET_SHARE` | 0.25 | 本次本地收益可分配给远程工作的比例 |
| `LINGMOU_FULL_ALLOW_UNFUNDED_REMOTE` | false | 显式实验开关，允许没有本地收益时付费改写 |
| `LINGMOU_FULL_OUTPUT_REWRITE` | false | 显式启用生成后的付费整理 |

本地阶段不需要 key。Kimi/Jev 沿用已有仓库外密钥环境变量。本地 LLMLingua-2、Caveman NLP/MLM 沿用模型路径配置；不会自动下载模型。源码接口也可注入 Headroom 等后端。未配置的算法不要求执行，不能把“存在标签”写成“实际采用”。

协议依据：[TypeSafe Noul](https://docs.typesafe.ai/primitives/noul.md)、[HTTP API](https://docs.typesafe.ai/api.md)、[OpenAI hosted tool search](https://developers.openai.com/api/docs/guides/tools-tool-search)。0.75/0.9 是本项目可调阈值，不是供应商保证的准确率。

本次验证与适用范围见 [验收记录](../evidence/full_compression_reintegration_20261012/REPORT.md)。启动新的 monitor 才会加载改过的 Python 代码；修改文件不会热更新已经运行的进程。
