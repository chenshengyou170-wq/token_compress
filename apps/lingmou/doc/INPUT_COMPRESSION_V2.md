# 灵眸输入压缩 v2

这是灵眸产品的输入侧优化，不改变独立 Token 调研项目的验收。默认关闭；压缩质量仍需按任务检查。

## 处理边界

代理仅处理 `function_call_output.output`、Codex 的 `custom_tool_call_output.output`、
Chat Completions 的 tool 文本及用户消息中的显式参考块：

```text
核对订单，返回 approved 布尔值和 status 原枚举。
<lingmou-reference>
这里放文档、代码或记录。
</lingmou-reference>
输出格式要求写在参考块外。
```

宿主也可使用 `codexscope.compression_boundary.reference_text(text)` 生成块。
嵌套、缺少闭合或多余标记会保留整条消息。system、developer、instructions、未标记的
user 文本及 assistant 历史均原样保留；标记不能覆盖角色边界。
工具定义、调用参数、输出 schema、消息 ID/phase、多模态及加密 reasoning 项不参与压缩。
外层 JSON 可以重新序列化；字符串值及 JSON 数字字面量不改变。
服务端历史引用、签名/摘要请求、不支持的编码及端点按原有转发边界处理。

## 可还原的结构压缩

`structure`（兼容名称 `hybrid`）不调用模型。每个候选先做解码校验，再比较字段和完整请求的
本地 token 估算；没有收益则使用原文。格式通过 `$lingmou` 标记及 `decode` 字段说明：

| 格式 | 保留的信息 |
|---|---|
| `table/v1` | 字段顺序、逐行值、布尔/null/数值/字符串类型；字段名仅保存一次 |
| `logs/v1` | 模板片段、变量、次数及记录顺序；包括换行，能逐字恢复 |
| `repeat/v1` | 指向同一请求中更早的结果，保留首次结果，避免追加历史时改写旧前缀 |
| `delta/v1` | 相同工具及相同参数的完整基准，加按 key/index 路径的替换；支持删除键和数组变化 |

JSON 浮点数不经过浮点运算，保留原始数字字面量；重复键、非 JSON 常量、伪造的压缩标记等保持不动。
差量以非差量结果为基准，不产生无界引用链；请求间不共享基准。
`decode_tool_result(text, bases)` 可恢复 canonical JSON 或原始日志；它会拒绝缺失基准、循环及超量展开。
JSON 空白和字符串转义的表现形式可以变化，JSON 值不变。解码正确并不自动证明所有模型都理解此格式；
真实任务检查另列于验收记录。

## 按任务筛选原文及补读

`extract` 是无需密钥的中英文词项匹配基线；`jev` 用 TypeSafe 的一批独立 Noul 问题判断段落相关性；
`kimi` 仅接受 `keep_ids`，不再接受自由改写。筛选器返回编号，程序核验编号后从原文直接切片。
Jev 保留不确定段落；未找到强相关证据时保留整份材料。阈值是本项目的保守初值，不是语义正确性保证。

段落包含字符偏移、行号和来源 hash。Python 顶层函数/类及 Markdown 代码围栏整块保留；
识别到的条件、例外段和选中段的相邻段一起发送。筛选仍可能漏掉远处依赖，模型需要时应补读原文。
当前超过 80 段、100,000 字符、没有可用任务或无有效编号的材料不做有损选段。
结构压缩已有可还原结果时优先使用它。

```bash
codexscope monitor -C /path/to/project \
  --request-token-tap-upstream https://chatgpt.com/backend-api/codex \
  --input-compression extract
```

监控器会为该运行创建 `compression_sources/` 并注册 stdio MCP 工具 `lingmou_source_read`。
目录权限为 0700，新文件为 0600；读取工具仅接受来源 hash，不接受任意路径。原文按内容寻址，
不淘汰仍可被引用的内容；默认 64 MiB 配额，超限时保留请求原文。原文不会写入 usage 日志。
这些私有源文件用于重读，会留在本次运行目录，随该运行一起保管或删除。

手动使用：

```bash
codexscope context compress request.json --mode extract --store /private/run/sources --output compressed.json
codexscope context read --store /private/run/sources SOURCE_SHA256 --start-line 1 --end-line 30
codexscope context serve --store /private/run/sources
```

库调用需要传入 `SourceStore`，并由宿主提供相应读取工具；未传入 store 时只执行可还原结构压缩。
缓存键包含当前任务和原文，换任务重新选择；失败调用有短时退避，不把一次筛选结果复用于不同任务。
每次请求最多 4 次模型尝试。Kimi/Jev 的调用、失败和官方 usage 均进入请求的 `compression_calls`。

## LLMLingua-2 对照

可选依赖不影响普通安装：

```bash
uv sync --locked --extra test --extra proxy --extra compression
# 先自行下载 Microsoft 的 LLMLingua-2 模型到仓库外，再指定完整本地目录：
export LINGMOU_LLMLINGUA_MODEL=/private/models/llmlingua-2-xlm-roberta-large-meetingbank
codexscope monitor -C /path/to/project \
  --request-token-tap-upstream https://chatgpt.com/backend-api/codex \
  --input-compression llmlingua2
```

CPU 环境可先从 PyTorch CPU wheel 源安装 `torch`，再用 `uv pip install -e '.[compression]'` 安装其余依赖，
避免默认 CUDA wheel。模型延迟加载，默认 CPU、保留率 0.6，`local_files_only=True`、`trust_remote_code=False`。
程序将受保护文本替换为必须保留的标记，核验顺序/次数后还原；缺依赖、缺权重、标记损坏或预计增长均回退原文。
超过保护标记上限时也回退。代码、引号字面量、数字及识别到的条件不参与删词。
模型输出明确标记 `lossy/v1`，保留完整源供补读。这是有损研究基线，不以论文压缩率承诺产品收益。

## 工具按需加载和前缀缓存

`DeferredToolRegistry` 是宿主接口：`catalog()` 只列名称和描述，`load(names)` 返回完整原始定义。
支持 Responses 的宿主可用 `responses_tools()` 配置 client tool search，再用
`handle_search(tool_search_call)` 返回与 call_id 绑定的 `tool_search_output`。
宿主负责将返回定义及输出加入后续上下文，并按自己的策略执行已加载工具。
只允许加载注册过的可信函数，参数 schema 不作简写，未知名称会报错。

当前工作区 Codex 已有 tool search / deferred loading；监控器保留这套行为。
代理不会删除工具定义，也不会擅自注入搜索工具。现有 `tool_search` 配置保持原值。
使用接口的完整请求往返示例见 [宿主示例](../examples/context_compression_host.py)。

`with_prompt_cache_key(body, namespace=...)` 提供宿主显式调用的稳定缓存路由键，已有键不覆盖。
namespace 应按租户/任务族隔离；工具和稳定指令前缀保持原顺序，动态材料放后面。
缓存只可能减少重复计算及费用，不减少输入长度；是否命中仍由官方 `cached_input_tokens` 验证。

## 完整任务开销与正确性

请求日志保存完整请求的本地前/后估算及该请求返回的官方 usage，二者分开。
`manifest.json` 中 `usage_ledger.tasks` 的累计值不会因最近 200 条列表上限而丢失。
Codex 的 thread/turn 元数据会映射为任务 ID；缺少元数据时明确归于整次运行。
重复请求体的次数作为重试推断并注明来源；读取工具结果触发的下一次模型请求标为补读。
经 Codex `exec` 代码工具调用补读时，根据工具调用表达式识别并注明是推断；目录搜索不计为补读。
宿主可使用以下头显式归组，代理记录后移除，不转发给服务商：

```text
X-Lingmou-Task-Id: task-001
X-Lingmou-Purpose: generation   # 或 reread / retry
X-Lingmou-Attempt: 1
```

汇总包括所有下游尝试和远程选段调用；补读/重试是下游调用的可能重叠子集，不能再次加到总量中。
本地 LLMLingua 调用单列次数、请求总压缩耗时，没有伪造官方 usage。
失败请求或选段调用缺少 usage 时保留已知总量，但净节省值为 `null`。
输入含 cached input；缓存 detail 缺失也保持未知。输出增长单列，价格及延迟不从 token 降幅推断。

```bash
codexscope context report candidate/request_usage.jsonl \
  --baseline baseline/request_usage.jsonl --task-id task-001 \
  --checks candidate-checks.json --baseline-checks baseline-checks.json
```

checks 文件是实际验收程序产生的 JSON 布尔检查集合，例如 `{"exact_fields":true,"approved_type":true}`。
没有质量检查时 `quality_passed` 为 null；只有两侧检查全部通过、usage 完整且净量下降，
`verified_task_savings` 才为 true。

可复现合成对照（真实 Codex 命令使用现有 ChatGPT 登录，会消耗相应额度）：

```bash
.venv/bin/python scripts/evaluate_context_compression.py --provider local --out /private/context-local
.venv/bin/python scripts/evaluate_context_compression.py --provider codex --out /private/context-codex
```

用 `--modes`、`--cases` 缩小范围。输出目录记录配置；同目录可续跑，已经保存的失败不会被覆盖。
英文表格、中文条件及枚举/布尔值、代码、实际补读往返分别验收；所有重试都留在总量里。
合成冗余材料只能验证功能，不能代表日常任务平均收益。

## 实现参考

- [Microsoft LLMLingua 官方实现](https://github.com/microsoft/LLMLingua)和 [LLMLingua-2 论文](https://arxiv.org/abs/2403.12968)：用于本地可选分类压缩接口。
- [LongLLMLingua 论文](https://aclanthology.org/2024.acl-long.91/)：问题相关压缩的思路参考，本实现的抽取算法没有冒用其名称。
- [TypeSafe HTTP API](https://docs.typesafe.ai/api)、[Noul](https://docs.typesafe.ai/primitives/noul)、[reranking cookbook](https://docs.typesafe.ai/cookbooks/rerank_typesafe)：采用批量相关性判断，代码负责选择和复制原文。
- [OpenAI Tool Search](https://developers.openai.com/api/docs/guides/tools-tool-search)及[前缀缓存](https://developers.openai.com/api/docs/guides/prompt-caching)：宿主接口与缓存语义，以服务商当前可用能力为准。
