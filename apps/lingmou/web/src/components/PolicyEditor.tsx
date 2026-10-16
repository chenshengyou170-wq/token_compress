import { useEffect, useState } from "react";
import type { PolicyCatalog } from "../types";
import type { MetaPolicy } from "../policyComposition";
import { PolicyTraceTree, type RuleTrace } from "./PolicyTraceTree";
import { MetaPolicyBuilder } from "./MetaPolicyBuilder";
type Rule = { id: string; name: string; event: string; mode: string; enabled?: boolean; when: unknown };
type Document = { schema_version: string; atoms: Record<string, unknown>; lists: Record<string, unknown>; rules: Rule[]; overrides: Record<string, Record<string, unknown>>; filesystem?: { deny: string[] }; semantic_atoms?: Record<string, { question: string; fields: string[]; min_probability: number }> };
type Configuration = { document: Document; revision: string; path: string; defaults: Rule[]; meta_policies?: { items: MetaPolicy[] }; filesystem_guard?: { status: string; denied_paths?: string[]; restart_required: boolean } };
type IntentProposal = { status: "ready"; proposal_id: string; summary: string; changes: { action: string; path: string; summary: string }[] };
type IntentResult = IntentProposal | { status: "already_active"; summary: string; message: string; configuration: Configuration };
type Preview = { traces?: RuleTrace[]; decisions: { policy_id: string; policy_name: string; mode: string }[]; blocking_rule: string | null; facts?: Record<string, unknown>; parse_warnings?: string[] };
async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, headers: { "Content-Type": "application/json" } });
  const value = await response.json();
  if (!response.ok) throw new Error(typeof value.detail === "string" ? value.detail : `请求失败 (${response.status})`);
  return value;
}
const modes: Record<string, string> = { observe: "记录", review: "人工复核", deny: "阻断", transform: "处理内容" };
const fields: Record<string, string> = { "command.text": "命令文本", "command.cwd": "执行目录", "principal.role": "Agent 角色" };
const operators: Record<string, string> = { contains: "包含", eq: "等于", starts_with: "开头是", ends_with: "结尾是", gt: "大于", gte: "至少", lt: "小于", lte: "至多", in: "在名单中", not_in: "不在名单中", intersects: "与名单有交集", exists: "存在" };
function conditionLabel(value: unknown, depth = 0): string {
  if (!value || typeof value !== "object" || depth > 4) return "在高级配置中查看条件";
  const node = value as Record<string, unknown>;
  if (typeof node.atom === "string") return `条件原子：${node.atom}`;
  if (Array.isArray(node.all)) return node.all.map((v) => conditionLabel(v, depth + 1)).join(" 且 ");
  if (Array.isArray(node.any)) return node.any.map((v) => conditionLabel(v, depth + 1)).join(" 或 ");
  if (node.not) return `不满足（${conditionLabel(node.not, depth + 1)}）`;
  if (typeof node.field === "string" && typeof node.op === "string") return `${fields[node.field] || node.field}${operators[node.op] || node.op} ${typeof node.value === "string" ? node.value : JSON.stringify(node.value)}`;
  return "在高级配置中查看条件";
}
export function PolicyEditor({ onSaved }: { onSaved?: (catalog: PolicyCatalog) => void }) {
  const [config, setConfig] = useState<Configuration | null>(null);
  const [draft, setDraft] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [requirement, setRequirement] = useState("");
  const [proposal, setProposal] = useState<IntentProposal | null>(null);
  const [activating, setActivating] = useState(false);
  const [activated, setActivated] = useState("");
  useEffect(() => { let live = true; request<Configuration>("/api/v1/policy-config").then((value) => { if (live) { setConfig(value); setDraft(JSON.stringify(value.document, null, 2)); setBuiltin(value.defaults[0]?.id || ""); } }).catch((e) => { if (live) setError(String(e.message || e)); }); return () => { live = false; }; }, []);
  const [command, setCommand] = useState("");
  const [builtin, setBuiltin] = useState("");
  const [name, setName] = useState("");
  const [semanticQuestion, setSemanticQuestion] = useState("");
  const [needle, setNeedle] = useState("");
  const [directory, setDirectory] = useState("");
  const [mode, setMode] = useState("review");
  const [field, setField] = useState("command.text");
  const [operator, setOperator] = useState("contains");
  async function perform(action: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("");
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  async function load() {
    await perform(async () => {
      const value = await request<Configuration>("/api/v1/policy-config");
      setConfig(value); setDraft(JSON.stringify(value.document, null, 2)); setBuiltin(value.defaults[0]?.id || ""); setPreview(null); setOpen(true);
    });
  }
  function change(update: (document: Document) => void) {
    try { const document: Document = JSON.parse(draft); update(document); setDraft(JSON.stringify(document, null, 2)); setPreview(null); setError(""); setMessage("草稿已修改，请保存。目录边界变更需重启 Agent。"); return true; }
    catch { setError("JSON 草稿格式有误，请先修正后再使用快捷编辑。"); return false; }
  }
  let parsed: Document | null = null;
  try { const value = JSON.parse(draft); if (value && Array.isArray(value.rules)) parsed = value; } catch { /* Draft stays editable. */ }
  const directoryRules = parsed && Array.isArray(parsed.filesystem?.deny) ? parsed.filesystem.deny.filter((p) => typeof p === "string") : [];
  const selected = config?.defaults.find((r) => r.id === builtin);
  const override = parsed?.overrides?.[builtin];
  const previewBlocker = preview?.decisions.find((d) => d.policy_id === preview.blocking_rule);
  return <section className="policy-editor" aria-label="定制策略">
    <div className="policy-editor-heading"><div><h2>自定义策略</h2><p>用语言设置目录边界，或组合网络、文件和执行条件。</p></div><button className="header-button" type="button" disabled={busy} onClick={() => open ? setOpen(false) : config ? setOpen(true) : void load()}>{open ? "收起规则编辑" : "编辑组合规则"}</button></div>
    {error && <p role="alert" className="policy-editor-error">{error}</p>}
    <div className="policy-intent">
      <label htmlFor="policy-requirement">你希望 Agent 遵守什么限制？</label>
      <textarea id="policy-requirement" value={requirement} maxLength={4000} rows={3} disabled={busy} onChange={(e) => { setRequirement(e.target.value); setProposal(null); setActivated(""); setError(""); }} placeholder="例如：不要让 Agent 访问财务私有目录 finance/private，其他资料正常使用。" />
      <div className="policy-editor-actions"><button className="primary-button" type="button" disabled={busy || !requirement.trim()} onClick={() => void perform(async () => { setProposal(null); setActivated(""); const result = await request<IntentResult>("/api/v1/policy-intent/interpret", { method: "POST", body: JSON.stringify({ text: requirement }) }); if (result.status === "already_active") { setConfig(result.configuration); setDraft(JSON.stringify(result.configuration.document, null, 2)); setActivated(`${result.message} ${result.summary}`); } else { setProposal(result); } })}>{busy && !activating ? "正在理解需求…" : "生成策略"}</button><small>支持禁止访问指定目录或解除目录禁访问；不明确的要求会提示你补充。</small></div>
      {proposal && <div className="policy-intent-result" aria-live="polite"><h3>将启用以下规则</h3><ul>{proposal.changes.map((c, i) => <li key={i}>{c.summary}</li>)}</ul><p>启用后自动进入新的受保护会话，历史记录仍可查看。</p><button type="button" className="primary-button" disabled={busy} onClick={() => void perform(async () => { setActivating(true); try { const applied = await request<{ status: string; summary: string; configuration: Configuration }>("/api/v1/policy-intent/activate", { method: "POST", body: JSON.stringify({ proposal_id: proposal.proposal_id }) }); setConfig(applied.configuration); setDraft(JSON.stringify(applied.configuration.document, null, 2)); setActivated(applied.summary); setProposal(null); onSaved?.(await request<PolicyCatalog>("/api/v1/policies")); } finally { setActivating(false); } })}>{activating ? "正在启用并连接 Agent…" : "启用策略"}</button></div>}
      {activated && <div role="status" className="policy-intent-result"><strong>策略已生效</strong><p>{activated}</p><a className="header-button" href="#/workbench">去工作台提交任务</a></div>}
      {!activated && config?.filesystem_guard?.status === "active" && <small>当前受保护目录：{config.filesystem_guard.denied_paths?.join("、")}</small>}
    </div>

    {open && config && <div className="policy-editor-body">
      <p>命令策略仅在 Agent 请求执行前审批时生效；观察模式只记录，复核模式保留原审批，阻断模式在保护开启时拒绝。办公动作在提交时检查。</p>
      <MetaPolicyBuilder catalog={config.meta_policies?.items || []} busy={busy} onAdd={(rule) => change((d) => { d.rules.push({ ...rule, id: `USER-${crypto.randomUUID()}`, enabled: true, event: "command.approval" }); })} />
      <fieldset disabled={busy}><legend>禁止访问目录</legend>
        <p>指定目录及其子目录禁止 Agent 读取、列出和修改。支持工作区相对路径或绝对路径；保存后重启 Agent 生效。</p>
        <div className="policy-editor-controls"><label className="policy-editor-command">目录路径<input value={directory} onChange={(e) => setDirectory(e.target.value)} placeholder="例如：finance/private" /></label><button className="header-button" type="button" disabled={!directory.trim()} onClick={() => change((d) => { d.filesystem = { deny: [...new Set([...(d.filesystem?.deny || []), directory.trim()])] }; setDirectory(""); })}>禁止此目录</button></div>
        <div className="policy-editor-rules">{directoryRules.map((path) => <div key={path}><span><strong>{path}</strong><small>禁止读取、列目录、写入</small></span><button className="header-button" type="button" onClick={() => change((d) => { d.filesystem = { deny: (d.filesystem?.deny || []).filter((p) => p !== path) }; })}>移除 {path}</button></div>)}</div>
        <small role="status">{config.filesystem_guard?.restart_required ? "配置已保存，待重启 Agent。当前会话仍使用原目录边界。" : config.filesystem_guard?.status === "active" ? "当前 Agent 已启用目录保护。" : "当前 Agent 未启用目录保护。"}</small>
        {!!config.filesystem_guard?.denied_paths?.length && <small>当前生效：{config.filesystem_guard.denied_paths.join("、")}</small>}
      </fieldset>
      <fieldset disabled={busy}><legend>调整内置规则</legend><div className="policy-editor-controls">
        <label>规则<select aria-label="规则" value={builtin} onChange={(e) => setBuiltin(e.target.value)}>{config.defaults.map((r) => <option key={r.id} value={r.id}>{r.id} · {r.name}</option>)}</select></label>
        <label>内置规则处置<select aria-label="内置规则处置" value={String(override?.mode || selected?.mode || "observe")} onChange={(e) => change((d) => { d.overrides[builtin] = { ...d.overrides[builtin], mode: e.target.value }; })}><option value="observe">记录</option><option value="review">人工复核</option><option value="deny">阻断</option>{selected?.mode === "transform" && <option value="transform">处理内容</option>}</select></label>
        <label className="policy-editor-check"><input type="checkbox" checked={override?.enabled !== false} onChange={(e) => change((d) => { d.overrides[builtin] = { ...d.overrides[builtin], enabled: e.target.checked }; })} />启用</label>
        <button className="header-button" type="button" onClick={() => change((d) => { delete d.overrides[builtin]; })}>恢复此规则默认值</button>
      </div><small>{selected?.event === "work.action" ? "办公动作提交前检查；内容处理规则也可调整条件或停用。" : "只调整命令审批阶段；运行时检测仍保留原始证据。"}</small></fieldset>
      <fieldset disabled={busy}><legend>新增 Jev 语义条件</legend><p>描述需要判断的行为。Jev 根据命令文本判断；无法确定时进入人工复核。与网络、文件等元策略的嵌套组合可在高级配置中编辑。</p><div className="policy-editor-controls"><label className="policy-editor-command">判断标准<input value={semanticQuestion} maxLength={2000} onChange={e => setSemanticQuestion(e.target.value)} placeholder="例如：命令是否向外部服务上传本地文件？" /></label><button className="header-button" type="button" disabled={!semanticQuestion.trim()} onClick={() => change(d => { const id = `semantic-${crypto.randomUUID()}`; d.semantic_atoms = { ...d.semantic_atoms, [id]: { question: semanticQuestion.trim(), fields: ["command.text"], min_probability: 0.9 } }; d.rules.push({ id: `USER-${id}`, name: semanticQuestion.trim().slice(0, 160), event: "command.approval", mode: "review", when: { semantic: id } }); setSemanticQuestion(""); })}>加入复核规则草稿</button></div><small>输入仅发送配置中指定的字段；缺失或脱敏的证据转人工。模型概率并非事实证明。服务密钥由管理员在服务端配置。</small></fieldset>
      <fieldset disabled={busy}><legend>新增命令规则</legend><div className="policy-editor-controls">
        <label>规则名称<input value={name} maxLength={160} onChange={(e) => setName(e.target.value)} placeholder="例如：部署前人工复核" /></label>
        <label>检查字段<select aria-label="检查字段" value={field} onChange={(e) => setField(e.target.value)}><option value="command.text">命令文本</option><option value="command.cwd">执行目录</option><option value="principal.role">Agent 角色</option></select></label>
        <label>条件<select aria-label="条件" value={operator} onChange={(e) => setOperator(e.target.value)}><option value="contains">包含</option><option value="eq">等于</option><option value="starts_with">开头是</option><option value="ends_with">结尾是</option></select></label>
        <label>匹配值<input value={needle} onChange={(e) => setNeedle(e.target.value)} placeholder="例如：deploy" /></label>
        <label>新规则处置<select aria-label="新规则处置" value={mode} onChange={(e) => setMode(e.target.value)}><option value="review">人工复核</option><option value="deny">阻断</option><option value="observe">记录</option></select></label>
        <button className="header-button" type="button" disabled={!name.trim() || !needle.trim()} onClick={() => change((d) => { d.rules.push({ id: `USER-${crypto.randomUUID()}`, name: name.trim(), enabled: true, event: "command.approval", mode, when: { field, op: operator, value: needle } }); setName(""); setNeedle(""); })}>加入草稿</button>
      </div></fieldset>
      <div className="policy-editor-rules" aria-label="自定义规则草稿">{parsed?.rules?.filter((r) => r && typeof r.id === "string" && typeof r.name === "string" && typeof r.mode === "string" && typeof r.event === "string").map((r) => <div key={r.id}><span><strong>{r.name}</strong><small>{conditionLabel(r.when)} · {modes[r.mode] || r.mode} · {r.enabled === false ? "停用" : "启用"}</small></span><button className="header-button" type="button" disabled={busy} onClick={() => change((d) => { d.rules = d.rules.filter((x) => x.id !== r.id); })}>删除 {r.name}</button></div>)}</div>
      <details><summary>高级配置：组合条件、可复用原子与名单</summary><p>用 all / any / not 组合条件，以 atom 引用自定义原子或内置 meta.* 元策略，以 semantic 引用 semantic_atoms 中的 Jev 判断。办公规则使用 work.action 事件，可匹配 action.request.* 和 action.impact.* 字段。保存时会校验全部规则。</p><label>策略 JSON<textarea spellCheck={false} value={draft} disabled={busy} onChange={(e) => { setDraft(e.target.value); setPreview(null); setMessage(""); }} rows={18} /></label><small>配置文件：{config.path}</small></details>
      <fieldset disabled={busy}><legend>保存前试算</legend><p>只试算命令审批条件，不检查目录访问权限，不会执行。目录规则请在重启 Agent 后验证。</p><div className="policy-editor-controls"><label className="policy-editor-command">命令<input value={command} onChange={(e) => { setCommand(e.target.value); setPreview(null); }} placeholder="例如：npm run deploy" /></label><button className="header-button" type="button" disabled={!command.trim()} onClick={() => void perform(async () => { setPreview(await request<Preview>("/api/v1/policy-config/preview", { method: "POST", body: JSON.stringify({ document: JSON.parse(draft), command }) })); })}>试算草稿</button></div>
        {preview && <div role="status" className="policy-editor-preview"><strong>{preview.blocking_rule ? `命中阻断规则：${previewBlocker?.policy_name || "配置规则"}` : "没有阻断规则命中，继续原审批流程"}</strong>{preview.blocking_rule && <p>保护开启且操作进入执行前审批时，该规则会拒绝执行。<small>规则编号：{preview.blocking_rule}</small></p>}<ul>{preview.decisions.map((d) => <li key={d.policy_id}>{d.policy_name} · {d.mode === "deny" ? "阻断" : d.mode === "review" ? "人工复核" : "记录"}</li>)}</ul></div>}
        {preview?.parse_warnings && preview.parse_warnings.length > 0 && <div className="policy-editor-preview"><strong>部分行为无法从命令确定</strong><ul>{preview.parse_warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul><p>可添加“命令无法完整静态解析”条件，要求人工复核。</p></div>}
        {preview?.traces && <PolicyTraceTree traces={preview.traces} />}
        {preview?.facts && <details><summary>查看本次识别出的网络、文件和进程事实</summary><pre className="policy-facts">{JSON.stringify(preview.facts, null, 2)}</pre></details>}
      </fieldset>
      <div className="policy-editor-actions"><button className="primary-button" type="button" disabled={busy} onClick={() => void perform(async () => { const saved = await request<Configuration>("/api/v1/policy-config", { method: "PUT", body: JSON.stringify({ document: JSON.parse(draft), revision: config.revision }) }); setConfig(saved); setDraft(JSON.stringify(saved.document, null, 2)); setMessage(saved.filesystem_guard?.restart_required ? "已保存目录配置，请重启 Agent 后使用新边界。" : "已保存，后续执行前检查将使用新策略。"); onSaved?.(await request<PolicyCatalog>("/api/v1/policies")); })}>{busy ? "处理中…" : "保存策略"}</button><button className="header-button" type="button" disabled={busy} onClick={() => void load()}>放弃草稿并重新载入</button><span role="status">{message}</span></div>
    </div>}
  </section>;
}
