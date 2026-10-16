import { useState } from "react";

export type ConditionTrace = {
  kind: string; path: string; result: string; name?: string; field?: string; op?: string;
  actual?: unknown; expected?: unknown; value_present?: boolean; reason?: string;
  question?: string; model?: string; source?: string; threshold?: number;
  probabilities?: Record<string, number>; evidence?: unknown; evidence_digest?: string;
  review?: unknown; primary?: unknown; review_error?: string; children?: ConditionTrace[];
};
export type RuleTrace = {
  schema_version: string; policy_id: string; policy_name: string; result: string;
  configured_mode: string; effective_mode: string; when: ConditionTrace;
  scope?: ConditionTrace | null; review_when?: ConditionTrace | null;
};
const labels: Record<string, string> = { true: "真", false: "假", unknown: "不确定" };
const kinds: Record<string, string> = { all: "全部成立 AND", any: "任一成立 OR", not: "取反 NOT" };
const modes: Record<string, string> = { deny: "阻断", review: "人工复核", observe: "记录", transform: "处理内容", none: "不触发" };
function Value({ value }: { value: unknown }) {
  return <code>{JSON.stringify(value) ?? "未提供"}</code>;
}
function Branch({ node }: { node: ConditionTrace }) {
  if (!node || typeof node !== "object") return <p>此历史记录未保存完整条件，请重新试算。</p>;
  return <li className="policy-trace-node">
    <div className="policy-trace-line"><span className={`policy-trace-verdict is-${node.result}`}>{labels[node.result] || "未记录"}</span><strong>{kinds[node.kind] || node.name || node.field || "条件"}</strong>{node.op && <span>{node.op}</span>}</div>
    {node.kind === "predicate" && <dl className="policy-trace-values"><dt>实际值</dt><dd>{node.value_present === false ? "字段缺失" : <Value value={node.actual} />}</dd><dt>比较值</dt><dd><Value value={node.expected} /></dd></dl>}
    {node.question && <p>{node.question}</p>}
    {node.reason && <small>{node.reason}</small>}
    {node.kind === "semantic" && <>
      <p className="policy-trace-model">{node.source === "review_model" ? "复核模型判断" : "Jev 语义判断"}{node.model ? ` · ${node.model}` : " · 尚无有效模型响应"}{node.threshold != null ? ` · 采用阈值 ${Math.round(node.threshold * 100)}%` : ""}</p>
      {node.probabilities && <p>选择概率：成立 {Math.round(node.probabilities.matched * 100)}% · 不成立 {Math.round(node.probabilities.not_matched * 100)}% · 未知 {Math.round(node.probabilities.unknown * 100)}%</p>}
      <details><summary>查看模型输入与复核记录</summary><pre>{JSON.stringify({ evidence: node.evidence, evidence_digest: node.evidence_digest, primary: node.primary, review: node.review, review_error: node.review_error }, null, 2)}</pre></details>
    </>}
    {Array.isArray(node.children) && <ul>{node.children.map((child, i) => <Branch key={child.path || i} node={child} />)}</ul>}
  </li>;
}
export function PolicyTraceTree({ traces }: { traces: RuleTrace[] }) {
  const [all, setAll] = useState(false);
  if (!traces.length) return null;
  const relevant = traces.filter(t => t.result !== "false");
  const visible = all ? traces : relevant;
  return <section className="policy-traces" aria-label="条件解释树">
    <div className="policy-traces-heading"><div><h3>条件解释树</h3><p>{traces.length} 条规则已判断 · {relevant.length} 条命中或待复核</p></div><label><input type="checkbox" checked={all} onChange={e => setAll(e.target.checked)} />显示未命中规则</label></div>
    <p className="policy-traces-help">展开查看每个分支。真／假表示条件判断，不确定表示证据或模型判断不足；不代表操作已经执行。</p>
    {!visible.length && <p>本次没有触发规则。勾选“显示未命中规则”可检查各条件为何为假。</p>}
    {visible.map(trace => <details className="policy-trace-rule" key={trace.policy_id}>
      <summary><span className={`policy-trace-verdict is-${trace.result}`}>{labels[trace.result] || "未记录"}</span><strong>{trace.policy_name}</strong><span className="policy-trace-effect">{modes[trace.effective_mode] || trace.effective_mode}</span></summary>
      <p className="policy-trace-id">{trace.policy_id} · 配置处置：{modes[trace.configured_mode] || trace.configured_mode}</p>
      {trace.scope && <><h4>适用范围</h4><ul><Branch node={trace.scope} /></ul></>}
      <h4>触发条件</h4><ul><Branch node={trace.when} /></ul>
      {trace.review_when && <><h4>转人工复核条件</h4><ul><Branch node={trace.review_when} /></ul></>}
    </details>)}
  </section>;
}
export function tracesIn(value: unknown): RuleTrace[] {
  const found = new Map<string, RuleTrace>();
  function visit(item: unknown, depth: number) {
    if (!item || typeof item !== "object" || depth > 12) return;
    if (Array.isArray(item)) { item.forEach(v => visit(v, depth + 1)); return; }
    const record = item as Record<string, unknown>;
    if (record.schema_version === "lingmou.policy-trace.v1" && typeof record.policy_id === "string" && record.when && typeof record.when === "object") {
      found.set(record.policy_id, record as RuleTrace); return;
    }
    Object.values(record).forEach(v => visit(v, depth + 1));
  }
  visit(value, 0);
  return [...found.values()];
}
