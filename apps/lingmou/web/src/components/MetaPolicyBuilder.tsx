import { useState } from "react";
import { composePolicy, type Clause, type MetaPolicy, type Predicate } from "../policyComposition";

export function MetaPolicyBuilder({ catalog, busy, onAdd }: {
  catalog: MetaPolicy[]; busy: boolean;
  onAdd: (rule: { name: string; mode: string; when: Predicate }) => boolean;
}) {
  const [clauses, setClauses] = useState<Clause[]>([]);
  const [join, setJoin] = useState<"all" | "any">("all");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("review");
  const [error, setError] = useState("");
  const categories = [...new Set(catalog.map((item) => item.category))];
  const update = (id: string, patch: Partial<Clause>) => {
    setClauses((rows) => rows.map((row) => row.id === id ? { ...row, ...patch } : row)); setError("");
  };
  function addRule() {
    setError("");
    try {
      if (!name.trim()) throw new Error("请为组合规则命名。");
      const when = composePolicy(catalog, clauses, join);
      if (onAdd({ name: name.trim(), mode, when })) { setClauses([]); setName(""); }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  }
  return <fieldset disabled={busy} className="meta-policy-builder"><legend>组合网络、文件与执行条件</legend>
    <p>选择元策略并填写范围，再组合成一条规则。排除条件仅对这条规则有效。</p>
    <div className="policy-editor-controls">
      <label>组合规则名称<input value={name} maxLength={160} onChange={(e) => setName(e.target.value)} placeholder="例如：上传到非公司域名时阻断" /></label>
      <label>触发方式<select aria-label="触发方式" value={join} onChange={(e) => setJoin(e.target.value as "all" | "any")}><option value="all">全部条件满足</option><option value="any">任一条件满足</option></select></label>
      <label>组合规则处置<select aria-label="组合规则处置" value={mode} onChange={(e) => setMode(e.target.value)}><option value="review">人工复核</option><option value="deny">阻断</option><option value="observe">记录</option></select></label>
    </div>
    {!clauses.length && <p>可组合 {catalog.length} 项元策略。例如：“上传或发送数据”且“访问允许名单以外的域名”。</p>}
    <div className="meta-policy-clauses">{clauses.map((row, index) => {
      const meta = catalog.find((item) => item.id === row.metaId);
      return <div className="meta-policy-clause" key={row.id}>
        <div className="policy-editor-controls">
          <label>条件 {index + 1}<select aria-label={`条件 ${index + 1}`} value={row.metaId} onChange={(e) => update(row.id, { metaId: e.target.value, input: "" })}>
            {categories.map((category) => <optgroup key={category} label={category}>{catalog.filter((item) => item.category === category).map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</optgroup>)}
          </select></label>
          {meta?.parameter && <label className="policy-editor-command">匹配范围 {index + 1}<input value={row.input} onChange={(e) => update(row.id, { input: e.target.value })} placeholder={meta.parameter.placeholder} /></label>}
          <label className="policy-editor-check"><input type="checkbox" checked={row.exclude} onChange={(e) => update(row.id, { exclude: e.target.checked })} />作为排除条件</label>
          <button type="button" className="header-button" onClick={() => setClauses((rows) => rows.filter((r) => r.id !== row.id))}>移除条件 {index + 1}</button>
        </div><small>{meta?.description}{meta?.parameter ? " 多项用逗号分隔。" : ""}</small>
      </div>;
    })}</div>
    {error && <p role="alert" className="policy-editor-error">{error}</p>}
    <div className="policy-editor-actions">
      <button type="button" className="header-button" disabled={!catalog.length || clauses.length >= 32} onClick={() => setClauses((rows) => [...rows, { id: crypto.randomUUID(), metaId: catalog[0].id, input: "", exclude: false }])}>添加元策略条件</button>
      <button type="button" className="header-button" disabled={!clauses.length || !name.trim()} onClick={addRule}>将组合规则加入草稿</button>
    </div>
    <small>保存后用于后续命令审批。试算可查看解析出的目标和缺口；脚本内部行为不一定可见。</small>
  </fieldset>;
}
