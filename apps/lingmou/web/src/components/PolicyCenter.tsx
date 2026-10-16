import { Fragment, useMemo, useState } from "react";
import { explanationFor } from "../activity";
import type { PolicyCatalog, PolicyCatalogEntry, WorkbenchEvent } from "../types";
import { PolicyEditor } from "./PolicyEditor";
import { Icon } from "./Icon";

const levelLabel: Record<string, string> = {
  notice: "提示",
  warning: "警告",
  high: "高风险",
  critical: "严重",
};

const modeLabel: Record<string, string> = {
  observe: "静默记录",
  review: "随原审批复核",
  deny: "执行前阻断",
  transform: "处理内容",
};

const stageLabel: Record<string, string> = {
  kernel_filesystem: "文件访问时",
  pre_execution_approval: "命令执行前",
  pre_execution_file_approval: "文件变更前",
  command_lifecycle: "命令生命周期",
  runtime_observation: "运行时观测",
  post_execution_observation: "执行后观测",
  tool_before: "工具调用前",
  tool_after: "工具返回后",
  llm_before: "输入模型前",
};

const resultLabel: Record<string, string> = {
  observed: "已静默记录",
  detected: "已检测",
  review: "已附加复核",
  review_required: "需要重新确认",
  baseline_created: "已建立基线",
  blocked: "已阻断",
};

type PolicyDecision = {
  policy_id?: string;
  policy_name?: string;
  level?: string;
  mode?: string;
  stage?: string;
  result?: string;
  reason?: string;
  blocking?: boolean;
  evidence_source?: string;
};

type PolicyOccurrence = {
  policyId: string;
  event: WorkbenchEvent;
  decision: PolicyDecision | null;
};

function explicitDecision(event: WorkbenchEvent): PolicyDecision | null {
  if (event.kind !== "policy_decision" || !event.payload || typeof event.payload !== "object") return null;
  const decision = (event.payload as Record<string, unknown>).decision;
  return decision && typeof decision === "object" ? decision as PolicyDecision : null;
}

function eventRuleIds(event: WorkbenchEvent): string[] {
  const decision = explicitDecision(event);
  if (decision?.policy_id) return [decision.policy_id];
  const risk = explanationFor(event).risk;
  const ids = new Set<string>();
  if (risk?.blocking_rule) ids.add(risk.blocking_rule);
  if (risk?.policy_id) ids.add(risk.policy_id);
  for (const value of risk?.matched_rules || []) {
    if (typeof value === "string") ids.add(value);
    if (value && typeof value === "object" && "id" in value) ids.add(String(value.id));
  }
  for (const observation of event.evidence?.observations || []) {
    if (observation.blocking_rule) ids.add(observation.blocking_rule);
    if (observation.policy_id) ids.add(observation.policy_id);
    for (const value of observation.matched_rules || []) {
      if (typeof value === "string") ids.add(value);
      if (value && typeof value === "object" && "id" in value) ids.add(String(value.id));
    }
  }
  return [...ids];
}

function policyOccurrences(events: WorkbenchEvent[]): Map<string, PolicyOccurrence[]> {
  const explicit = new Map<string, PolicyOccurrence>();
  const legacy = new Map<string, PolicyOccurrence>();
  for (const event of events) {
    const decision = explicitDecision(event);
    const ids = eventRuleIds(event);
    for (const id of ids) {
      const subject = event.item_id || event.event_id;
      const key = `${id}:${subject}`;
      const target = decision ? explicit : legacy;
      const previous = target.get(key);
      if (!previous || previous.event.seq <= event.seq) target.set(key, { policyId: id, event, decision });
    }
  }
  const grouped = new Map<string, PolicyOccurrence[]>();
  for (const [key, occurrence] of legacy) {
    if (!explicit.has(key)) explicit.set(key, occurrence);
  }
  for (const occurrence of explicit.values()) {
    const id = occurrence.policyId;
    if (!id) continue;
    const current = grouped.get(id) || [];
    current.push(occurrence);
    grouped.set(id, current);
  }
  for (const current of grouped.values()) current.sort((a, b) => b.event.seq - a.event.seq);
  return grouped;
}

function formatTime(seconds: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(seconds * 1000));
}

function testedLabel(value: string): string {
  return {
    real_upstream: "真实上游验收",
    local: "本地场景测试",
    unverified: "待补验收",
  }[value] || value;
}

export function PolicyCenter({ catalog, events, onCatalogChange }: { catalog: PolicyCatalog | null; events: WorkbenchEvent[]; onCatalogChange?: (catalog: PolicyCatalog) => void }) {
  const [activeGroup, setActiveGroup] = useState("all");
  const [search, setSearch] = useState("");
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null);
  const occurrences = useMemo(() => policyOccurrences(events), [events]);
  const groups = catalog?.groups || [];
  const visibleGroups = groups
    .filter((group) => activeGroup === "all" || group.id === activeGroup)
    .map((group) => ({
      ...group,
      policies: group.policies.filter((policy) => {
        const needle = search.trim().toLocaleLowerCase("zh-CN");
        return !needle || `${policy.id} ${policy.name} ${policy.action} ${policy.stage === "kernel_filesystem" ? "拒绝访问" : modeLabel[policy.mode] || policy.mode}`.toLocaleLowerCase("zh-CN").includes(needle);
      }),
    }))
    .filter((group) => group.policies.length > 0);
  const shown = visibleGroups.reduce((total, group) => total + group.policies.length, 0);

  return (
    <main className="policy-center">
      <header className="policy-center-header">
        <div><h1>策略中心</h1><p>查看每条保护规则的执行阶段、用户影响和本次运行回放。</p></div>
        <div className="policy-health"><span><Icon name="shield" size={20} /></span><div><strong>{catalog ? `${catalog.total} 项策略已加载` : "正在读取策略"}</strong><small>逐条保存命中与处置，不保存敏感正文</small></div></div>
      </header>

      <PolicyEditor onSaved={onCatalogChange} />

      <section className="policy-toolbar" aria-label="策略筛选">
        <div className="policy-tabs" role="tablist" aria-label="策略分组">
          <button type="button" role="tab" aria-selected={activeGroup === "all"} className={activeGroup === "all" ? "active" : ""} onClick={() => setActiveGroup("all")}>全部 <em>{catalog?.total || 0}</em></button>
          {groups.map((group) => (
            <button type="button" role="tab" key={group.id} aria-selected={activeGroup === group.id} className={activeGroup === group.id ? "active" : ""} onClick={() => setActiveGroup(group.id)}>{group.name} <em>{group.policies.length}</em></button>
          ))}
        </div>
        <label className="policy-search"><span className="visually-hidden">搜索策略</span><Icon name="search" size={17} /><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索编号、名称、处置或模式" /></label>
      </section>

      <div className="policy-content">
        {!catalog && <div className="policy-loading"><span /><strong>正在读取本机策略包…</strong></div>}
        {catalog && !shown && <div className="policy-empty"><Icon name="search" size={24} /><strong>没有匹配的策略</strong><p>换一个关键词或分组后再试。</p></div>}
        {visibleGroups.map((group) => (
          <section className="policy-group" key={group.id} aria-labelledby={`policy-group-${group.id}`}>
            <header><div><h2 id={`policy-group-${group.id}`}>{group.name}</h2><p>{group.description}</p></div><span>{group.policies.length} 项策略</span></header>
            <div className="policy-table" role="table" aria-label={`${group.name}策略列表`}>
              <div className="policy-table-head" role="row"><span role="columnheader">策略</span><span role="columnheader">风险等级</span><span role="columnheader">系统处置</span><span role="columnheader">本次运行</span></div>
              {group.policies.map((policy: PolicyCatalogEntry) => {
                const replay = occurrences.get(policy.id) || [];
                const expanded = expandedPolicy === policy.id;
                return (
                  <Fragment key={policy.id}>
                    <div className={`policy-row ${expanded ? "expanded" : ""}`} role="row">
                      <span className="policy-identity" role="cell"><code>{policy.id}</code><strong>{policy.name}</strong><small>{policy.stateful ? "跨步骤状态" : "单事件判断"} · {testedLabel(policy.tested)}</small></span>
                      <span role="cell"><em className={`policy-level level-${policy.risk_level}`}>{levelLabel[policy.risk_level] || policy.risk_level}</em></span>
                      <span className="policy-action" role="cell"><span>{policy.action}</span><small><em className={`policy-mode mode-${policy.mode}`}>{policy.stage === "kernel_filesystem" ? "拒绝访问" : modeLabel[policy.mode] || policy.mode}</em>{stageLabel[policy.stage] || policy.stage}{!policy.enforceable_now ? " · 当前仅观测" : ""}</small></span>
                      <span className="policy-hit" role="cell">
                        {replay.length ? (
                          <button type="button" aria-expanded={expanded} onClick={() => setExpandedPolicy(expanded ? null : policy.id)}>{replay.length} 次命中 <Icon className="policy-hit-chevron" name="chevronDown" size={13} /></button>
                        ) : <small>未命中</small>}
                      </span>
                    </div>
                    {expanded && (
                      <div className="policy-replay" role="row">
                        <div role="cell">
                          <header><strong>{policy.name} · 最近回放</strong><span>同一 Agent Item 只计一次</span></header>
                          <ol>
                            {replay.slice(0, 8).map(({ event, decision }) => {
                              const result = decision?.result || (event.status === "blocked" ? "blocked" : "observed");
                              const reason = decision?.reason || explanationFor(event).risk?.reasons?.[0] || "策略命中已记录";
                              const stage = decision?.stage || explanationFor(event).risk?.policy_stage || policy.stage;
                              return (
                                <li key={event.event_id}>
                                  <time dateTime={new Date(event.occurred_at * 1000).toISOString()}>{formatTime(event.occurred_at)}</time>
                                  <em className={`policy-result result-${result}`}>{resultLabel[result] || result}</em>
                                  <span><strong>{reason}</strong><small>{stageLabel[stage] || stage} · {decision?.evidence_source || policy.evidence_source}</small></span>
                                  {event.item_id && <a href={`#/workbench?item_id=${encodeURIComponent(event.item_id)}`}>查看关联活动</a>}
                                </li>
                              );
                            })}
                          </ol>
                          {replay.length > 8 && <p>另有 {replay.length - 8} 条较早记录，可在调查回放中按关联活动查看。</p>}
                        </div>
                      </div>
                    )}
                  </Fragment>
                );
              })}
            </div>
          </section>
        ))}
      </div>
    </main>
  );
}
