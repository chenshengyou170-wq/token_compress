import { useEffect, useState } from "react";
import {
  evidenceFor,
  evidenceLabel,
  explanationFor,
  hasSideEffects,
  rawCommand,
  riskLabel,
  sourceLabel,
  statusLabel,
} from "../activity";
import type { WorkbenchEvent, WorkbenchState } from "../types";
import { EffectsGrid, RiskPill, SourceBadge, StatusPill } from "./CardPrimitives";
import { PolicyTraceTree, tracesIn } from "./PolicyTraceTree";
import { Icon } from "./Icon";

type InspectorTab = "explanation" | "evidence" | "raw";

function DefaultInspector({
  state,
  recentFiles,
}: {
  state: WorkbenchState;
  recentFiles: string[];
}) {
  const step = state.task?.current_step;
  return (
    <div className="default-inspector">
      <section className="inspector-summary-card">
        <h3>当前步骤</h3>
        <strong className="inspector-step-title">{step?.title || "等待任务"}</strong>
        <p>{state.task?.goal || "输入任务后，这里会持续解释 Agent 当前在做什么。"}</p>
      </section>
      <section>
        <h3>正在运行的命令</h3>
        {state.task?.active_command ? (
          <div className="current-command">
            <strong>{state.task.active_command.headline}</strong>
            <code>{state.task.active_command.command}</code>
          </div>
        ) : <p className="muted-copy">当前没有运行中的命令。</p>}
      </section>
      <section>
        <h3>最近修改文件</h3>
        {recentFiles.length ? (
          <ul className="plain-list">{recentFiles.slice(0, 6).map((path) => <li key={path}>{path}</li>)}</ul>
        ) : <p className="muted-copy">本次任务还没有记录文件修改。</p>}
      </section>
      <section>
        <h3>待审批事项</h3>
        <p className={state.pending_interactions.length ? "attention-copy" : "muted-copy"}>
          {state.pending_interactions.length ? `${state.pending_interactions.length} 项操作等待你的决定。` : "当前没有待审批事项。"}
        </p>
      </section>
      <section className="reading-help">
        <h3>如何理解活动流</h3>
        <ol>
          <li>先看 Agent 的公开计划与目的。</li>
          <li>再看实际命令、工具和文件修改。</li>
          <li>结果与安全处置会附在同一步骤中。</li>
          <li>OS 事实只在真实采集后显示为“系统观察到”。</li>
        </ol>
      </section>
    </div>
  );
}

export function EvidenceInspector({
  event,
  state,
  recentFiles,
  initialTab,
  onClose,
}: {
  event: WorkbenchEvent | null;
  state: WorkbenchState;
  recentFiles: string[];
  initialTab?: InspectorTab;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<InspectorTab>(initialTab || "explanation");
  useEffect(() => setTab(initialTab || "explanation"), [event?.event_id, initialTab]);

  if (!event) {
    return (
      <div className="inspector-inner">
        <div className="inspector-heading">
          <div><h2>任务摘要</h2><p>当前活动解释</p></div>
          <button type="button" className="icon-button drawer-close" onClick={onClose} aria-label="关闭详情栏"><Icon name="close" /></button>
        </div>
        <DefaultInspector state={state} recentFiles={recentFiles} />
      </div>
    );
  }

  const explanation = explanationFor(event);
  const evidence = evidenceFor(event);
  const primarySource = explanation.purpose?.source || explanation.sources?.[0] || event.source;
  const sideEffectStatus = explanation.conservative_fallback
    ? "尚未确认"
    : hasSideEffects(explanation)
      ? "有或可能有"
      : "解析未发现";
  return (
    <div className="inspector-inner">
      <div className="inspector-heading">
        <div><h2>{explanation.headline || event.title}</h2><p>当前活动解释</p></div>
        <button type="button" className="icon-button drawer-close" onClick={onClose} aria-label="关闭详情栏"><Icon name="close" /></button>
      </div>
      <div className="inspector-pinned-facts">
        <StatusPill status={event.status} />
        <RiskPill level={explanation.risk?.level} />
        <span className="fact-chip">副作用：{sideEffectStatus}</span>
        <span className="fact-chip">来源：{sourceLabel(primarySource)}</span>
        <span className="fact-chip">证据：{evidenceLabel(evidence.completeness)}</span>
      </div>
      <div className="inspector-tabs" role="tablist" aria-label="活动详情">
        {([
          ["explanation", "解释"],
          ["evidence", "证据"],
          ["raw", "原始数据"],
        ] as Array<[InspectorTab, string]>).map(([key, label]) => (
          <button
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? "active" : ""}
            key={key}
            onClick={() => setTab(key)}
          >{label}</button>
        ))}
      </div>
      <div className="inspector-content">
        {tab === "explanation" && (
          <div className="inspector-explanation">
            <section><h3>它在做什么</h3><p>{explanation.description || event.title}</p></section>
            <section>
              <h3>为什么要做</h3>
              <p>{explanation.purpose?.text || "完成当前任务"}</p>
              <SourceBadge source={explanation.purpose?.source} />
            </section>
            <section><h3>影响哪些对象</h3><EffectsGrid effects={explanation.effects} /></section>
            <section className={`risk-detail risk-surface-${explanation.risk?.level || "low"}`}>
              <h3>风险与策略判断</h3>
              <p><strong>{riskLabel(explanation.risk?.level)}</strong> · 依据：{sourceLabel(explanation.risk?.basis)}</p>
              {(explanation.risk?.reasons || []).length
                ? <ul>{explanation.risk?.reasons?.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                : <p>没有登记额外风险原因。</p>}
            </section>
            <PolicyTraceTree traces={tracesIn(event)} />
            <section><h3>结果怎样</h3><p>{explanation.result?.summary || statusLabel(event.status)}</p></section>
          </div>
        )}
        {tab === "evidence" && (
          <div className="inspector-evidence">
            <div className={`evidence-availability availability-${evidence.availability || "unavailable"}`}>
              <strong>{evidenceLabel(evidence.availability)}</strong>
              <p>{evidence.summary || "暂无 OS 级证据"}</p>
            </div>
            {event.kind === "command" && (
              <section><h3>命令请求</h3><pre className="evidence-command">{rawCommand(event)}</pre></section>
            )}
            <section>
              <h3>{event.kind === "command" ? "系统实际观察到" : "已记录证据"}</h3>
              {evidence.observations?.length ? (
                <ol className="evidence-timeline">
                  {evidence.observations.map((observation, index) => (
                    <li key={`${observation.kind}:${observation.pid}:${index}`}>
                      <span className="evidence-check"><Icon name="step" size={17} /></span>
                      <div>
                        <strong>{observation.label || observation.kind}</strong>
                        <small>
                          {[observation.pid != null ? `PID ${observation.pid}` : "", observation.syscall, sourceLabel(observation.source)].filter(Boolean).join(" · ")}
                        </small>
                        {observation.file_path && <code>{observation.file_path}</code>}
                        {observation.network_target && <code>{observation.network_target}</code>}
                      </div>
                    </li>
                  ))}
                </ol>
              ) : <p className="muted-copy">暂无与该活动可靠关联的 OS 级证据。</p>}
              {evidence.negative_observations?.map((observation) => (
                <p className="negative-observation" key={observation.label}><Icon name="step" size={16} />{observation.label}</p>
              ))}
            </section>
            <section>
              <h3>关联信息</h3>
              <dl className="correlation-grid">
                <div><dt>Turn</dt><dd>{evidence.correlation?.turn_id || event.turn_id || "无"}</dd></div>
                <div><dt>Item</dt><dd>{evidence.correlation?.item_id || event.item_id || "无"}</dd></div>
                <div><dt>PID / PPID</dt><dd>{evidence.correlation?.pid ?? "无"} / {evidence.correlation?.ppid ?? "无"}</dd></div>
                <div><dt>关联置信度</dt><dd>{evidence.correlation?.confidence || "none"}</dd></div>
              </dl>
              {(event.item_id || evidence.correlation?.item_id) && (
                <a className="evidence-syscall-link" href={`#/syscalls?item_id=${encodeURIComponent(event.item_id || evidence.correlation?.item_id || "")}`}>
                  <Icon name="syscall" size={16} />查看关联系统调用
                </a>
              )}
            </section>
          </div>
        )}
        {tab === "raw" && (
          <div className="raw-inspector">
            <p>供调试和审计使用。普通判断请优先查看“解释”和“证据”。</p>
            <pre>{JSON.stringify(event, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
