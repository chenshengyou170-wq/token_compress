import { useEffect, useMemo, useRef, useState } from "react";
import { riskRank, sourceLabel } from "../activity";
import { incidentNarrative, type IncidentNarrative } from "../incidentNarrative";
import { policyAlertsForEvents, type PolicyAlert, type PolicyAlertOutcome } from "../policyAlerts";
import type { Interaction, WorkbenchEvent } from "../types";
import { RiskPill, SourceBadge } from "./CardPrimitives";
import { Icon } from "./Icon";

function useFocusTrap(active: boolean, onEscape?: () => void) {
  const ref = useRef<HTMLElement>(null);
  const escapeRef = useRef(onEscape);
  useEffect(() => { escapeRef.current = onEscape; }, [onEscape]);
  useEffect(() => {
    if (!active || !ref.current) return;
    const root = ref.current;
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const getFocusable = () => Array.from(root.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), summary, a[href], [tabindex]:not([tabindex='-1'])")).filter((node) => node.getClientRects().length > 0);
    const shell = document.querySelector<HTMLElement>(".product-shell");
    const wasInert = shell?.inert;
    const previousOverflow = document.body.style.overflow;
    if (shell) shell.inert = true;
    document.body.style.overflow = "hidden";
    (root.querySelector<HTMLElement>(".recommended, .policy-alert-actions button") || getFocusable()[0])?.focus();
    const keyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && escapeRef.current) {
        event.preventDefault();
        escapeRef.current();
        return;
      }
      const focusable = getFocusable();
      if (event.key !== "Tab" || !focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    root.addEventListener("keydown", keyDown);
    return () => {
      root.removeEventListener("keydown", keyDown);
      if (shell) shell.inert = wasInert || false;
      document.body.style.overflow = previousOverflow;
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, [active]);
  return ref;
}

function IncidentImpact({ incident, blocked = false, pending = true }: { incident: IncidentNarrative; blocked?: boolean; pending?: boolean }) {
  const stage = blocked ? "已截断" : pending ? "待确认" : "风险已识别";
  return <div className="incident-impact">
    <p className="incident-happened">{incident.happened}</p>
    <div className="incident-path" aria-label={`${incident.from}，${stage}，${incident.to}`}>
      <span><Icon name="file" size={18} /><strong>{incident.from}</strong></span>
      <span className={`incident-gate ${blocked ? "" : "incident-unconfirmed"}`}><Icon name={blocked ? "shield" : pending ? "pause" : "warning"} size={22} /><b>{stage}</b></span>
      <span><Icon name="network" size={18} /><strong>{incident.to}</strong></span>
    </div>
    {incident.facts?.length ? <dl className="incident-facts">{incident.facts.map((fact) => <div key={fact.label}><dt>{fact.label}</dt><dd>{fact.value}</dd></div>)}</dl> : null}
    <div className="incident-consequence"><h3>{blocked ? "未拦截的潜在后果" : pending ? "放行后的潜在后果" : "潜在后果"}</h3><p>{incident.consequence}</p></div>
  </div>;
}

function HighlightedCommand({ command }: { command: string }) {
  const pattern = /(https?:\/\/[^\s'";]+|@?[^\s'";]*(?:\.env|secret|credential|api[_-]?key)[^\s'";]*|\brm\b|\bunlink\b|--data-binary|--upload-file|-rf\b)/gi;
  const highlight = /^(?:https?:\/\/|@?[^\s'";]*(?:\.env|secret|credential|api[_-]?key)|rm$|unlink$|--data-binary$|--upload-file$|-rf$)/i;
  const parts = command.split(pattern);
  return (
    <code className="highlighted-command">
      {parts.map((part, index) => highlight.test(part)
        ? <mark key={`${part}:${index}`}>{part}</mark>
        : <span key={`${part}:${index}`}>{part}</span>)}
    </code>
  );
}

function ruleLabel(rule: unknown): string {
  if (typeof rule === "string") return rule;
  if (rule && typeof rule === "object") {
    const value = rule as Record<string, unknown>;
    return [value.rule_id || value.id || value.policy_id, value.reason || value.label].filter(Boolean).join("：") || JSON.stringify(rule);
  }
  return String(rule);
}

export function ApprovalDialog({
  interaction,
  busy,
  onDecision,
}: {
  interaction: Interaction;
  busy: boolean;
  onDecision: (decision: string) => void;
}) {
  const dialogRef = useFocusTrap(true);
  const explanation = interaction.explanation || {
    headline: "Agent 请求执行操作",
    description: interaction.reason || "系统无法完整判断该操作的副作用。",
    purpose: { text: interaction.reason || "完成当前任务", source: "contextual_inference" },
    effects: { reads: [], writes: [], network: [], processes: [] },
    risk: interaction.risk,
  };
  const risk = { ...interaction.risk, ...explanation.risk };
  const highRisk = riskRank(risk.level) >= 3;
  const effects = explanation.effects;
  const sensitiveReads = (effects?.reads || []).filter((path) => /(?:\.env|secret|credential|key)/i.test(path));
  const hasWriteOrNetwork = Boolean(effects?.writes?.length || effects?.network?.length);
  const rules = [
    ...(risk.matched_rules || []),
    ...(risk.blocking_rule ? [risk.blocking_rule] : []),
    ...(risk.policy_id ? [risk.policy_id] : []),
  ];
  const incident = incidentNarrative(rules.map((rule) => typeof rule === "string" ? rule : ruleLabel(rule).split("：")[0]), effects);
  return (
    <div className="modal-backdrop" role="presentation">
      <section
        ref={dialogRef}
        className={`decision-dialog risk-dialog-${risk.level || "warning"}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-title"
      >
        <header className="decision-header">
          <div>
            <h2 id="approval-title">{incident?.subject || `需要批准：${explanation.headline || "执行操作"}`}</h2>
            <p>操作正在等待批准 · 由你决定是否执行</p>
          </div>
          <RiskPill level={risk.level} />
        </header>
        {incident && <IncidentImpact incident={incident} />}
        <div className="decision-sections">
          <section>
            <h3>请求执行的操作</h3>
            <p>{explanation.description}</p>
            <p className="purpose-copy">目的：{explanation.purpose?.text || interaction.reason || "完成当前任务"}</p>
            <SourceBadge source={explanation.purpose?.source} />
          </section>
          <section>
            <h3>可能影响</h3>
            <ul className="impact-list">
              <li><span>敏感文件</span><strong>{sensitiveReads.length} 个</strong></li>
              <li><span>文件写入</span><strong>{effects?.writes?.length || 0} 个</strong></li>
              <li><span>外部网络目标</span><strong>{effects?.network?.length || 0} 个</strong></li>
              {(effects?.network?.length || 0) > 0 && <li className="impact-warning">数据可能离开当前工作区</li>}
            </ul>
            {[...(effects?.reads || []), ...(effects?.writes || []), ...(effects?.network || [])].length > 0 && (
              <div className="impact-targets">
                {[...(effects?.reads || []), ...(effects?.writes || []), ...(effects?.network || [])].map((target) => <code key={target}>{target}</code>)}
              </div>
            )}
          </section>
          <section>
            <h3>审批原因</h3>
            <p>{interaction.reason || (hasWriteOrNetwork ? "该操作可能修改文件或访问网络，超出自动执行范围。" : "当前审批策略要求你确认该操作。")}</p>
            {(risk.reasons || []).length > 0 && <ul className="risk-reason-list">{risk.reasons?.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
            {rules.length > 0 && (
              <div className="rule-list">
                {rules.map((rule, index) => <code key={`${ruleLabel(rule)}:${index}`}>{ruleLabel(rule)}</code>)}
              </div>
            )}
            <small>判断依据：{sourceLabel(risk.basis || explanation.sources?.[0])}</small>
          </section>
          <section className="decision-outcome">
            <h3>批准与拒绝的结果</h3>
            <div><strong>允许一次</strong><p>本次操作继续执行，后续同类操作仍会再次询问。</p></div>
            <div><strong>拒绝</strong><p>本次操作不会执行，Agent 可以调整方案继续处理。</p></div>
          </section>
        </div>
        {interaction.command && (
          <details className="raw-command-details">
            <summary>查看原始命令</summary>
            <HighlightedCommand command={interaction.command} />
          </details>
        )}
        {!interaction.command && interaction.file_changes != null && (
          <details className="raw-command-details"><summary>查看原始文件变更</summary><pre>{JSON.stringify(interaction.file_changes, null, 2)}</pre></details>
        )}
        {highRisk && <div className="system-recommendation">系统建议：拒绝</div>}
        <footer className="decision-actions">
          <button type="button" className={highRisk ? "danger-button recommended" : "danger-button"} onClick={() => onDecision("decline")} disabled={busy}>{highRisk ? "阻止本次操作" : "拒绝"}</button>
          {!highRisk && (interaction.choices?.includes("acceptForSession") ?? true) && (
            <button type="button" className="secondary-button" onClick={() => onDecision("acceptForSession")} disabled={busy}>本会话允许</button>
          )}
          <button
            type="button"
            className={highRisk ? "secondary-button" : hasWriteOrNetwork ? "primary-button recommended" : "primary-button"}
            onClick={() => onDecision("accept")}
            disabled={busy}
          >仅允许一次</button>
          <button type="button" className="cancel-turn-button" onClick={() => onDecision("cancel")} disabled={busy}>拒绝并停止当前回合</button>
        </footer>
      </section>
    </div>
  );
}

const OUTCOME_COPY: Record<PolicyAlertOutcome, {
  label: string;
  statement: string;
  resultHeading: string;
}> = {
  blocked: { label: "已阻断", statement: "策略已阻止这项风险操作", resultHeading: "处置结果" },
  review_required: { label: "待复核", statement: "操作已暂停，等待人工复核", resultHeading: "当前状态" },
  transformed: { label: "已安全调整", statement: "原始风险参数没有被原样执行", resultHeading: "调整结果" },
  detected: { label: "已识别", statement: "策略发现风险信号并已发出告警", resultHeading: "检测结果" },
};

function policyModeLabel(mode?: string): string {
  return {
    deny: "阻断",
    block: "阻断",
    blocked: "阻断",
    review: "复核",
    review_required: "复核",
    transform: "转换",
    transformed: "转换",
    observe: "观测",
    observed: "观测",
    detect: "检测",
    detected: "检测",
  }[mode || ""] || mode || "已命中";
}

export function PolicyAlertDialog({
  alert,
  onDismiss,
}: {
  alert: PolicyAlert;
  onDismiss: () => void;
}) {
  const dialogRef = useFocusTrap(true, onDismiss);
  const observations = alert.evidence.observations || [];
  const copy = OUTCOME_COPY[alert.outcome];
  const blockedBeforeExecution = alert.outcome === "blocked" && alert.executorStarted === false;
  const icon = alert.outcome === "blocked" ? "shield" : "warning";
  const incident = incidentNarrative(alert.policies.map((policy) => policy.id), alert.sourceEvent.explanation?.effects, alert.businessImpact);
  const statement = blockedBeforeExecution ? incident?.blockedStatement || "操作没有进入执行阶段" : copy.statement;
  const incidentTitle = incident ? `${blockedBeforeExecution ? "已拦住" : alert.outcome === "review_required" ? "请确认" : "发现风险"}：${incident.subject}` : alert.title;
  const nextStep = incident?.nextStep || (incident && alert.policies.some((policy) => policy.id === "WORK-PROCURE-007")
    ? "先核对首张采购单和当前库存；确需追加时，再确认新的采购数量。" : alert.nextStep);
  return (
    <div className={`modal-backdrop policy-alert-backdrop policy-alert-backdrop-${alert.outcome}`} role="presentation">
      <section
        ref={dialogRef}
        className={`decision-dialog policy-alert-dialog policy-alert-${alert.outcome}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="policy-alert-title"
        aria-describedby="policy-alert-summary"
      >
        <header className="decision-header">
          <div className="policy-alert-heading">
            <span className="policy-alert-icon" aria-hidden="true"><Icon name={icon} size={21} /></span>
            <div>
              <h2 id="policy-alert-title">{incidentTitle}</h2>
              <p>{alert.policies.length ? `${alert.policies.length} 条策略命中` : "策略问题已确认"} · {copy.label}<RiskPill level={alert.level} /></p>
            </div>
          </div>
        </header>
        {incident && <IncidentImpact incident={incident} blocked={blockedBeforeExecution} pending={alert.outcome === "review_required"} />}
        <div id="policy-alert-summary" className="policy-alert-statement">
          <strong>{statement}</strong>
          <p>{incident ? alert.resultSummary : alert.summary}</p>
        </div>
        <section className={`policy-alert-resolution ${incident ? "incident-resolution" : ""}`}>
          {!incident && <div><h3>{copy.resultHeading}</h3><p>{alert.resultSummary}</p></div>}
          <div><h3>建议操作</h3><p>{nextStep}</p></div>
        </section>
        <details className="policy-alert-policies">
          <summary>查看命中策略{alert.policies.length ? `（${alert.policies.length}）` : ""}</summary>
          <ul>
            {alert.policies.length ? alert.policies.map((policy) => (
              <li key={policy.id}>
                <div className="policy-alert-policy-title">
                  <code>{policy.id}</code>
                  {policy.name && <strong>{policy.name}</strong>}
                  <span>{policyModeLabel(policy.mode || policy.result)}</span>
                </div>
                {policy.reason && <p>{policy.reason}</p>}
                {policy.evidenceSummary && <small>判定证据：{policy.evidenceSummary}</small>}
              </li>
            )) : (
              <li><p>策略标识未随旧事件保存，请在活动流中查看原始记录。</p></li>
            )}
          </ul>
        </details>
        <details className="policy-alert-technical-details">
          <summary>查看策略命中与技术明细{observations.length ? `（${observations.length} 条证据）` : ""}</summary>
          <div>
            <ul className="policy-alert-evidence-list">
              {observations.length
                ? observations.map((observation, index) => (
                  <li key={`${observation.kind || "evidence"}:${index}`}>
                    <Icon name="step" size={17} />
                    <span>{observation.label || observation.kind || "策略证据已记录"}</span>
                  </li>
                ))
                : <li><Icon name="step" size={17} /><span>策略决策事件与关联标识已写入本次运行证据。</span></li>}
            </ul>
            <SourceBadge source={alert.sourceEvent.source} />
          </div>
        </details>
        {alert.actionSummary && (
          <details className="raw-command-details">
            <summary>查看关联动作</summary>
            <HighlightedCommand command={alert.actionSummary} />
          </details>
        )}
        <footer className="decision-actions policy-alert-actions">
          <button type="button" className="primary-button" onClick={onDismiss}>知道了，返回活动流</button>
        </footer>
      </section>
    </div>
  );
}

export function BlockedDialog({ event, onDismiss }: { event: WorkbenchEvent; onDismiss: () => void }) {
  const alert = policyAlertsForEvents([event])[0];
  return alert ? <PolicyAlertDialog alert={alert} onDismiss={onDismiss} /> : null;
}

export function UserInputDialog({
  interaction,
  busy,
  onSubmit,
}: {
  interaction: Interaction;
  busy: boolean;
  onSubmit: (answers: Record<string, string>) => void;
}) {
  const dialogRef = useFocusTrap(true);
  const [values, setValues] = useState<Record<string, string>>({});
  const complete = useMemo(
    () => (interaction.questions || []).every((question) => Boolean(values[question.id]?.trim())),
    [interaction.questions, values],
  );
  return (
    <div className="modal-backdrop" role="presentation">
      <section ref={dialogRef} className="decision-dialog user-input-dialog" role="dialog" aria-modal="true" aria-labelledby="question-title">
        <header className="decision-header"><div><h2 id="question-title">请回答后继续</h2><p>Agent 需要补充信息</p></div></header>
        {(interaction.questions || []).map((question) => (
          <label className="question-field" key={question.id}>
            <strong>{question.header || question.question}</strong>
            {question.header && <span>{question.question}</span>}
            <input
              type={question.isSecret ? "password" : "text"}
              value={values[question.id] || ""}
              onChange={(event) => setValues((current) => ({ ...current, [question.id]: event.target.value }))}
              list={`options-${question.id}`}
            />
            <datalist id={`options-${question.id}`}>{question.options?.map((option) => <option key={option.label} value={option.label} />)}</datalist>
          </label>
        ))}
        <footer className="decision-actions"><button type="button" className="primary-button" onClick={() => onSubmit(values)} disabled={busy || !complete}>提交回答</button></footer>
      </section>
    </div>
  );
}
