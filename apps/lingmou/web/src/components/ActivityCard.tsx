import { explanationFor, riskRank, sourceLabel, summaryText } from "../activity";
import { policyEventNeedsAlert, policyIdsForEvent, policyOutcomeForEvent, type PolicyAlertOutcome } from "../policyAlerts";
import type { WorkbenchEvent } from "../types";
import { EventShell, RiskPill, SourceBadge } from "./CardPrimitives";
import { Icon, type IconName } from "./Icon";

const iconFor: Record<string, IconName> = {
  user_prompt: "user",
  agent_message: "agent",
  plan: "plan",
  reasoning_summary: "summary",
  approval_request: "attention",
  approval: "step",
  approval_required: "attention",
  policy_block: "shield",
  policy_decision: "shield",
  action_result: "shield",
  user_input_request: "question",
  user_input_response: "reply",
  turn: "step",
  error: "warning",
  warning: "warning",
};

const roleFor: Record<string, string> = {
  user_prompt: "你交给 Agent 的任务",
  agent_message: "Agent 公开回复",
  plan: "Agent 公开计划",
  reasoning_summary: "Agent 公开推理摘要",
  approval_request: "等待你的处理",
  approval: "系统处置",
  approval_required: "等待你的处理",
  policy_block: "安全策略处置",
  policy_decision: "策略独立判定",
  action_result: "策略处置结果",
  user_input_request: "等待你的补充",
  user_input_response: "你的补充",
  turn: "运行状态",
  error: "运行异常",
  warning: "运行提醒",
};

const policyOutcomeLabel: Record<PolicyAlertOutcome, string> = {
  blocked: "已阻断",
  review_required: "待复核",
  transformed: "已安全调整",
  detected: "已识别",
};

const policyOutcomeLevel: Record<PolicyAlertOutcome, string> = {
  blocked: "critical",
  review_required: "high",
  transformed: "warning",
  detected: "warning",
};

export function ActivityCard({
  event,
  selected,
  onSelect,
  onShowEvidence,
}: {
  event: WorkbenchEvent;
  selected: boolean;
  onSelect: () => void;
  onShowEvidence: () => void;
}) {
  const explanation = explanationFor(event);
  const text = summaryText(event.summary);
  const policyOutcome = policyOutcomeForEvent(event);
  const policyIssue = policyEventNeedsAlert(event);
  const security = ["approval_request", "approval_required", "approval", "policy_block", "error", "warning"].includes(event.kind) || policyIssue;
  const policyBlock = event.kind === "policy_block" ? explanation.policy_summary : undefined;
  const policyIds = policyIdsForEvent(event);
  const baseLevel = explanation.risk?.level || "normal";
  const minimumLevel = policyOutcome ? policyOutcomeLevel[policyOutcome] : "warning";
  const displayedLevel = riskRank(baseLevel) >= riskRank(minimumLevel) ? baseLevel : minimumLevel;
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload as Record<string, unknown>
    : {};
  const safeNextStep = typeof payload.safe_next_step === "string" ? payload.safe_next_step : policyBlock?.next_step;
  return (
    <EventShell event={event} selected={selected} icon={<Icon name={iconFor[event.kind] || "spark"} size={17} />} onSelect={onSelect}>
      <div className="activity-role">{roleFor[event.kind] || "Agent 活动"}</div>
      {text && <div className="message-content">{text}</div>}
      {security && (
        <div className={`security-summary risk-surface-${displayedLevel}`}>
          <div className="policy-id-row">
            <RiskPill level={displayedLevel} />
            {policyOutcome && <strong>{policyOutcomeLabel[policyOutcome]}</strong>}
            {policyIds.map((policyId) => <code key={policyId}>{policyId}</code>)}
          </div>
          {policyBlock ? (
            <>
              <p className="security-conclusion">{policyBlock.summary || explanation.description}</p>
              {explanation.result?.summary && <p className="security-result">处置结果：{explanation.result.summary}</p>}
              {safeNextStep && <p className="security-next-step">安全继续：{safeNextStep}</p>}
            </>
          ) : policyIssue ? (
            <>
              <p className="security-conclusion">{explanation.description || text}</p>
              {explanation.result?.summary && explanation.result.summary !== text && (
                <p className="security-result">处置结果：{explanation.result.summary}</p>
              )}
              {safeNextStep && <p className="security-next-step">安全继续：{safeNextStep}</p>}
            </>
          ) : (
            <>
              {(explanation.risk?.reasons || []).map((reason) => <p key={reason}>{reason}</p>)}
              {explanation.result?.summary && <p>{explanation.result.summary}</p>}
            </>
          )}
        </div>
      )}
      <div className="card-actions compact-actions">
        <SourceBadge source={explanation.sources?.[0] || event.source} />
        <button
          type="button"
          className="text-button"
          onClick={(clickEvent) => {
            clickEvent.stopPropagation();
            onShowEvidence();
          }}
        >{security ? "查看处置依据" : "查看详情"}</button>
      </div>
      {explanation.conservative_fallback && (
        <span className="visually-hidden">解释来源：{sourceLabel("conservative_fallback")}</span>
      )}
    </EventShell>
  );
}
