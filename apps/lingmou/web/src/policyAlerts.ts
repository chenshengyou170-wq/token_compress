import type { ActivityEvidence, WorkbenchEvent } from "./types";

export type PolicyAlertOutcome = "blocked" | "review_required" | "transformed" | "detected";

export type PolicyAlertPolicy = {
  id: string;
  name?: string;
  level?: string;
  mode?: string;
  result?: string;
  reason?: string;
  evidenceSummary?: string;
};

export type PolicyAlert = {
  id: string;
  eventIds: string[];
  subjectId: string;
  firstSeq: number;
  lastSeq: number;
  occurredAt: number;
  outcome: PolicyAlertOutcome;
  level: string;
  title: string;
  summary: string;
  resultSummary: string;
  nextStep: string;
  actionSummary?: string;
  executorStarted?: boolean;
  businessImpact?: Record<string, unknown>;
  policies: PolicyAlertPolicy[];
  evidence: ActivityEvidence;
  sourceEvent: WorkbenchEvent;
  coveredByApproval: boolean;
};

type UnknownRecord = Record<string, unknown>;

const OUTCOME_RANK: Record<PolicyAlertOutcome, number> = {
  detected: 1,
  transformed: 2,
  review_required: 3,
  blocked: 4,
};

const LEVEL_RANK: Record<string, number> = {
  low: 0,
  normal: 0,
  notice: 1,
  warning: 2,
  medium: 2,
  high: 3,
  critical: 4,
};

const NON_ALERT_RESULTS = new Set([
  "allow",
  "allowed",
  "approved",
  "baseline_created",
  "completed",
  "executed",
  "not_matched",
  "success",
]);

function record(value: unknown): UnknownRecord | null {
  return value != null && typeof value === "object" && !Array.isArray(value)
    ? value as UnknownRecord
    : null;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === "string" && item.trim()) return [item.trim()];
    const itemRecord = record(item);
    const id = itemRecord?.policy_id || itemRecord?.rule_id || itemRecord?.id;
    return typeof id === "string" && id.trim() ? [id.trim()] : [];
  });
}

function text(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (value == null) return "";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function evidenceText(value: unknown): string | undefined {
  const evidence = record(value);
  if (!evidence) return undefined;
  const entries = Object.entries(evidence).filter(([, item]) => item != null && item !== "");
  if (!entries.length) return undefined;
  return entries.map(([key, item]) => `${key}=${text(item)}`).join(" · ");
}

function explicitDecision(event: WorkbenchEvent): UnknownRecord | null {
  const payload = record(event.payload);
  return record(payload?.decision);
}

function policySummary(event: WorkbenchEvent): UnknownRecord | null {
  return record(event.explanation?.policy_summary);
}

function normalizeOutcome(value: unknown): PolicyAlertOutcome | null {
  const normalized = String(value || "").trim().toLocaleLowerCase("en-US");
  if (!normalized || NON_ALERT_RESULTS.has(normalized)) return null;
  if (["block", "blocked", "deny", "denied"].includes(normalized)) return "blocked";
  if (["review", "review_required", "pending"].includes(normalized)) return "review_required";
  if (["transform", "transformed"].includes(normalized)) return "transformed";
  if (["detect", "detected", "observe", "observed", "warning"].includes(normalized)) return "detected";
  return null;
}

export function policyIdsForEvent(event: WorkbenchEvent): string[] {
  const payload = record(event.payload);
  const decision = explicitDecision(event);
  const summary = policySummary(event);
  const risk = event.explanation?.risk;
  const ids = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === "string" && value.trim()) ids.add(value.trim());
  };

  add(decision?.policy_id);
  add(payload?.policy_id);
  add(summary?.policy_id);
  add(risk?.policy_id);
  add(risk?.blocking_rule);
  strings(payload?.policy_ids).forEach(add);
  strings(risk?.matched_rules).forEach(add);
  for (const observation of event.evidence?.observations || []) {
    add(observation.policy_id);
    add(observation.blocking_rule);
    strings(observation.matched_rules).forEach(add);
  }
  return [...ids];
}

export function policyOutcomeForEvent(event: WorkbenchEvent): PolicyAlertOutcome | null {
  if (event.kind === "policy_block") return "blocked";

  const payload = record(event.payload);
  const decision = explicitDecision(event);
  const policyIds = policyIdsForEvent(event);
  if (event.kind === "action_result") {
    if (!policyIds.length) return null;
    return normalizeOutcome(payload?.status || event.status || event.explanation?.result?.status);
  }

  if (event.kind !== "policy_decision") {
    return event.status === "blocked" && policyIds.length ? "blocked" : null;
  }

  if (decision?.matched === false) return null;
  const explicitResult = decision?.result || payload?.result;
  if (NON_ALERT_RESULTS.has(String(explicitResult || "").toLocaleLowerCase("en-US"))) return null;
  const outcome = normalizeOutcome(
    explicitResult
      || event.status
      || decision?.mode
      || payload?.mode
      || event.explanation?.risk?.policy_mode,
  );
  if (outcome) return outcome;

  const level = String(decision?.level || event.explanation?.risk?.level || "normal").toLocaleLowerCase("en-US");
  return policyIds.length && (LEVEL_RANK[level] || 0) >= LEVEL_RANK.warning ? "detected" : null;
}

export function policyEventNeedsAlert(event: WorkbenchEvent): boolean {
  return policyOutcomeForEvent(event) != null;
}

function eventSubject(event: WorkbenchEvent): string {
  const payload = record(event.payload);
  return text(payload?.action_id) || event.item_id || event.event_id;
}

function policyRecords(event: WorkbenchEvent): PolicyAlertPolicy[] {
  const payload = record(event.payload);
  const decision = explicitDecision(event);
  const summary = policySummary(event);
  const risk = event.explanation?.risk;
  const records = new Map<string, PolicyAlertPolicy>();

  const add = (policy: PolicyAlertPolicy) => {
    if (!policy.id) return;
    const current = records.get(policy.id);
    records.set(policy.id, {
      id: policy.id,
      name: policy.name || current?.name,
      level: policy.level || current?.level,
      mode: policy.mode || current?.mode,
      result: policy.result || current?.result,
      reason: policy.reason || current?.reason,
      evidenceSummary: policy.evidenceSummary || current?.evidenceSummary,
    });
  };

  if (decision?.policy_id) {
    add({
      id: text(decision.policy_id),
      name: text(decision.policy_name) || undefined,
      level: text(decision.level) || undefined,
      mode: text(decision.mode) || undefined,
      result: text(decision.result) || undefined,
      reason: text(decision.reason) || undefined,
      evidenceSummary: evidenceText(decision.evidence),
    });
  }
  if (payload?.policy_id) {
    add({
      id: text(payload.policy_id),
      level: risk?.level,
      mode: text(payload.mode) || risk?.policy_mode,
      result: event.status,
      reason: text(payload.reason) || text(event.summary) || undefined,
      evidenceSummary: evidenceText(payload.evidence),
    });
  }
  if (summary?.policy_id) {
    add({
      id: text(summary.policy_id),
      name: text(summary.policy_name) || undefined,
      level: risk?.level,
      mode: risk?.policy_mode,
      result: event.status,
      reason: text(summary.reason) || text(summary.summary) || undefined,
    });
  }
  for (const id of policyIdsForEvent(event)) {
    add({ id, level: risk?.level, mode: risk?.policy_mode, result: event.status });
  }
  return [...records.values()];
}

function strongestOutcome(events: WorkbenchEvent[]): PolicyAlertOutcome {
  const canonical = [...events].reverse().find((event) => {
    const outcome = policyOutcomeForEvent(event);
    return outcome && (event.kind === "policy_block" || event.kind === "action_result");
  });
  if (canonical) return policyOutcomeForEvent(canonical)!;
  return events.reduce<PolicyAlertOutcome>((strongest, event) => {
    const outcome = policyOutcomeForEvent(event) || "detected";
    return OUTCOME_RANK[outcome] > OUTCOME_RANK[strongest] ? outcome : strongest;
  }, "detected");
}

function strongestLevel(events: WorkbenchEvent[], outcome: PolicyAlertOutcome): string {
  const fallback = outcome === "blocked" ? "critical" : outcome === "detected" ? "warning" : "high";
  return events.reduce((strongest, event) => {
    const decision = explicitDecision(event);
    const level = String(decision?.level || event.explanation?.risk?.level || "normal").toLocaleLowerCase("en-US");
    return (LEVEL_RANK[level] || 0) > (LEVEL_RANK[strongest] || 0) ? level : strongest;
  }, fallback);
}

function defaultTitle(outcome: PolicyAlertOutcome): string {
  return {
    blocked: "危险操作已阻断",
    review_required: "策略要求人工复核",
    transformed: "风险操作已安全调整",
    detected: "发现需要关注的策略风险",
  }[outcome];
}

function defaultNextStep(outcome: PolicyAlertOutcome): string {
  return {
    blocked: "核对命中策略和当前业务状态，缩小操作范围后再试。",
    review_required: "确认影响范围后，只对当前动作作出一次性决定。",
    transformed: "核对安全调整后的实际结果，再决定是否继续后续步骤。",
    detected: "查看策略原因和证据，确认该动作是否需要停止或收窄。",
  }[outcome];
}

function uniqueObservations(events: WorkbenchEvent[]): NonNullable<ActivityEvidence["observations"]> {
  const seen = new Set<string>();
  const result: NonNullable<ActivityEvidence["observations"]> = [];
  for (const event of events) {
    for (const observation of event.evidence?.observations || []) {
      const key = `${observation.kind || "evidence"}:${observation.label || ""}:${observation.policy_id || ""}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push(observation);
      }
    }
  }
  return result;
}

function mergePolicies(events: WorkbenchEvent[]): PolicyAlertPolicy[] {
  const merged = new Map<string, PolicyAlertPolicy>();
  for (const event of events) {
    for (const policy of policyRecords(event)) {
      const current = merged.get(policy.id);
      const currentLevel = current?.level || "normal";
      const candidateLevel = policy.level || "normal";
      merged.set(policy.id, {
        id: policy.id,
        name: policy.name || current?.name,
        level: (LEVEL_RANK[candidateLevel] || 0) > (LEVEL_RANK[currentLevel] || 0)
          ? policy.level
          : current?.level || policy.level,
        mode: policy.mode || current?.mode,
        result: policy.result || current?.result,
        reason: policy.reason || current?.reason,
        evidenceSummary: policy.evidenceSummary || current?.evidenceSummary,
      });
    }
  }
  return [...merged.values()].sort((left, right) => left.id.localeCompare(right.id));
}

function booleanAt(value: unknown, key: string): boolean | undefined {
  const target = record(value)?.[key];
  return typeof target === "boolean" ? target : undefined;
}

function actionSummaryForEvent(event: WorkbenchEvent): string {
  const payload = record(event.payload);
  const subject = record(payload?.subject);
  return text(subject?.summary)
    || text(payload?.action_summary)
    || (event.kind === "policy_block" ? text(event.summary) : "");
}

export function policyAlertsForEvents(events: WorkbenchEvent[]): PolicyAlert[] {
  const groups = new Map<string, WorkbenchEvent[]>();
  const allBySubject = new Map<string, WorkbenchEvent[]>();
  for (const event of events) {
    const subject = eventSubject(event);
    const all = allBySubject.get(subject) || [];
    all.push(event);
    allBySubject.set(subject, all);
    if (!policyEventNeedsAlert(event)) continue;
    const group = groups.get(subject) || [];
    group.push(event);
    groups.set(subject, group);
  }

  const alerts: PolicyAlert[] = [];
  for (const [subjectId, rawEvents] of groups) {
    const groupedEvents = [...rawEvents].sort((left, right) => left.seq - right.seq);
    const outcome = strongestOutcome(groupedEvents);
    const canonical = [...groupedEvents].reverse().find((event) => {
      const candidate = policyOutcomeForEvent(event);
      return candidate === outcome && (event.kind === "policy_block" || event.kind === "action_result");
    }) || [...groupedEvents].reverse().find((event) => policyOutcomeForEvent(event) === outcome) || groupedEvents.at(-1)!;
    const payload = record(canonical.payload);
    const summary = policySummary(canonical);
    // The video-era gateway stored trading metrics on the policy decision;
    // newer gateways also copy them into the final action result. Only carry
    // numeric evidence from this exact action, never infer pause/execution state.
    const tradingEvidence: UnknownRecord = {};
    for (const event of groupedEvents) {
      if (!policyIdsForEvent(event).includes("WORK-SOURCE-CHURN-018")) continue;
      const evidence = record(explicitDecision(event)?.evidence) || record(record(event.payload)?.evidence);
      for (const key of ["churn_anomaly_score", "churn_score_threshold", "commission_yuan", "fill_count", "turnover_yuan"]) {
        if (evidence && key in evidence) tradingEvidence[key] = evidence[key];
      }
    }
    const businessImpact = { ...tradingEvidence, ...record(payload?.business_impact) };
    const policies = mergePolicies(groupedEvents);
    const actionSummary = groupedEvents.map(actionSummaryForEvent).find(Boolean) || "";
    const policyReasons = policies.map((policy) => policy.reason).filter(Boolean).join("；");
    const eventSummary = text(canonical.summary);
    const resultSummary = text(canonical.explanation?.result?.summary)
      || text(payload?.summary)
      || eventSummary
      || policyReasons;
    const description = text(summary?.summary)
      || text(canonical.explanation?.description)
      || policyReasons
      || eventSummary
      || resultSummary;
    const executorStarted = booleanAt(businessImpact, "executor_started")
      ?? (canonical.kind === "policy_block" ? false : undefined);
    const related = allBySubject.get(subjectId) || [];

    alerts.push({
      id: `policy-alert:${subjectId}`,
      eventIds: groupedEvents.map((event) => event.event_id),
      subjectId,
      firstSeq: groupedEvents[0].seq,
      lastSeq: groupedEvents.at(-1)!.seq,
      occurredAt: canonical.occurred_at,
      outcome,
      level: strongestLevel(groupedEvents, outcome),
      title: canonical.kind === "policy_block"
        ? text(canonical.explanation?.headline) || defaultTitle(outcome)
        : defaultTitle(outcome),
      summary: description || defaultTitle(outcome),
      resultSummary: resultSummary || description || defaultTitle(outcome),
      nextStep: text(payload?.safe_next_step) || text(summary?.next_step) || defaultNextStep(outcome),
      actionSummary: actionSummary && actionSummary !== description ? actionSummary : undefined,
      executorStarted,
      businessImpact: businessImpact || undefined,
      policies,
      evidence: {
        ...(canonical.evidence || {}),
        observations: uniqueObservations(groupedEvents),
      },
      sourceEvent: canonical,
      coveredByApproval: related.some((event) => [
        "approval_request",
        "approval_required",
        "approval",
      ].includes(event.kind)),
    });
  }
  return alerts.sort((left, right) => left.firstSeq - right.firstSeq);
}
