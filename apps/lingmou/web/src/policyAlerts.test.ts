import { describe, expect, it } from "vitest";
import { policyAlertsForEvents, policyEventNeedsAlert, policyOutcomeForEvent } from "./policyAlerts";
import type { WorkbenchEvent } from "./types";

function event(overrides: Partial<WorkbenchEvent>): WorkbenchEvent {
  return {
    seq: 1,
    event_id: "event-1",
    occurred_at: 1,
    kind: "policy_decision",
    source: "lingmou_workbuddy",
    status: "deny",
    item_id: "action-1",
    title: "办公策略已独立判定",
    summary: "策略发现问题",
    payload: {},
    ...overrides,
  };
}

describe("policy alert aggregation", () => {
  it("carries trading decision metrics into the final result without inventing execution or pause state", () => {
    const decision = event({ payload: {
      action_id: "trade-1", policy_id: "WORK-SOURCE-CHURN-018", mode: "deny",
      evidence: { churn_anomaly_score: 122.25, churn_score_threshold: 120, commission_yuan: 1250, strategy_status: "paused" },
    } });
    const result = event({ seq: 2, kind: "action_result", status: "blocked", payload: {
      action_id: "trade-1", policy_ids: ["WORK-SOURCE-CHURN-018"],
      business_impact: { executor_started: false, commission_yuan: 1300 },
    } });
    const alert = policyAlertsForEvents([decision, result])[0];
    expect(alert.businessImpact).toEqual({
      churn_anomaly_score: 122.25, churn_score_threshold: 120, commission_yuan: 1300, executor_started: false,
    });
    expect(policyAlertsForEvents([decision])[0].executorStarted).toBeUndefined();
  });
  it("turns the two real WB-05 deny decisions and final block into one alert", () => {
    const events = [
      event({
        seq: 158,
        event_id: "policy-158",
        summary: "库存已经达到目标，禁止重复采购。",
        payload: {
          action_id: "wb-purchase-1",
          policy_id: "WORK-PROCURE-007",
          mode: "deny",
          reason: "库存已经达到目标，禁止重复采购。",
          evidence: { current_boxes: 100, target_boxes: 100 },
        },
        explanation: { risk: { level: "high", policy_id: "WORK-PROCURE-007", policy_mode: "deny" } },
      }),
      event({
        seq: 159,
        event_id: "policy-159",
        summary: "累计采购金额将超过阈值。",
        payload: {
          action_id: "wb-purchase-1",
          policy_id: "WORK-SPEND-008",
          mode: "deny",
          reason: "累计采购金额将超过阈值。",
          evidence: { prior_spend_yuan: 8_800, projected_spend_yuan: 17_600 },
        },
        explanation: { risk: { level: "high", policy_id: "WORK-SPEND-008", policy_mode: "deny" } },
      }),
      event({
        seq: 160,
        event_id: "result-160",
        kind: "action_result",
        status: "blocked",
        title: "办公动作返回结构化结果",
        summary: "危险或重复动作已在执行器启动前阻止。",
        payload: {
          action_id: "wb-purchase-1",
          status: "blocked",
          summary: "危险或重复动作已在执行器启动前阻止。",
          policy_ids: ["WORK-PROCURE-007", "WORK-SPEND-008"],
          business_impact: { executor_started: false },
          safe_next_step: "使用 action_status 核对状态；不要重复提交。",
        },
        explanation: {
          description: "危险或重复动作已在执行器启动前阻止。",
          risk: { level: "normal", matched_rules: ["WORK-PROCURE-007", "WORK-SPEND-008"] },
          result: { status: "blocked", summary: "危险或重复动作已在执行器启动前阻止。" },
        },
      }),
    ];

    const alerts = policyAlertsForEvents(events);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      id: "policy-alert:wb-purchase-1",
      outcome: "blocked",
      level: "critical",
      executorStarted: false,
      nextStep: "使用 action_status 核对状态；不要重复提交。",
    });
    expect(alerts[0].eventIds).toEqual(["policy-158", "policy-159", "result-160"]);
    expect(alerts[0].policies.map((policy) => policy.id)).toEqual(["WORK-PROCURE-007", "WORK-SPEND-008"]);
    expect(alerts[0].policies[0]).toMatchObject({
      level: "high",
      mode: "deny",
      reason: "库存已经达到目标，禁止重复采购。",
      evidenceSummary: "current_boxes=100 · target_boxes=100",
    });
  });

  it("marks review alerts as already covered when the same action has an approval dialog", () => {
    const review = event({
      event_id: "review-1",
      status: "review_required",
      payload: { action_id: "action-review", policy_id: "WORK-MAIL-002", mode: "review" },
    });
    const approval = event({
      seq: 2,
      event_id: "approval-1",
      kind: "approval_required",
      status: "pending",
      item_id: "action-review",
      payload: { action_id: "action-review" },
    });

    expect(policyAlertsForEvents([review, approval])[0]).toMatchObject({
      outcome: "review_required",
      coveredByApproval: true,
    });
  });

  it("reports transformed outcomes without claiming that the action was blocked", () => {
    const transformed = event({
      status: "transform",
      payload: {
        action_id: "action-transform",
        policy_id: "WORK-CALENDAR-003",
        mode: "transform",
        reason: "外部与会人已移除。",
      },
    });
    const result = event({
      seq: 2,
      event_id: "result-transform",
      kind: "action_result",
      status: "transformed",
      payload: {
        action_id: "action-transform",
        status: "transformed",
        policy_ids: ["WORK-CALENDAR-003"],
        summary: "已仅保留内部与会人。",
      },
      summary: "已仅保留内部与会人。",
    });

    expect(policyAlertsForEvents([transformed, result])[0]).toMatchObject({
      outcome: "transformed",
      title: "风险操作已安全调整",
      resultSummary: "已仅保留内部与会人。",
    });
  });

  it("alerts on a matched generic detection decision", () => {
    const detected = event({
      source: "codexscope_policy",
      status: "observed",
      item_id: "tool-1",
      payload: {
        decision: {
          policy_id: "LING-OUTPUT-INJECTION-031",
          policy_name: "工具输出指令注入",
          level: "warning",
          mode: "observe",
          result: "detected",
          matched: true,
          reason: "工具输出包含越权指令。",
        },
        subject: { item_id: "tool-1", summary: "读取外部工具结果" },
      },
    });

    expect(policyEventNeedsAlert(detected)).toBe(true);
    expect(policyAlertsForEvents([detected])[0]).toMatchObject({
      outcome: "detected",
      actionSummary: "读取外部工具结果",
      policies: [{ id: "LING-OUTPUT-INJECTION-031", name: "工具输出指令注入" }],
    });
  });

  it("does not alert for baseline creation, allowed decisions, or unrelated failures", () => {
    const baseline = event({
      source: "codexscope_policy",
      status: "observed",
      payload: {
        decision: {
          policy_id: "LING-MCP-DRIFT-033",
          level: "notice",
          mode: "review",
          result: "baseline_created",
          matched: true,
        },
      },
    });
    const allowed = event({ status: "allow", payload: { policy_id: "WORK-SAFE-001", mode: "allow" } });
    const failed = event({
      kind: "action_result",
      status: "failed",
      payload: { status: "failed", policy_ids: ["WORK-SAFE-001"] },
    });

    expect(policyOutcomeForEvent(baseline)).toBeNull();
    expect(policyOutcomeForEvent(allowed)).toBeNull();
    expect(policyOutcomeForEvent(failed)).toBeNull();
    expect(policyAlertsForEvents([baseline, allowed, failed])).toEqual([]);
  });

  it("keeps legacy policy_block events in the unified alert path", () => {
    const blocked = event({
      event_id: "legacy-block",
      kind: "policy_block",
      status: "blocked",
      item_id: "command-1",
      payload: { hard_block: true },
      explanation: { policy_summary: { policy_id: "PAY-EXFIL-004", reason: "密钥外发" } },
    });

    expect(policyAlertsForEvents([blocked])[0]).toMatchObject({
      id: "policy-alert:command-1",
      eventIds: ["legacy-block"],
      outcome: "blocked",
      policies: [{ id: "PAY-EXFIL-004", reason: "密钥外发" }],
    });
  });
});
