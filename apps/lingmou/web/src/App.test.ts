import { describe, expect, it } from "vitest";
import { mergeTimeline, summaryText, type WorkbenchEvent } from "./App";
import { eventMatches, explanationFor, groupTimeline, sourceLabel, statusLabel } from "./activity";

function event(overrides: Partial<WorkbenchEvent>): WorkbenchEvent {
  return {
    seq: 1,
    event_id: "event-1",
    occurred_at: 1,
    kind: "agent_delta",
    source: "codex_app_server",
    status: "streaming",
    item_id: "message-1",
    title: "Agent 正在回复",
    summary: "开始",
    payload: { delta: "开始" },
    ...overrides,
  };
}

describe("workbench timeline", () => {
  it("merges streamed Agent deltas into one readable activity", () => {
    const timeline = mergeTimeline([
      event({ summary: "开始" }),
      event({ seq: 2, event_id: "event-2", summary: "检查" }),
      event({
        seq: 3,
        event_id: "event-3",
        kind: "agent_message",
        status: "completed",
        title: "Agent 回复",
        summary: "开始检查",
        payload: { text: "开始检查" },
      }),
    ]);

    expect(timeline).toHaveLength(1);
    expect(timeline[0].summary).toBe("开始检查");
    expect(timeline[0].status).toBe("completed");
  });

  it("renders privacy-preserving replay metadata clearly", () => {
    expect(summaryText({ omitted: true, characters: 42 })).toBe("内容未落盘 · 42 字符");
  });

  it("folds a delayed OS evidence update back into its command card", () => {
    const timeline = mergeTimeline([
      event({
        kind: "command",
        item_id: "command-1",
        status: "completed",
        payload: { item: { command: "sed -n '1,20p' retry.py" } },
      }),
      event({
        seq: 2,
        event_id: "evidence-2",
        kind: "command_evidence",
        item_id: "command-1",
        source: "os_observation",
        evidence: {
          availability: "available",
          completeness: "partial",
          observations: [{ kind: "file_read", label: "以只读方式访问文件", pid: 18422 }],
        },
      }),
    ]);

    expect(timeline).toHaveLength(1);
    expect(timeline[0].kind).toBe("command");
    expect(timeline[0].evidence?.availability).toBe("available");
    expect(timeline[0].evidence?.observations?.[0].pid).toBe(18422);
  });

  it("groups high-level activity by the persisted Agent plan step", () => {
    const timeline = [
      event({
        kind: "command",
        item_id: "command-1",
        step: { id: "turn-1:step:2", index: 2, title: "检查支付重试逻辑", status: "in_progress", source: "agent_plan" },
      }),
      event({
        seq: 2,
        event_id: "event-2",
        kind: "file_change",
        item_id: "file-1",
        step: { id: "turn-1:step:2", index: 2, title: "检查支付重试逻辑", status: "completed", source: "agent_plan" },
      }),
    ];

    const groups = groupTimeline(timeline);
    expect(groups).toHaveLength(1);
    expect(groups[0].step.title).toBe("检查支付重试逻辑");
    expect(groups[0].step.status).toBe("completed");
    expect(groups[0].events).toHaveLength(2);
  });

  it("hides low-level protocol noise and searches commands, files, rules, and tools", () => {
    const command = event({
      kind: "command",
      title: "读取支付重试模块",
      summary: "sed -n '1,200p' payment/retry.py",
    });
    const delta = event({ kind: "command_output", summary: "chunk" });

    expect(eventMatches(command, "tools", "retry.py")).toBe(true);
    expect(eventMatches(command, "risk", "")).toBe(true);
    expect(eventMatches(delta, "all", "")).toBe(false);
  });

  it("shows problem policy events in the activity and risk feeds but hides benign baselines", () => {
    const denied = event({
      kind: "policy_decision",
      status: "deny",
      item_id: "purchase-1",
      payload: { action_id: "purchase-1", policy_id: "WORK-PROCURE-007", mode: "deny" },
    });
    const baseline = event({
      kind: "policy_decision",
      status: "observed",
      item_id: "tool-1",
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

    expect(eventMatches(denied, "all", "")).toBe(true);
    expect(eventMatches(denied, "risk", "WORK-PROCURE-007")).toBe(true);
    expect(eventMatches(baseline, "all", "")).toBe(false);
  });

  it("provides an explicit conservative explanation for old command events", () => {
    const explanation = explanationFor(event({ kind: "command", title: "执行命令", summary: "vendor-tool --run" }));
    expect(explanation.conservative_fallback).toBe(true);
    expect(explanation.description).toContain("完整副作用");
    expect(sourceLabel(explanation.sources?.[0])).toBe("保守回退");
    expect(statusLabel("blocked")).toBe("已阻断");
  });
});
