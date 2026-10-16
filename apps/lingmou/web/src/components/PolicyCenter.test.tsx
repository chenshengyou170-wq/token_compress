import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { PolicyCatalog, WorkbenchEvent } from "../types";
import { PolicyCenter } from "./PolicyCenter";

const catalog: PolicyCatalog = {
  schema_version: "lingmou.workbench-policy-catalog.v1",
  total: 2,
  groups: [
    {
      id: "runtime",
      name: "Agent 行为防护",
      description: "测试策略分组",
      policies: [
        {
          id: "LING-OBFEXEC-026",
          name: "解码与混淆载荷执行",
          risk_level: "critical",
          action: "高置信度时执行前阻断",
          enabled: true,
          mode: "deny",
          stage: "pre_execution_approval",
          evidence_source: "deterministic_command_analysis",
          enforceable_now: true,
          stateful: false,
          tested: "local",
        },
        {
          id: "LING-PROMPT-INJECT-036",
          name: "输入侧直接与间接提示注入",
          risk_level: "warning",
          action: "仅记录模式与内容哈希，不阻止用户提交",
          enabled: true,
          mode: "observe",
          stage: "llm_before",
          evidence_source: "bounded_input_analysis",
          enforceable_now: false,
          stateful: false,
          tested: "local",
        },
      ],
    },
  ],
};

function decisionEvent(
  seq: number,
  policyId: string,
  result: string,
): WorkbenchEvent {
  return {
    seq,
    event_id: `policy-${seq}`,
    occurred_at: seq,
    kind: "policy_decision",
    source: "codexscope_policy",
    status: result === "blocked" ? "blocked" : "observed",
    item_id: "same-agent-item",
    title: `${policyId} decision`,
    summary: "策略命中",
    payload: {
      decision: {
        policy_id: policyId,
        result,
        reason: `${policyId} 独立原因`,
      },
    },
  };
}

describe("policy center replay contract", () => {
  it("maps one source item to separate policy rows instead of one hard-coded hit", () => {
    const html = renderToStaticMarkup(
      <PolicyCenter
        catalog={catalog}
        events={[
          decisionEvent(1, "LING-OBFEXEC-026", "blocked"),
          decisionEvent(2, "LING-PROMPT-INJECT-036", "observed"),
        ]}
      />,
    );

    expect(html).toContain("LING-OBFEXEC-026");
    expect(html).toContain("LING-PROMPT-INJECT-036");
    expect(html).toContain("执行前阻断");
    expect(html).toContain("静默记录");
    expect(html.match(/1 次命中/g)).toHaveLength(2);
    expect(html).toContain("逐条保存命中与处置");
  });

  it("keeps every rule on a legacy multi-match event in its own row", () => {
    const legacy: WorkbenchEvent = {
      seq: 3,
      event_id: "legacy-multi-hit",
      occurred_at: 3,
      kind: "command",
      source: "codex_app_server",
      status: "blocked",
      item_id: "legacy-item",
      title: "旧版多策略事件",
      summary: "redacted command",
      payload: {},
      explanation: {
        risk: {
          level: "critical",
          blocking_rule: "LING-OBFEXEC-026",
          matched_rules: ["LING-OBFEXEC-026", "LING-PROMPT-INJECT-036"],
        },
      },
    };

    const html = renderToStaticMarkup(
      <PolicyCenter catalog={catalog} events={[legacy]} />,
    );

    expect(html.match(/1 次命中/g)).toHaveLength(2);
  });
});
