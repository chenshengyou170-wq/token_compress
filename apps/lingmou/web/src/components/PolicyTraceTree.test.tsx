import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PolicyTraceTree, tracesIn, type RuleTrace } from "./PolicyTraceTree";

const trace: RuleTrace = {
  schema_version: "lingmou.policy-trace.v1", policy_id: "USER-upload", policy_name: "上传复核",
  result: "unknown", configured_mode: "deny", effective_mode: "review", when: {
    kind: "all", path: "when", result: "unknown", children: [
      { kind: "predicate", path: "when.all[0]", result: "true", field: "network.present", op: "eq", actual: true, expected: true, value_present: true },
      { kind: "not", path: "when.all[1]", result: "unknown", children: [{ kind: "semantic", path: "when.all[1].not[0]", name: "approved", result: "unknown", reason: "所需证据缺失" }] },
    ],
  },
};

describe("policy explanation tree", () => {
  it("shows nested unknowns and facts without claiming a block occurred", () => {
    const html = renderToStaticMarkup(<PolicyTraceTree traces={[trace]} />);
    expect(html).toContain("全部成立 AND");
    expect(html).toContain("取反 NOT");
    expect(html).toContain("所需证据缺失");
    expect(html).toContain("人工复核");
    expect(html).toContain("不代表操作已经执行");
    expect(html).toContain("实际值");
  });
  it("extracts and deduplicates persisted decisions and full evaluation events", () => {
    expect(tracesIn({ payload: { decision: { evidence: { condition_trace: trace } } }, evidence: { traces: [trace] } })).toEqual([trace]);
    expect(tracesIn({ payload: { traces: [trace] } })).toEqual([trace]);
    expect(tracesIn({ payload: { condition_trace: "[TRUNCATED]" } })).toEqual([]);
  });
});
