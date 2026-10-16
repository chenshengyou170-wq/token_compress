import { describe, expect, it } from "vitest";
import { incidentNarrative } from "./incidentNarrative";

describe("incident consequences are tied to evidence", () => {
  it("does not label a credential read as a proven leak", () => {
    const incident = incidentNarrative(["PAY-KEY-001"], { reads: ["payment/.env.demo"] });
    expect(incident?.subject).toBe("Agent 正在请求读取支付密钥");
    expect(incident?.consequence).toContain("尚不能认定已经外泄");
  });
  it("shows the destination host without URL credentials or query secrets", () => {
    const incident = incidentNarrative(["PAY-EXFIL-004"], { network: ["https://demo:secret@receiver.invalid/collect?key=private"] });
    expect(incident?.to).toBe("receiver.invalid");
    expect(incident?.consequence).toContain("密钥权限内");
  });
  it("does not invent savings from already paid procurement spend", () => {
    const incident = incidentNarrative(["WORK-PROCURE-007", "WORK-SPEND-008"], {}, { current_boxes: 100, target_boxes: 100, prior_spend_yuan: 8800 });
    expect(incident?.facts).toContainEqual({ label: "已有采购金额", value: "¥8,800" });
    expect(incident?.consequence).not.toContain("8,800");
    expect(incidentNarrative(["WORK-PROCURE-007"], {}, { current_boxes: "100" })?.facts).toEqual([]);
  });
  it("keeps unrelated or unknown policy findings on their own descriptions", () => {
    expect(incidentNarrative(["CUSTOM-POLICY"])).toBeNull();
  });
  it("separates paid trading commissions from prevented future orders", () => {
    const incident = incidentNarrative(["WORK-SOURCE-CHURN-018"], {}, {
      churn_anomaly_score: 122.25, churn_score_threshold: 120, commission_yuan: 1250,
      strategy_status: "paused", simulation: true,
    });
    expect(incident?.facts).toContainEqual({ label: "异常评分", value: "122.25" });
    expect(incident?.facts).toContainEqual({ label: "已付模拟佣金", value: "¥1,250" });
    expect(incident?.blockedStatement).toBe("新委托已拦截，策略已暂停");
    expect(incident?.consequence).toContain("不会因拦截新委托而撤销");
  });
  it("never fills missing trading metrics from video examples or assumes a pause", () => {
    const incident = incidentNarrative(["WORK-SOURCE-CHURN-018"], {}, {
      churn_anomaly_score: "122.25", commission_yuan: -1, fill_count: 0.5,
      turnover_yuan: Infinity, strategy_status: "active",
    });
    expect(incident?.facts).toEqual([]);
    expect(incident?.blockedStatement).not.toContain("已暂停");
  });
});
