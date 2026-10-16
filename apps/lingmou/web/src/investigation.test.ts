import { describe, expect, it } from "vitest";
import {
  confidenceLabels,
  captureCompletenessLabel,
  formatDuration,
  evidenceStateLabel,
  fileAccessLabel,
  incidentEdges,
  investigationStatusLabel,
  isTimeGap,
  relationLabel,
  stageLabels,
} from "./investigation";
import type { InvestigationEdge, InvestigationTimeGap } from "./types";

describe("investigation presentation contract", () => {
  it("keeps fact, strong association, candidate, and unproven visibly distinct", () => {
    expect(confidenceLabels.fact).toBe("已观察事实");
    expect(confidenceLabels.strong).toBe("强关联");
    expect(confidenceLabels.candidate).toBe("候选关联");
    expect(confidenceLabels.unproven).toBe("无法证明");
  });

  it("uses the six requested investigation stages", () => {
    expect(Object.values(stageLabels)).toEqual([
      "入口",
      "访问 / 侦察",
      "收集",
      "加工 / 准备",
      "外联 / 高危执行",
      "结果 / 处置",
    ]);
  });

  it("compresses long quiet intervals without losing their duration", () => {
    const gap: InvestigationTimeGap = {
      id: "gap-1",
      node_type: "time_gap",
      duration_seconds: 172_800,
      occurred_at: 1,
      title: "无相关事件区间已压缩",
      summary: "2 天内无相关事件",
    };
    expect(isTimeGap(gap)).toBe(true);
    expect(formatDuration(gap.duration_seconds)).toBe("2 天");
  });

  it("shows the evidence reason for every relationship touching a node", () => {
    const edges: InvestigationEdge[] = [
      {
        id: "edge-1",
        source: "read",
        target: "write",
        relation: "SAME_FILE_VERSION",
        confidence_tier: "strong",
        confidence: 0.88,
        evidence: "同一内容版本 abc123",
        causal: false,
      },
      {
        id: "edge-2",
        source: "write",
        target: "block",
        relation: "POLICY_DECIDES",
        confidence_tier: "fact",
        confidence: 1,
        evidence: "同一策略事件",
        causal: true,
      },
    ];
    expect(incidentEdges("write", edges)).toHaveLength(2);
    expect(relationLabel(edges[0].relation)).toBe("同一文件版本");
  });

  it("states every terminal outcome instead of collapsing it to recorded", () => {
    expect(investigationStatusLabel("completed")).toBe("已执行");
    expect(investigationStatusLabel("failed")).toBe("执行失败");
    expect(investigationStatusLabel("interrupted")).toBe("已中断");
    expect(investigationStatusLabel("blocked")).toBe("已阻断");
    expect(relationLabel("ACTION_RESULT")).toBe("操作与最终结果");
    expect(relationLabel("SAME_NETWORK_TARGET")).toBe("同一网络目标");
    expect(relationLabel("SAME_PROCESS")).toBe("同一进程");
    expect(relationLabel("TURN_SEQUENCE")).toBe("同回合记录顺序");
    expect(investigationStatusLabel("pending")).toBe("等待审批");
    expect(evidenceStateLabel("partial")).toBe("部分");
    expect(fileAccessLabel("attempted_read")).toBe("请求读取（未执行）");
    expect(captureCompletenessLabel("content_hash")).toBe("元数据与内容哈希");
  });
});
