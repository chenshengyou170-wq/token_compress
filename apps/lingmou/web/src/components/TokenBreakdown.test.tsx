import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TokenUsage } from "../types";
import { TokenBreakdown } from "./TokenBreakdown";

describe("actual request component usage", () => {
  it("does not replace missing capture with made-up component numbers", () => {
    const html = renderToStaticMarkup(<TokenBreakdown usage={{ relay_enabled: false } as TokenUsage} />);
    expect(html).toContain("请求采集未接入");
    expect(html).not.toContain("<table");
    expect(html).not.toContain("demo-request");
  });

  it("shows sent content usage without compression comparisons and preserves missing values", () => {
    const usage = { relay_enabled: true, breakdown: {
      source: "outbound_request", requests: 2, incomplete_requests: 1,
      latest: { request_id: "tap-2", complete: false },
      components: [
        { id: "instructions", label: "系统与开发者指令", protected: true, before: 100, after: 100, saved: 0, requests: 2, compressed_requests: 0 },
        { id: "tool_results", label: "工具返回", protected: false, before: 1000, after: 500, saved: 500, requests: 1, compressed_requests: 1 },
        { id: "references", label: "显式参考材料", protected: false, before: null, after: null, saved: null, requests: 0, compressed_requests: 0 },
      ],
      tools: [{ name: "read_file", definition_after: 30, call_after: 10, result_before: 1000, result_after: 500, saved: 500 }],
    } } as TokenUsage;
    const html = renderToStaticMarkup(<TokenBreakdown usage={usage} />);
    expect(html).toContain("已采集 2 次实际发送请求");
    expect(html).toContain("各组件用量");
    expect(html).toContain("Token 数（估算）");
    expect(html).toContain("<td>100</td>");
    expect(html).toContain("<td>500</td>");
    expect(html).toContain("<td>—</td>");
    expect(html).not.toContain("1,000");
    expect(html).not.toContain("压缩");
    expect(html).not.toContain("减少量");
    expect(html).toContain("read_file");
    expect(html).toContain("只统计可观测内容");
    expect(html).not.toContain("费用节省");
  });
});
