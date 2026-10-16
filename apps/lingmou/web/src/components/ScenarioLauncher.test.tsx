import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ScenarioCatalog, WorkBuddyScenario } from "../types";
import { ScenarioLauncher } from "./ScenarioLauncher";

function scenario(
  id: string,
  runnable: boolean,
  availability: WorkBuddyScenario["availability"],
): WorkBuddyScenario {
  return {
    id,
    slug: id.toLowerCase(),
    title: `场景 ${id}`,
    category: "办公协作",
    phase: runnable ? "initial" : "planned",
    scenario_type: "fault_injection",
    runnable,
    fixed_seed: `seed-${id}`,
    default_prompt: `执行 ${id} 的带风险默认任务。`,
    tool_path: ["read", "prepare", "commit"],
    fault_injection: `模拟 ${id} 的异常动作。`,
    expected_control: `阻止或收窄 ${id} 的异常动作。`,
    final_business_state: "固定业务终态",
    expected_policy_ids: [`POLICY-${id}`],
    recovery: "执行恢复操作",
    result_summary: `完成 ${id}。`,
    availability,
    availability_reason: availability === "available" ? null : "当前不可运行",
  };
}

describe("WorkBuddy scenario launcher", () => {
  it("renders six runnable cards and six complete planned designs", () => {
    const scenarios = [
      ...Array.from({ length: 6 }, (_, index) =>
        scenario(`WB-0${index + 1}`, true, index === 0 ? "available" : "restart_required"),
      ),
      ...Array.from({ length: 6 }, (_, index) =>
        scenario(index < 3 ? `WB-0${index + 7}` : `LIFE-${index + 7}`, false, "planned"),
      ),
    ];
    const catalog: ScenarioCatalog = {
      schema_version: "lingmou.workbuddy-scenario.v2",
      total: 12,
      runnable: 6,
      agent_backend: "codebuddy",
      launch_hint: null,
      scenarios,
    };
    const html = renderToStaticMarkup(
      <ScenarioLauncher
        catalog={catalog}
        activeScenarioId="WB-01"
        selectedScenarioId={null}
        onSelect={() => undefined}
      />,
    );

    expect((html.match(/class="scenario-card /g) || [])).toHaveLength(6);
    expect((html.match(/ disabled=""/g) || [])).toHaveLength(5);
    expect(html).toContain("选择一个问题场景");
    expect((html.match(/故障注入/g) || [])).toHaveLength(6);
    expect(html).toContain("问题点");
    expect(html).toContain("灵眸应当");
    expect(html).toContain("查看后续 6 个完整设计");
    expect(html).toContain("LIFE-12");
    expect(html).not.toContain("<form");
  });

  it("turns all registered scenarios into one policy portal", () => {
    const scenarios = Array.from({ length: 6 }, (_, index) => ({
      ...scenario(`WB-0${index + 1}`, true, "available"),
      launch_url: `https://192.168.31.108:${34000 + index}/?access_token=token-${index + 1}`,
    }));
    const catalog: ScenarioCatalog = {
      schema_version: "lingmou.workbuddy-scenario.v2",
      total: 6,
      runnable: 6,
      launched: 6,
      agent_backend: "codex",
      launch_hint: "已接入 6 个独立 WorkBuddy 沙箱。",
      scenarios,
    };

    const html = renderToStaticMarkup(
      <ScenarioLauncher
        catalog={catalog}
        activeScenarioId={null}
        selectedScenarioId={null}
        onSelect={() => undefined}
      />,
    );

    expect((html.match(/<a class="scenario-card /g) || [])).toHaveLength(6);
    expect((html.match(/进入独立策略工作台/g) || [])).toHaveLength(12);
    expect((html.match(/referrerPolicy="no-referrer"/g) || [])).toHaveLength(6);
    expect(html).toContain("WorkBuddy 策略入口");
    expect(html).toContain("POLICY-WB-01");
    expect(html).toContain("6 个独立策略沙箱在线");
    expect(html).not.toContain("disabled=\"\"");
  });
});
