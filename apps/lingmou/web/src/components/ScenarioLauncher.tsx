import type { ScenarioCatalog, WorkBuddyScenario } from "../types";
import { Icon, type IconName } from "./Icon";

const categoryIcon: Record<string, IconName> = {
  "办公协作": "link",
  "日程会议": "session",
  "财务审批": "inspect",
  "采购库存": "database",
  "销售汇报": "summary",
};

function availabilityLabel(scenario: WorkBuddyScenario): string {
  if (scenario.availability === "available") return "可运行";
  if (scenario.availability === "restart_required") return "需干净重启";
  if (scenario.availability === "workbuddy_start_required") return "需启动 WorkBuddy";
  if (scenario.availability === "agent_unavailable") return "Agent 未安装";
  return "完整设计";
}

export function ScenarioLauncher({
  catalog,
  activeScenarioId,
  selectedScenarioId,
  onSelect,
}: {
  catalog: ScenarioCatalog | null;
  activeScenarioId?: string | null;
  selectedScenarioId?: string | null;
  onSelect: (scenario: WorkBuddyScenario) => void;
}) {
  if (!catalog) {
    return (
      <section className="scenario-launcher scenario-loading" aria-busy="true">
        <span aria-hidden="true" />
        <div><strong>正在读取办公场景</strong><p>场景状态会按当前 Agent 与沙箱能力校验。</p></div>
      </section>
    );
  }
  const runnable = catalog.scenarios.filter((scenario) => scenario.runnable);
  const planned = catalog.scenarios.filter((scenario) => !scenario.runnable);
  const portalReady = Boolean(catalog.launched);
  return (
    <section className="scenario-launcher" aria-labelledby="scenario-launcher-title">
      <header className="scenario-launcher-heading">
        <div>
          <h2 id="scenario-launcher-title">{portalReady ? "WorkBuddy 策略入口" : "选择一个问题场景"}</h2>
          <p>{portalReady
            ? "六个场景分别运行在独立沙箱中。先看清策略处置，再点击进入对应工作台执行演示。"
            : "每张卡都会注入可复现的违规或故障动作。点击后先查看带风险的默认指令，再由你发送。"}</p>
        </div>
        <span className={`scenario-agent-source source-${catalog.agent_backend}`}>
          <Icon name="agent" size={16} />
          {portalReady
            ? `${catalog.launched} 个独立策略沙箱在线`
            : catalog.agent_backend === "codebuddy"
            ? "CodeBuddy ACP"
            : activeScenarioId
              ? "Codex + WorkBuddy MCP"
              : "Codex 默认链路"}
        </span>
      </header>
      <div className="scenario-card-grid">
        {runnable.map((scenario) => {
          const enabled = scenario.availability === "available";
          const current = scenario.id === activeScenarioId;
          const selected = scenario.id === selectedScenarioId;
          const external = enabled && Boolean(scenario.launch_url) && !current;
          const className = `scenario-card ${current ? "current" : ""} ${selected ? "selected" : ""}`;
          const content = (
            <>
              <span className="scenario-card-icon"><Icon name={categoryIcon[scenario.category] || "tool"} size={20} /></span>
              <span className="scenario-card-copy">
                <span className="scenario-card-title"><strong>{scenario.title}</strong><code>{scenario.id}</code></span>
                <span className="scenario-fault-label"><Icon name="warning" size={13} />故障注入</span>
                <span className="scenario-card-problem"><b>问题点</b><span>{scenario.fault_injection}</span></span>
                <span className="scenario-card-control"><b>灵眸应当</b><span>{scenario.expected_control}</span></span>
                <span className="scenario-policy-list">
                  <b>生效策略</b>
                  <span>{scenario.expected_policy_ids.map((policyId) => <code key={policyId}>{policyId}</code>)}</span>
                </span>
                <span className="scenario-card-meta">
                  <em className={`availability-${scenario.availability}`}>
                    {current ? "当前场景" : external ? "已启动" : availabilityLabel(scenario)}
                  </em>
                  <span>{scenario.expected_policy_ids.length} 项策略</span>
                </span>
                <span className="scenario-card-action">
                  {external ? "进入独立策略工作台" : enabled ? "载入演示提示词" : availabilityLabel(scenario)}
                  {enabled && <Icon name="arrowRight" size={16} />}
                </span>
              </span>
            </>
          );
          if (external) {
            return (
              <a
                key={scenario.id}
                className={className}
                href={scenario.launch_url || undefined}
                referrerPolicy="no-referrer"
                aria-label={`${scenario.title}，进入独立策略工作台`}
              >
                {content}
              </a>
            );
          }
          return (
            <button
              type="button"
              key={scenario.id}
              className={className}
              disabled={!enabled}
              title={scenario.availability_reason || undefined}
              onClick={() => onSelect(scenario)}
              aria-pressed={selected}
            >
              {content}
            </button>
          );
        })}
      </div>
      <div className="scenario-launcher-foot">
        <p>{catalog.launch_hint || (activeScenarioId ? `当前独立沙箱：${activeScenarioId}` : "请选择已启动的独立沙箱。")}</p>
        <details>
          <summary>查看后续 6 个完整设计</summary>
          <ul>
            {planned.map((scenario) => (
              <li key={scenario.id}><code>{scenario.id}</code><strong>{scenario.title}</strong><span>问题：{scenario.fault_injection}<br />处置：{scenario.expected_control}</span></li>
            ))}
          </ul>
        </details>
      </div>
    </section>
  );
}
