import { useMemo } from "react";
import { explanationFor, statusLabel, summaryText } from "../activity";
import type { PolicyCatalog, ScenarioCatalog, WorkbenchEvent, WorkbenchState, WorkBuddyScenario } from "../types";
import { Icon } from "./Icon";
import { ScenarioLauncher } from "./ScenarioLauncher";

const riskRank: Record<string, number> = { normal: 0, low: 0, notice: 1, warning: 2, high: 3, critical: 4 };

function shortWorkspace(path: string): string {
  return path.split("/").filter(Boolean).at(-1) || path;
}

function formatClock(value?: number): string {
  if (!value) return "刚刚";
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(value * 1_000);
}

export function SecurityCenter({
  state,
  events,
  policies,
  scenarios,
  selectedScenarioId,
  streamConnected,
  onOpenWorkbench,
  onOpenPolicies,
  onSelectEvent,
  onSelectScenario,
}: {
  state: WorkbenchState;
  events: WorkbenchEvent[];
  policies: PolicyCatalog | null;
  scenarios: ScenarioCatalog | null;
  selectedScenarioId?: string | null;
  streamConnected: boolean;
  onOpenWorkbench: () => void;
  onOpenPolicies: () => void;
  onSelectEvent: (event: WorkbenchEvent) => void;
  onSelectScenario: (scenario: WorkBuddyScenario) => void;
}) {
  const metrics = useMemo(() => {
    const blockedItems = new Set<string>();
    const riskEvents: WorkbenchEvent[] = [];
    const changedFiles = new Set<string>();
    const networkTargets = new Set<string>();
    for (const event of events) {
      const explanation = explanationFor(event);
      if (event.kind === "policy_block" || event.status === "blocked") {
        blockedItems.add(event.item_id || event.event_id);
      }
      if ((riskRank[explanation.risk?.level || "normal"] || 0) >= 2 || event.kind === "policy_block") {
        riskEvents.push(event);
      }
      explanation.effects?.writes?.forEach((path) => changedFiles.add(path));
      explanation.effects?.network?.forEach((target) => networkTargets.add(target));
    }
    return {
      blocked: blockedItems.size,
      risks: riskEvents.length,
      changedFiles: changedFiles.size,
      networkTargets: networkTargets.size,
      recentRisks: riskEvents.slice(-5).reverse(),
    };
  }, [events]);

  const online = state.connected && streamConnected;
  const enforcing = state.security_mode === "enforce";
  const protectionTone = !online ? "offline" : enforcing ? "safe" : "observe";
  const headline = !online ? "等待 Agent 接入" : enforcing ? "Agent 保护中" : "Agent 正在观察中";
  const supporting = !online
    ? "工作台会自动恢复本地 Agent 链路，已记录的证据仍可查看。"
    : enforcing
      ? "高置信度危险操作会在真正执行前被策略门拒绝。"
      : "当前记录风险但不会自动阻断，可在下次启动时开启强制策略。";
  const task = state.task;
  const currentStep = task?.current_step;
  const workspace = shortWorkspace(state.workspace);
  const policyGroups = policies?.groups || [];
  const codebuddy = state.agent_backend === "codebuddy";
  const workbuddy = Boolean(state.active_scenario?.id);
  const agentName = codebuddy ? "CodeBuddy" : "Codex";
  const gatewayOnline = state.mcp_gateway_status?.status === "online";

  return (
    <main className="security-center">
      <header className="security-center-header">
        <div>
          <h1>Agent 安全中心</h1>
          <p>实时看清 {agentName} 的操作，在敏感数据或高风险动作执行前完成转换、审批与阻断。</p>
        </div>
        <div className="security-header-facts">
          <span><Icon name="session" size={16} />{workspace}</span>
          <span className={online ? "online" : "offline"}><i aria-hidden="true" />{online ? "实时链路已连接" : "链路恢复中"}</span>
        </div>
      </header>

      <section className={`protection-overview protection-${protectionTone}`} aria-labelledby="protection-title">
        <div className="protection-message">
          <div className="protection-emblem" aria-hidden="true">
            <span className="protection-orbit orbit-one" />
            <span className="protection-orbit orbit-two" />
            <span className="protection-shield"><Icon name={enforcing ? "shield" : "eye"} size={54} /></span>
          </div>
          <div className="protection-copy">
            <h2 id="protection-title">{headline}</h2>
            <p>{supporting}</p>
            <div className="protection-actions">
              <button type="button" className="protection-primary-action" onClick={onOpenWorkbench}>
                <Icon name="terminal" size={18} />进入 Agent 工作台
              </button>
              <button type="button" className="protection-secondary-action" onClick={onOpenPolicies}>查看已接入策略</button>
            </div>
          </div>
        </div>
        <dl className="protection-metrics">
          <div><dt>已审阅活动</dt><dd>{events.length}</dd><small>本次运行</small></div>
          <div><dt>发现风险</dt><dd>{metrics.risks}</dd><small>需关注事件</small></div>
          <div className={metrics.blocked ? "has-blocks" : ""}><dt>执行前阻断</dt><dd>{metrics.blocked}</dd><small>命令未启动</small></div>
          <div><dt>本机策略</dt><dd>{policies?.total ?? "—"}</dd><small>{policyGroups.length || "—"} 类保护</small></div>
        </dl>
      </section>

      <ScenarioLauncher
        catalog={scenarios}
        activeScenarioId={state.active_scenario?.id}
        selectedScenarioId={selectedScenarioId}
        onSelect={onSelectScenario}
      />

      <div className="security-center-grid">
        <section className="current-protection-panel" aria-labelledby="current-task-title">
          <div className="panel-heading-row">
            <div><h2 id="current-task-title">当前 Agent 任务</h2><p>从目标到命令，保持同一条证据链</p></div>
            <span className={`task-state task-${state.turn_status}`}>{state.active_turn_id ? statusLabel(state.turn_status) : "等待任务"}</span>
          </div>
          <div className="task-focus">
            <span className="task-focus-icon"><Icon name="agent" size={24} /></span>
            <div>
              <strong>{task?.goal || "尚未提交任务"}</strong>
              <p>{task?.goal ? "灵眸正在关联计划、操作、结果与策略处置。" : "进入工作台输入任务，灵眸会同步展示 Agent 的计划和真实操作。"}</p>
            </div>
          </div>
          <ol className="task-progress-list">
            {(task?.steps?.length ? task.steps : [currentStep || { index: 1, title: "理解任务", status: "pending" }]).slice(0, 4).map((step, index) => (
              <li key={step.id || `${step.title}-${index}`} className={`step-${step.status || "pending"}`}>
                <span>{step.index || index + 1}</span>
                <div><strong>{step.title || `步骤 ${index + 1}`}</strong><small>{statusLabel(step.status || "pending")}</small></div>
              </li>
            ))}
          </ol>
          {task?.active_command && (
            <div className="active-command-line">
              <Icon name="terminal" size={16} />
              <span><small>正在执行</small><code>{task.active_command.command || task.active_command.headline}</code></span>
            </div>
          )}
        </section>

        <section className="protection-layers-panel" aria-labelledby="protection-layers-title">
          <div className="panel-heading-row">
            <div><h2 id="protection-layers-title">保护链路</h2><p>每一层都给出当前真实状态</p></div>
          </div>
          <ul className="protection-layer-list">
            <li>
              <span className={`layer-icon ${enforcing ? "healthy" : "attention"}`}><Icon name="shield" size={20} /></span>
              <div><strong>执行前策略门</strong><p>{enforcing ? "强制阻断已开启" : "仅记录，不自动拒绝"}</p></div>
              <em>{enforcing ? "已保护" : "观察"}</em>
            </li>
            <li>
              <span className={`layer-icon ${online ? "healthy" : "attention"}`}><Icon name="agent" size={20} /></span>
              <div><strong>Agent 实时链路</strong><p>{online ? `已连接 ${state.model || agentName}` : codebuddy ? "正在等待公开 ACP v1" : "正在等待本机 app-server"}</p></div>
              <em>{online ? "在线" : "恢复中"}</em>
            </li>
            {workbuddy && (
              <li>
                <span className={`layer-icon ${gatewayOnline ? "healthy" : "attention"}`}><Icon name="database" size={20} /></span>
                <div><strong>MCP 安全网关</strong><p>{gatewayOnline ? `${state.active_scenario?.id} · 沙箱 ${state.mcp_gateway_status?.sandbox_id}` : "事务沙箱网关未就绪"}</p></div>
                <em>{gatewayOnline ? "在线" : "检查中"}</em>
              </li>
            )}
            <li>
              <span className="layer-icon healthy"><Icon name="inspect" size={20} /></span>
              <div><strong>跨层本地证据</strong><p>{metrics.changedFiles} 个变更文件 · {metrics.networkTargets} 个网络目标</p></div>
              <em>{events.length ? "记录中" : "待活动"}</em>
            </li>
            <li>
              <span className="layer-icon healthy"><Icon name="eye" size={20} /></span>
              <div><strong>凭据与会话隐私</strong><p>凭据始终脱敏，{state.privacy.conversation_persisted ? "对话脱敏后落盘" : "对话默认不落全文"}</p></div>
              <em>本地</em>
            </li>
          </ul>
        </section>
      </div>

      <div className="security-center-grid lower-grid">
        <section className="recent-risk-panel" aria-labelledby="recent-risk-title">
          <div className="panel-heading-row">
            <div><h2 id="recent-risk-title">最近安全事件</h2><p>先看结果，再下钻命令和证据</p></div>
            <button type="button" className="panel-text-action" onClick={onOpenWorkbench}>查看全部活动</button>
          </div>
          {metrics.recentRisks.length ? (
            <div className="recent-risk-list">
              {metrics.recentRisks.map((event) => {
                const explanation = explanationFor(event);
                const level = explanation.risk?.level || (event.kind === "policy_block" ? "critical" : "warning");
                return (
                  <button type="button" key={event.event_id} onClick={() => onSelectEvent(event)}>
                    <span className={`risk-event-icon risk-${level}`}><Icon name={event.kind === "policy_block" ? "shield" : "warning"} size={18} /></span>
                    <span className="risk-event-copy"><strong>{explanation.headline || event.title}</strong><small>{summaryText(event.summary)}</small></span>
                    <span className="risk-event-meta"><em>{event.kind === "policy_block" ? "已阻断" : "已识别"}</em><time>{formatClock(event.occurred_at)}</time></span>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="quiet-empty-state">
              <span><Icon name="shield" size={24} /></span>
              <div><strong>暂未发现需要处理的风险</strong><p>命令、文件、网络和审批活动出现后会在这里给出安全结论。</p></div>
            </div>
          )}
        </section>

        <section className="policy-summary-panel" aria-labelledby="policy-summary-title">
          <div className="panel-heading-row">
            <div><h2 id="policy-summary-title">已接入策略</h2><p>通用、敏感资产与生活业务统一呈现</p></div>
          </div>
          <div className="policy-total-line"><strong>{policies?.total ?? "—"}</strong><span>项本机策略<br />随当前 Agent 会话生效</span></div>
          <ul className="policy-group-summary">
            {policyGroups.map((group) => (
              <li key={group.id}><span><i aria-hidden="true" /><strong>{group.name}</strong></span><em>{group.policies.length} 项</em></li>
            ))}
          </ul>
          <button type="button" className="full-width-secondary" onClick={onOpenPolicies}>打开策略中心</button>
        </section>
      </div>
    </main>
  );
}
