import { useEffect, useMemo, useState } from "react";
import { explanationFor, statusLabel } from "../activity";
import type { WorkbenchEvent, WorkbenchState } from "../types";

function durationLabel(startedAt?: number | null, now = Date.now() / 1000): string {
  if (!startedAt) return "00:00";
  const seconds = Math.max(0, Math.floor(now - startedAt));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return hours
    ? `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

export function RunOverview({ state, events }: { state: WorkbenchState; events: WorkbenchEvent[] }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => tick((value) => value + 1), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const changedFiles = useMemo(() => {
    const values = new Set<string>();
    for (const event of events) {
      explanationFor(event).effects?.writes?.forEach((path) => values.add(path));
    }
    return values;
  }, [events]);
  const task = state.task;
  const step = task?.current_step;
  const codebuddy = state.agent_backend === "codebuddy";
  const workbuddy = Boolean(state.active_scenario?.id);
  const gatewayOnline = state.mcp_gateway_status?.status === "online";
  return (
    <section className="run-overview" aria-labelledby="task-overview-title">
      <div className="run-goal">
        <h1 id="task-overview-title"><span className="visually-hidden">当前任务：</span>{task?.goal || "等待你输入一个任务"}</h1>
        <div className="run-context-line" aria-label="当前 Agent 与沙箱">
          <span>{codebuddy ? "CodeBuddy ACP" : "Codex app-server"}</span>
          {state.active_scenario?.id && <span>{state.active_scenario.id} · {state.active_scenario.title}</span>}
          {workbuddy && <span className={gatewayOnline ? "online" : "offline"}>WorkBuddy MCP {gatewayOnline ? "在线" : "未就绪"} · {state.mcp_gateway_status?.sandbox_id || "独立沙箱"}</span>}
        </div>
        <div className="current-step-line">
          <span className="step-number">{step?.index || 1}</span>
          <div>
            <span>当前步骤</span>
            <strong>{step?.title || "理解任务"}</strong>
          </div>
          <span className={`overview-status status-${step?.status || state.turn_status}`} role="status" aria-live="polite">
            {statusLabel(step?.status === "in_progress" ? "running" : step?.status || state.turn_status)}
          </span>
        </div>
      </div>
      <dl className="overview-metrics">
        <div><dt>运行时间</dt><dd>{durationLabel(task?.started_at)}</dd></div>
        <div><dt>修改文件</dt><dd>{changedFiles.size}</dd></div>
        <div><dt>待审批</dt><dd>{state.pending_interactions?.filter((item) => item.kind === "approval").length || 0}</dd></div>
        <div><dt>风险处置</dt><dd>{state.live_security?.summary?.blocked_events_visible || 0}</dd></div>
      </dl>
    </section>
  );
}
