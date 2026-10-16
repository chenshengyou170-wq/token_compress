import type { ReactNode } from "react";
import type { WorkbenchState } from "../types";
import { Icon, type IconName } from "./Icon";

export type AppView = "overview" | "workbench" | "tokens" | "harness" | "syscalls" | "investigations" | "policies";

const navigation: Array<{ id: AppView; label: string; mobileLabel?: string; detail: string; icon: IconName }> = [
  { id: "overview", label: "安全总览", detail: "保护状态", icon: "summary" },
  { id: "workbench", label: "Agent 工作台", mobileLabel: "Agent", detail: "实时任务", icon: "terminal" },
  { id: "tokens", label: "Token 用量", mobileLabel: "Token", detail: "消耗统计", icon: "database" },
  { id: "harness", label: "Harness", detail: "内部遥测", icon: "session" },
  { id: "syscalls", label: "系统调用", detail: "进程证据", icon: "syscall" },
  { id: "investigations", label: "调查回放", detail: "根因与影响", icon: "graph" },
  { id: "policies", label: "策略中心", detail: "规则与处置", icon: "shield" },
];

export function AppShell({
  active,
  state,
  streamConnected,
  onNavigate,
  children,
}: {
  active: AppView;
  state: WorkbenchState;
  streamConnected: boolean;
  onNavigate: (view: AppView) => void;
  children: ReactNode;
}) {
  const protectedNow = state.connected && streamConnected;
  const workbuddy = Boolean(state.active_scenario?.id);
  return (
    <div className={`product-shell product-view-${active}`}>
      <aside className="product-rail" aria-label="灵眸主导航">
        <button type="button" className="product-brand" onClick={() => onNavigate("overview")} aria-label="返回安全总览">
          <span className="product-brand-mark"><Icon name="eye" size={24} /></span>
          <span><strong>灵眸</strong><small>Agent 安全</small></span>
        </button>
        <nav className="product-navigation">
          {navigation.map((item) => (
            <button
              type="button"
              key={item.id}
              className={active === item.id ? "active" : ""}
              aria-current={active === item.id ? "page" : undefined}
              aria-label={`${item.label}，${item.detail}`}
              onClick={() => onNavigate(item.id)}
            >
              <span className="product-nav-icon"><Icon name={item.icon} size={21} /></span>
              <span className="product-nav-copy"><strong><span className="product-nav-full-label">{item.label}</span><span className="product-nav-mobile-label">{item.mobileLabel || item.label}</span></strong><small>{item.detail}</small></span>
            </button>
          ))}
        </nav>
        <div className={`product-connection ${protectedNow ? "online" : "offline"}`} role="status">
          <span aria-hidden="true" />
          <div><strong>{protectedNow ? "本地保护在线" : "正在连接"}</strong><small>{workbuddy ? `${state.active_scenario?.id || "WorkBuddy"} · MCP ${state.mcp_gateway_status?.status === "online" ? "在线" : "检查中"}` : state.security_mode === "enforce" ? "执行前阻断已启用" : "当前为观察模式"}</small></div>
        </div>
      </aside>
      <div className="product-surface">{children}</div>
    </div>
  );
}
