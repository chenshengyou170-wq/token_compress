import { useEffect, type ReactNode } from "react";
import type { WorkbenchState } from "../types";
import { Icon } from "./Icon";

export function WorkbenchLayout({
  state,
  streamConnected,
  leftOpen,
  rightOpen,
  onToggleLeft,
  onOpenHistory,
  onToggleRight,
  onCloseDrawers,
  sidebar,
  overview,
  feed,
  composer,
  inspector,
  notices,
}: {
  state: WorkbenchState;
  streamConnected: boolean;
  leftOpen: boolean;
  rightOpen: boolean;
  onToggleLeft: () => void;
  onOpenHistory: () => void;
  onToggleRight: () => void;
  onCloseDrawers: () => void;
  sidebar: ReactNode;
  overview: ReactNode;
  feed: ReactNode;
  composer: ReactNode;
  inspector: ReactNode;
  notices?: ReactNode;
}) {
  const workspace = state.workspace.split("/").filter(Boolean).at(-1) || state.workspace;
  useEffect(() => {
    if (!leftOpen && !rightOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCloseDrawers();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [leftOpen, onCloseDrawers, rightOpen]);

  return (
    <div className={`workbench-shell ${leftOpen ? "left-open" : ""} ${rightOpen ? "right-open" : ""}`}>
      <header className="topbar">
        <div className="topbar-left">
          <button
            type="button"
            className="icon-button nav-toggle"
            onClick={onToggleLeft}
            aria-controls="workbench-sidebar"
            aria-expanded={leftOpen}
            aria-label={`${leftOpen ? "关闭" : "打开"}会话与筛选`}
          ><Icon name="menu" /></button>
          <a className="brand" href="/" aria-label="灵眸工作台首页">
            <span className="brand-mark"><Icon name="eye" size={20} /></span>
            <strong>灵眸</strong>
          </a>
          <span className="breadcrumb"><b>{workspace}</b><i>/</i><span>{state.task?.current_step?.title || "当前任务"}</span></span>
        </div>
        <div className="topbar-actions">
          <span className={`top-status ${state.connected && streamConnected ? "online" : "offline"}`} role="status" aria-live="polite">
            <i aria-hidden="true" />Agent {state.connected ? (streamConnected ? "运行就绪" : "正在恢复") : "未连接"}
          </span>
          <span className={`security-mode security-${state.security_mode}`}>
            <Icon name="shield" size={15} />{state.security_mode === "enforce" ? "执行前阻断" : "观察模式"}
          </span>
          <button type="button" className="header-button history-button" onClick={onOpenHistory}><Icon name="history" size={15} />历史记录</button>
          <button
            type="button"
            className="header-button inspector-toggle"
            onClick={onToggleRight}
            aria-controls="workbench-inspector"
            aria-expanded={rightOpen}
          ><Icon name="inspect" size={15} />活动解释</button>
        </div>
      </header>
      <aside
        id="workbench-sidebar"
        className="workbench-sidebar"
        aria-label="会话与筛选"
        aria-hidden={!leftOpen}
        inert={!leftOpen}
      >{sidebar}</aside>
      <main className="workbench-main">
        {overview}
        {notices}
        {feed}
        {composer}
      </main>
      <aside
        id="workbench-inspector"
        className="workbench-inspector"
        aria-label="活动解释与证据"
        aria-hidden={!rightOpen}
        inert={!rightOpen}
      >{inspector}</aside>
      <button type="button" className="drawer-scrim" onClick={onCloseDrawers} aria-label="关闭侧栏" hidden={!leftOpen && !rightOpen} />
    </div>
  );
}
