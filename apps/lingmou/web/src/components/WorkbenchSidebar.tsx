import type { FeedFilter, WorkbenchState } from "../types";
import { Icon, type IconName } from "./Icon";

const filters: Array<{ key: FeedFilter; label: string; icon: IconName }> = [
  { key: "all", label: "当前会话", icon: "session" },
  { key: "needs_action", label: "需要我处理", icon: "attention" },
  { key: "changes", label: "文件修改", icon: "file" },
  { key: "tools", label: "命令与工具", icon: "terminal" },
  { key: "risk", label: "风险事件", icon: "shield" },
];

export function WorkbenchSidebar({
  state,
  filter,
  counts,
  search,
  onFilter,
  onSearch,
  onClose,
}: {
  state: WorkbenchState;
  filter: FeedFilter;
  counts: Record<FeedFilter, number>;
  search: string;
  onFilter: (filter: FeedFilter) => void;
  onSearch: (value: string) => void;
  onClose: () => void;
}) {
  const workspaceName = state.workspace.split("/").filter(Boolean).at(-1) || state.workspace;
  return (
    <div className="sidebar-content">
      <div className="drawer-heading">
        <div><h2>{workspaceName}</h2><p>会话与筛选</p></div>
        <button type="button" className="icon-button drawer-close" onClick={onClose} aria-label="关闭会话栏"><Icon name="close" /></button>
      </div>
      <label className="event-search">
        <span className="visually-hidden">搜索事件</span>
        <Icon name="search" size={17} />
        <input
          type="search"
          value={search}
          onChange={(event) => onSearch(event.target.value)}
          placeholder="搜索命令、文件、规则或工具"
        />
      </label>
      <nav className="sidebar-nav" aria-label="活动筛选">
        {filters.map((item) => (
          <button
            type="button"
            key={item.key}
            className={filter === item.key ? "active" : ""}
            onClick={() => onFilter(item.key)}
          >
            <span className="nav-icon"><Icon name={item.icon} size={16} /></span>
            <span>{item.label}</span>
            <em>{counts[item.key]}</em>
          </button>
        ))}
      </nav>
      <section className="sidebar-section history-section">
        <h3 className="section-label">运行记录</h3>
        <div className="history-row current-history">
          <span className={`run-dot ${state.active_turn_id ? "active" : ""}`} aria-hidden="true" />
          <span><strong>当前运行</strong><small>{state.thread_id?.slice(0, 12) || "尚未创建会话"}</small></span>
        </div>
        <div className="deferred-history">
          <strong>历史运行</strong>
          <p>本次升级保留当前运行回放；完整历史会话管理将在后续版本提供。</p>
        </div>
      </section>
      <section className="sidebar-section workspace-facts">
        <h3 className="section-label">运行环境</h3>
        <dl>
          <div><dt>Agent</dt><dd>{state.model || "自动选择"}</dd></div>
          <div><dt>沙箱</dt><dd>{state.sandbox}</dd></div>
          <div><dt>审批</dt><dd>{state.approval_policy}</dd></div>
        </dl>
      </section>
      <div className="privacy-note">
        <strong>本地隐私</strong>
        <p>凭据始终脱敏；提示词与回复{state.privacy.conversation_persisted ? "脱敏后落盘" : "默认只存哈希与长度"}。</p>
      </div>
    </div>
  );
}
