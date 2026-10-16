import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from "react";
import type {
  SyscallAssociation,
  SyscallDensityBucket,
  SyscallEvent,
  SyscallProcess,
  SyscallQueryResponse,
  SyscallStatus,
} from "../types";
import { Icon } from "./Icon";

type ViewPreset = "behavior" | "all";
type SuccessFilter = "all" | "success" | "failed";

export type ExplorerFilters = {
  preset: ViewPreset;
  query: string;
  syscall: string;
  category: string;
  success: SuccessFilter;
  pid: number | null;
  fromNs: number | null;
  toNs: number | null;
};

const initialFilters: ExplorerFilters = {
  preset: "behavior",
  query: "",
  syscall: "",
  category: "",
  success: "all",
  pid: null,
  fromNs: null,
  toNs: null,
};

const categoryLabels: Record<string, string> = {
  file: "文件",
  network: "网络",
  process: "进程",
  ipc: "进程间通信",
  fd: "描述符",
  diagnostic: "采集诊断",
};

const accessLabels: Record<string, string> = {
  read: "读取",
  write: "写入",
  read_write: "读写",
  metadata_read: "读取元数据",
  metadata_write: "修改元数据",
  connect: "连接",
  send: "发送",
  receive: "接收",
  execute: "执行",
  spawn: "派生进程",
  wait: "等待",
  exit: "退出",
  create: "创建",
};

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.detail || `系统调用请求失败 (${response.status})`);
  return value as T;
}

export function formatSyscallCount(value: number | null | undefined): string {
  return Number(value || 0).toLocaleString("zh-CN");
}

export function formatSyscallBytes(value: number | null | undefined): string {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function densityBucketLimitForWidth(width: number): number {
  if (width <= 480) return 8;
  if (width <= 760) return 12;
  if (width <= 900) return 16;
  return 48;
}

export function aggregateDensityBuckets(
  buckets: SyscallDensityBucket[],
  limit: number,
): SyscallDensityBucket[] {
  const boundedLimit = Math.max(1, Math.floor(limit));
  if (buckets.length <= boundedLimit) return buckets;
  const groupSize = Math.ceil(buckets.length / boundedLimit);
  const grouped: SyscallDensityBucket[] = [];
  for (let offset = 0; offset < buckets.length; offset += groupSize) {
    const group = buckets.slice(offset, offset + groupSize);
    const first = group[0];
    const last = group.at(-1)!;
    grouped.push({
      index: first.index,
      from_ns: first.from_ns,
      to_ns: last.to_ns,
      total: group.reduce((sum, bucket) => sum + bucket.total, 0),
      failed: group.reduce((sum, bucket) => sum + bucket.failed, 0),
      network: group.reduce((sum, bucket) => sum + bucket.network, 0),
      writes: group.reduce((sum, bucket) => sum + bucket.writes, 0),
    });
  }
  return grouped;
}

export function collectionPresentation(
  status: SyscallStatus | null,
  streamConnected: boolean,
  statusError: string | null,
): { className: string; title: string; detail: string } {
  if (statusError) {
    return {
      className: "degraded",
      title: "采集状态更新失败",
      detail: status ? "正在显示上次已知状态，暂不能确认当前完整性" : "无法确认采集是否启用；不会把未知状态写成未启用",
    };
  }
  if (!status) {
    return { className: "loading", title: "正在读取系统调用状态", detail: "正在核对采集器、索引与独立实时流" };
  }
  const collection = status.collection;
  if (!collection.enabled) {
    return { className: "disabled", title: "系统调用采集未启用", detail: "下一次启动 monitor 时加入 --os-audit auto" };
  }
  if (collection.known_loss) {
    return { className: "degraded", title: "采集存在缺口", detail: "当前记录仍可查询，但不能据此证明某个调用绝对没有发生" };
  }
  if (collection.status === "completed") {
    return { className: "complete", title: "系统调用采集已完成", detail: "当前 Run 的索引已同步到原始记录" };
  }
  return {
    className: "running",
    title: "系统调用正在采集",
    detail: streamConnected ? "索引与独立实时流均已连接" : "索引可查询，实时流正在恢复",
  };
}

export function indexHealthPresentation(status: SyscallStatus | null): {
  value: string;
  detail: string;
  warning: boolean;
} {
  const parseErrors = Number(status?.index.parse_errors || 0);
  const lag = Number(status?.index.lag_events || 0);
  if (parseErrors > 0) {
    return { value: `${formatSyscallCount(parseErrors)} 条异常`, detail: `索引滞后 ${formatSyscallCount(lag)} 条`, warning: true };
  }
  if (status?.index.partial_line) {
    return { value: "等待完整行", detail: "原始末行仍在写入，暂不索引", warning: false };
  }
  return {
    value: formatSyscallCount(lag),
    detail: status?.collection.known_loss ? "存在采集缺口" : "索引可重建",
    warning: lag > 0,
  };
}

function formatRate(value: number | null | undefined): string {
  const rate = Number(value || 0);
  return rate >= 10 ? `${Math.round(rate)}/秒` : `${rate.toFixed(1)}/秒`;
}

function formatTime(wallTimeNs: number | null | undefined, includeDate = false): string {
  if (!wallTimeNs) return "时间未知";
  const date = new Date(wallTimeNs / 1_000_000);
  if (Number.isNaN(date.valueOf())) return "时间未知";
  return new Intl.DateTimeFormat("zh-CN", {
    ...(includeDate ? { month: "2-digit", day: "2-digit" } : {}),
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
    hour12: false,
  }).format(date);
}

function formatDuration(value: number | null | undefined): string {
  if (value == null) return "—";
  if (value < 1_000) return `${value} ns`;
  if (value < 1_000_000) return `${(value / 1_000).toFixed(value < 10_000 ? 1 : 0)} μs`;
  if (value < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)} ms`;
  return `${(value / 1_000_000_000).toFixed(2)} s`;
}

export function syscallTarget(event: SyscallEvent): string {
  return event.endpoint_text || event.path || (event.fd != null ? `fd ${event.fd}` : "没有可显示的对象");
}

function resultLabel(event: SyscallEvent): string {
  if (event.success === false) return event.errno ? `失败 · ${event.errno}` : "失败";
  if (event.success === true) return event.result == null ? "成功" : `成功 · ${String(event.result)}`;
  return event.synthetic ? "采集诊断" : "结果未知";
}

export function syscallMatchesFilters(event: SyscallEvent, filters: ExplorerFilters, itemId?: string | null): boolean {
  if (filters.pid != null && event.pid !== filters.pid) return false;
  if (filters.category && event.category !== filters.category) return false;
  if (filters.success === "success" && event.success !== true) return false;
  if (filters.success === "failed" && event.success !== false) return false;
  if (filters.syscall && !event.syscall.toLocaleLowerCase().includes(filters.syscall.trim().toLocaleLowerCase())) return false;
  if (filters.fromNs != null && event.wall_time_ns < filters.fromNs) return false;
  if (filters.toNs != null && event.wall_time_ns > filters.toNs) return false;
  if (itemId && event.agent_item?.item_id !== itemId) return false;
  if (filters.preset === "behavior" && !isBehaviorEvent(event)) return false;
  const needle = filters.query.trim().toLocaleLowerCase();
  if (!needle) return true;
  return [event.comm, event.syscall, event.path, event.endpoint_text, event.errno]
    .filter(Boolean)
    .some((value) => String(value).toLocaleLowerCase().includes(needle));
}

export function isBehaviorEvent(event: SyscallEvent): boolean {
  if (event.synthetic) return true;
  if (event.category === "process" && ["execute", "spawn"].includes(event.access || "")) {
    return event.success !== false || !["ENOENT", "ENOTDIR"].includes(event.errno || "");
  }
  if (event.category === "network") return Boolean(event.endpoint_text);
  if (event.category !== "file") return false;
  if (["write", "read_write", "metadata_write"].includes(event.access || "")) return true;
  if (!["read", "metadata_read"].includes(event.access || "")) return false;
  if (event.path_scope === "workspace") return true;
  const path = (event.path || "").toLocaleLowerCase();
  return [
    "/.ssh/", "/.aws/", "/.config/gcloud/", "/.kube/", "/.docker/config.json",
    "/.git-credentials", "/.npmrc", "/.pypirc", "/etc/passwd", "/etc/shadow",
    "/etc/sudoers", "/environ",
  ].some((marker) => path.includes(marker)) || path.endsWith("/.env") || path.includes("/.env.");
}

function queryPath(filters: ExplorerFilters, itemId?: string | null, beforeSeq?: number | null): string {
  const params = new URLSearchParams({ limit: "300", order: "desc" });
  if (beforeSeq) params.set("before_seq", String(beforeSeq));
  if (filters.pid != null) params.set("pid", String(filters.pid));
  if (filters.query.trim()) params.set("q", filters.query.trim());
  if (filters.syscall.trim()) params.append("syscall", filters.syscall.trim());
  if (filters.category) params.set("category", filters.category);
  if (filters.success !== "all") params.set("success", String(filters.success === "success"));
  if (filters.preset === "behavior") params.set("behavior_only", "true");
  if (filters.fromNs != null) params.set("from_ns", String(filters.fromNs));
  if (filters.toNs != null) params.set("to_ns", String(filters.toNs));
  if (itemId) params.set("item_id", itemId);
  return `/api/v1/syscalls?${params}`;
}

function densityPath(filters: ExplorerFilters): string {
  const params = new URLSearchParams({ buckets: "96" });
  if (filters.pid != null) params.set("pid", String(filters.pid));
  if (filters.category) params.set("category", filters.category);
  if (filters.preset === "behavior") params.set("behavior_only", "true");
  return `/api/v1/syscalls/density?${params}`;
}

function CollectionState({ status, streamConnected, statusError }: { status: SyscallStatus | null; streamConnected: boolean; statusError: string | null }) {
  const state = collectionPresentation(status, streamConnected, statusError);
  return (
    <div className={`syscall-collection-state state-${state.className}`} role="status">
      <span className="syscall-state-icon"><Icon name={state.className === "degraded" ? "warning" : "syscall"} size={22} /></span>
      <div><strong>{state.title}</strong><small>{state.detail}</small></div>
    </div>
  );
}

function DensityRail({
  buckets,
  selectedFrom,
  onSelect,
}: {
  buckets: SyscallDensityBucket[];
  selectedFrom: number | null;
  onSelect: (bucket: SyscallDensityBucket) => void;
}) {
  const [bucketLimit, setBucketLimit] = useState(() => densityBucketLimitForWidth(window.innerWidth));
  const buttonRefs = useRef<Array<HTMLButtonElement | null>>([]);
  useEffect(() => {
    const update = () => setBucketLimit(densityBucketLimitForWidth(window.innerWidth));
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);
  const displayBuckets = useMemo(() => aggregateDensityBuckets(buckets, bucketLimit), [bucketLimit, buckets]);
  const maximum = Math.max(1, ...displayBuckets.map((bucket) => bucket.total));
  const first = displayBuckets.find((bucket) => bucket.total)?.from_ns;
  const last = [...displayBuckets].reverse().find((bucket) => bucket.total)?.to_ns;
  const selectedIndex = displayBuckets.findIndex((bucket) => selectedFrom === bucket.from_ns);
  const rovingIndex = selectedIndex >= 0 ? selectedIndex : Math.max(0, displayBuckets.findIndex((bucket) => bucket.total > 0));
  const moveFocus = (current: number, key: string) => {
    let next = current;
    if (key === "ArrowRight" || key === "ArrowDown") next = Math.min(displayBuckets.length - 1, current + 1);
    else if (key === "ArrowLeft" || key === "ArrowUp") next = Math.max(0, current - 1);
    else if (key === "Home") next = 0;
    else if (key === "End") next = displayBuckets.length - 1;
    else return false;
    onSelect(displayBuckets[next]);
    window.requestAnimationFrame(() => buttonRefs.current[next]?.focus());
    return true;
  };
  return (
    <section className="syscall-density-panel" aria-labelledby="syscall-density-title">
      <div className="syscall-section-heading">
        <div><h2 id="syscall-density-title">时间密度</h2><p>点击一个时间片，只查看该窗口内已捕获的调用</p></div>
        <div className="density-legend" aria-label="密度图图例"><span className="total">全部</span><span className="network">网络</span><span className="failed">失败</span></div>
      </div>
      {displayBuckets.some((bucket) => bucket.total) ? (
        <>
          <div className="density-bars" role="group" aria-label="系统调用时间密度" style={{ gridTemplateColumns: `repeat(${displayBuckets.length}, minmax(0, 1fr))` }}>
            {displayBuckets.map((bucket, index) => {
              const height = Math.max(4, (bucket.total / maximum) * 100);
              const style = { "--bar-height": `${height}%` } as CSSProperties;
              return (
                <button
                  type="button"
                  className={selectedFrom === bucket.from_ns ? "selected" : ""}
                  key={bucket.index}
                  style={style}
                  onClick={() => onSelect(bucket)}
                  onKeyDown={(event) => {
                    if (moveFocus(index, event.key)) event.preventDefault();
                  }}
                  ref={(element) => { buttonRefs.current[index] = element; }}
                  tabIndex={index === rovingIndex ? 0 : -1}
                  aria-pressed={selectedFrom === bucket.from_ns}
                  aria-label={`${formatTime(bucket.from_ns)}：${bucket.total} 条调用，${bucket.network} 条网络，${bucket.failed} 条失败`}
                >
                  <span className="density-total" />
                  {bucket.network > 0 && <span className="density-network" style={{ height: `${Math.max(3, bucket.network / Math.max(1, bucket.total) * height)}%` }} />}
                  {bucket.failed > 0 && <span className="density-failed" />}
                </button>
              );
            })}
          </div>
          <div className="density-axis"><time>{formatTime(first)}</time><span>当前 Run</span><time>{formatTime(last)}</time></div>
        </>
      ) : <div className="syscall-inline-empty">当前筛选下还没有可绘制的调用。</div>}
    </section>
  );
}

function ProcessTree({
  processes,
  selectedPid,
  onSelect,
}: {
  processes: SyscallProcess[];
  selectedPid: number | null;
  onSelect: (pid: number | null) => void;
}) {
  const [search, setSearch] = useState("");
  const visible = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase();
    return processes
      .filter((process) => !needle || String(process.pid).includes(needle) || (process.comm || "").toLocaleLowerCase().includes(needle))
      .slice(0, 120);
  }, [processes, search]);
  return (
    <aside className="syscall-process-panel" aria-labelledby="syscall-process-title">
      <div className="syscall-pane-heading"><div><h2 id="syscall-process-title">进程树</h2><p>{formatSyscallCount(processes.length)} 个已观察 PID</p></div></div>
      <label className="syscall-compact-search">
        <Icon name="search" size={16} />
        <span className="visually-hidden">搜索进程</span>
        <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="进程名或 PID" />
      </label>
      <div className="syscall-process-list">
        <button type="button" className={selectedPid == null ? "active" : ""} onClick={() => onSelect(null)}>
          <span className="process-node-mark"><Icon name="agents" size={16} /></span>
          <span><strong>全部进程</strong><small>不限制 PID</small></span>
          <em>{formatSyscallCount(processes.reduce((sum, process) => sum + process.total, 0))}</em>
        </button>
        {visible.map((process) => (
          <button
            type="button"
            className={selectedPid === process.pid ? "active" : ""}
            key={process.pid}
            onClick={() => onSelect(process.pid)}
            style={{ paddingInlineStart: `${10 + Math.min(process.depth, 4) * 11}px` }}
          >
            <span className={`process-node-mark ${process.network ? "has-network" : ""}`}><Icon name={process.network ? "network" : "terminal"} size={15} /></span>
            <span><strong>{process.comm || "未知进程"}</strong><small>PID {process.pid}{process.ppid ? ` · PPID ${process.ppid}` : ""}</small></span>
            <em>{formatSyscallCount(process.total)}</em>
          </button>
        ))}
      </div>
      <p className="process-tree-boundary">树关系来自 PID / PPID 事实；名称取该 PID 的最近可用进程标识。</p>
    </aside>
  );
}

function VirtualSyscallTable({
  rows,
  selectedSeq,
  onSelect,
}: {
  rows: SyscallEvent[];
  selectedSeq: number | null;
  onSelect: (event: SyscallEvent) => void;
}) {
  const rowHeight = 48;
  const viewportHeight = 478;
  const overscan = 7;
  const [scrollTop, setScrollTop] = useState(0);
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(rows.length, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);
  const visible = rows.slice(start, end);
  const activate = (event: SyscallEvent, keyboardEvent: KeyboardEvent<HTMLDivElement>) => {
    if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
      keyboardEvent.preventDefault();
      onSelect(event);
    }
  };
  return (
    <div className="syscall-table" role="table" aria-label="系统调用列表" aria-rowcount={rows.length}>
      <div className="syscall-table-header" role="row">
        <span role="columnheader">时间</span><span role="columnheader">进程</span><span role="columnheader">调用</span><span role="columnheader">目标</span><span role="columnheader">结果</span><span role="columnheader">耗时</span>
      </div>
      <div className="syscall-table-viewport" onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}>
        {rows.length ? (
          <div className="syscall-table-spacer" style={{ height: `${rows.length * rowHeight}px` }}>
            <div className="syscall-visible-rows" style={{ transform: `translateY(${start * rowHeight}px)` }}>
              {visible.map((event) => (
                <div
                  role="row"
                  tabIndex={0}
                  aria-selected={selectedSeq === event.seq}
                  className={`syscall-table-row ${selectedSeq === event.seq ? "selected" : ""} ${event.success === false ? "failed" : ""}`}
                  key={event.seq}
                  onClick={() => onSelect(event)}
                  onKeyDown={(keyboardEvent) => activate(event, keyboardEvent)}
                >
                  <span role="cell"><time>{formatTime(event.wall_time_ns)}</time><small>#{event.seq}</small></span>
                  <span role="cell"><strong>{event.comm || "未知"}</strong><small>{event.pid != null ? `PID ${event.pid}${event.tid !== event.pid ? ` / TID ${event.tid}` : ""}` : "无 PID"}</small></span>
                  <span role="cell"><code>{event.syscall}</code><small>{accessLabels[event.access || ""] || event.access || categoryLabels[event.category || ""] || "其他"}</small></span>
                  <span role="cell" className="syscall-target-cell" title={syscallTarget(event)}>{syscallTarget(event)}</span>
                  <span role="cell"><strong className={event.success === false ? "result-failed" : "result-ok"}>{resultLabel(event)}</strong>{event.agent_item && <small className="agent-link-marker">已关联 Item</small>}</span>
                  <span role="cell" className="syscall-duration">{formatDuration(event.duration_ns)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : <div className="syscall-table-empty"><Icon name="search" size={24} /><strong>没有匹配的系统调用</strong><p>清除筛选，或等待当前 Run 产生新的调用。</p></div>}
      </div>
    </div>
  );
}

function SyscallDetail({ event, onSelectNeighbor, rows }: { event: SyscallEvent | null; onSelectNeighbor: (event: SyscallEvent) => void; rows: SyscallEvent[] }) {
  if (!event) {
    return (
      <aside className="syscall-detail-panel"><div className="syscall-detail-empty"><Icon name="inspect" size={28} /><strong>选择一条调用</strong><p>这里会显示脱敏参数、对象、结果、进程和 Agent 关联依据。</p></div></aside>
    );
  }
  const index = rows.findIndex((candidate) => candidate.seq === event.seq);
  const newer = index > 0 ? rows[index - 1] : null;
  const older = index >= 0 && index < rows.length - 1 ? rows[index + 1] : null;
  const agent = event.agent_item;
  return (
    <aside className="syscall-detail-panel" aria-labelledby="syscall-detail-title">
      <div className="syscall-detail-heading">
        <div><h2 id="syscall-detail-title">{event.syscall}</h2><p>调用 #{event.seq} · {formatTime(event.wall_time_ns, true)}</p></div>
        <span className={`syscall-result-badge ${event.success === false ? "failed" : event.synthetic ? "diagnostic" : "success"}`}>{resultLabel(event)}</span>
      </div>
      <div className="syscall-detail-nav">
        <button type="button" disabled={!newer} onClick={() => newer && onSelectNeighbor(newer)}>较新</button>
        <button type="button" disabled={!older} onClick={() => older && onSelectNeighbor(older)}>较早</button>
      </div>
      <section>
        <h3>系统实际观察到</h3>
        <div className="syscall-observation">
          <span><Icon name={event.category === "network" ? "network" : event.category === "process" ? "terminal" : "file"} size={18} /></span>
          <div><strong>{accessLabels[event.access || ""] || categoryLabels[event.category || ""] || "系统调用"}</strong><code>{syscallTarget(event)}</code></div>
        </div>
        <dl className="syscall-detail-grid">
          <div><dt>PID / TID</dt><dd>{event.pid ?? "无"} / {event.tid ?? "无"}</dd></div>
          <div><dt>PPID</dt><dd>{event.ppid ?? "无"}</dd></div>
          <div><dt>进程</dt><dd>{event.comm || "未知"}</dd></div>
          <div><dt>分类</dt><dd>{categoryLabels[event.category || ""] || event.category || "其他"}</dd></div>
          <div><dt>文件范围</dt><dd>{event.path_scope === "workspace" ? "工作区内" : event.path_scope === "external" ? "工作区外" : event.path_scope || "不适用"}</dd></div>
          <div><dt>耗时</dt><dd>{formatDuration(event.duration_ns)}</dd></div>
          {event.fd != null && <div><dt>文件描述符</dt><dd>{event.fd}</dd></div>}
          {event.bytes != null && <div><dt>字节数</dt><dd>{formatSyscallCount(event.bytes)}</dd></div>}
        </dl>
      </section>
      <section>
        <h3>安全参数</h3>
        <pre className="syscall-safe-arguments">{event.arguments || "采集器没有保留参数"}</pre>
        <p className="syscall-privacy-note"><Icon name="lock" size={15} />read/write 缓冲区正文和 exec argv 不进入索引；凭据继续脱敏。</p>
      </section>
      <section>
        <h3>Agent 证据关联</h3>
        {agent ? (
          <div className="syscall-agent-association">
            <span className={`association-tier tier-${agent.confidence_tier}`}>{agent.confidence_tier === "fact" ? "事实关联" : "强关联"}</span>
            <strong>{agent.title || agent.item_id}</strong>
            <p>{agent.basis === "exact_pid_and_item_lifecycle" ? "精确 PID 与 Agent Item 生命周期同时匹配。" : "该 PID 属于命令启动的后代进程树，并落在 Item 生命周期内。"}</p>
            <a href={`#/workbench?item_id=${encodeURIComponent(agent.item_id)}`}><Icon name="arrowRight" size={15} />回到 Agent 活动</a>
          </div>
        ) : (
          <div className="syscall-unassociated"><strong>未关联</strong><p>没有可靠的 PID 与 Agent Item 生命周期交叉证据。时间接近不会被写成因果关系。</p></div>
        )}
      </section>
    </aside>
  );
}

export function SyscallExplorer({ itemId }: { itemId?: string | null }) {
  const [status, setStatus] = useState<SyscallStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [rows, setRows] = useState<SyscallEvent[]>([]);
  const [processes, setProcesses] = useState<SyscallProcess[]>([]);
  const [density, setDensity] = useState<SyscallDensityBucket[]>([]);
  const [association, setAssociation] = useState<SyscallAssociation | null>(null);
  const [filters, setFilters] = useState<ExplorerFilters>(initialFilters);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [filteredTotal, setFilteredTotal] = useState(0);
  const [viewSummary, setViewSummary] = useState<SyscallQueryResponse["view"] | null>(null);
  const [nextBeforeSeq, setNextBeforeSeq] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [streamAfter, setStreamAfter] = useState<number | null>(null);
  const [resetNonce, setResetNonce] = useState(0);
  const streamCursor = useRef(0);

  const selected = rows.find((event) => event.seq === selectedSeq) || rows[0] || null;

  const updateFilters = (patch: Partial<ExplorerFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
  };

  const loadRows = useCallback(async (append = false, beforeSeq: number | null = null) => {
    const response = await requestJson<SyscallQueryResponse>(queryPath(filters, itemId, beforeSeq));
    setAssociation(response.association || null);
    setFilteredTotal(Number(response.total || 0));
    setViewSummary(response.view || null);
    setNextBeforeSeq(response.page.next_before_seq || null);
    setHasMore(response.page.has_more);
    setRows((current) => {
      const incoming = append ? [...current, ...response.items] : response.items;
      const unique = new Map(incoming.map((event) => [event.seq, event]));
      return [...unique.values()].sort((a, b) => b.seq - a.seq).slice(0, 2_000);
    });
    if (!append) setSelectedSeq(response.items[0]?.seq || null);
  }, [filters, itemId]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(() => {
      void loadRows()
        .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason)); })
        .finally(() => { if (!cancelled) setLoading(false); });
    }, 160);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [loadRows, resetNonce]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const refresh = async () => {
      try {
        const next = await requestJson<SyscallStatus>("/api/v1/syscalls/status");
        if (cancelled) return;
        setStatus(next);
        setStatusError(null);
        if (streamAfter == null) {
          streamCursor.current = next.index.last_seq;
          setStreamAfter(next.index.last_seq);
        }
      } catch (reason) {
        if (!cancelled) {
          const message = reason instanceof Error ? reason.message : String(reason);
          setStatusError(message);
          setError(message);
        }
      }
    };
    void refresh();
    timer = window.setInterval(refresh, 1_000);
    return () => { cancelled = true; if (timer) window.clearInterval(timer); };
  }, [streamAfter]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const refresh = async () => {
      try {
        const response = await requestJson<{ items: SyscallProcess[] }>("/api/v1/syscalls/processes");
        if (!cancelled) setProcesses(response.items);
      } catch (reason) {
        if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason));
      }
    };
    void refresh();
    timer = window.setInterval(refresh, 5_000);
    return () => { cancelled = true; if (timer) window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void requestJson<{ items: SyscallDensityBucket[] }>(densityPath(filters))
        .then((response) => { if (!cancelled) setDensity(response.items); })
        .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason)); });
    }, 120);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [filters.pid, filters.category, filters.preset, resetNonce]);

  useEffect(() => {
    if (streamAfter == null) return;
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let disposed = false;
    const connect = () => {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      const streamParams = new URLSearchParams({ after_seq: String(streamCursor.current) });
      if (filters.preset === "behavior") streamParams.set("behavior_only", "true");
      socket = new WebSocket(`${protocol}://${location.host}/api/v1/syscalls/ws?${streamParams}`);
      socket.onopen = () => setStreamConnected(true);
      socket.onmessage = (message) => {
        const data = JSON.parse(message.data) as { type: string; events?: SyscallEvent[]; status?: SyscallStatus; last_seq?: number; detail?: string };
        if (data.type === "status" && data.status) setStatus(data.status);
        if (data.type === "heartbeat" && data.last_seq != null) {
          streamCursor.current = Math.max(streamCursor.current, data.last_seq);
        }
        if (data.type === "reset") {
          streamCursor.current = 0;
          setResetNonce((value) => value + 1);
        }
        if (data.type === "error") setError(data.detail || "系统调用实时流发生错误");
        if (data.type === "batch" && data.events?.length) {
          streamCursor.current = Math.max(streamCursor.current, ...data.events.map((event) => event.seq));
          const visible = data.events.filter((event) => syscallMatchesFilters(event, filters, itemId));
          if (visible.length) {
            setRows((current) => {
              const unique = new Map([...visible, ...current].map((event) => [event.seq, event]));
              return [...unique.values()].sort((a, b) => b.seq - a.seq).slice(0, 2_000);
            });
            setFilteredTotal((value) => value + visible.length);
          }
        }
      };
      socket.onclose = () => {
        setStreamConnected(false);
        if (!disposed) retry = window.setTimeout(connect, 1_000);
      };
      socket.onerror = () => socket?.close();
    };
    connect();
    return () => { disposed = true; if (retry) window.clearTimeout(retry); socket?.close(); };
  }, [streamAfter, filters, itemId]);

  const loadOlder = async () => {
    if (!hasMore || !nextBeforeSeq || loadingOlder) return;
    setLoadingOlder(true);
    try {
      await loadRows(true, nextBeforeSeq);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoadingOlder(false);
    }
  };

  const rebuild = async () => {
    setLoading(true);
    setError(null);
    try {
      await requestJson("/api/v1/syscalls/rebuild", { method: "POST" });
      streamCursor.current = 0;
      setResetNonce((value) => value + 1);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  };

  const clearFilters = () => {
    setFilters(initialFilters);
    if (itemId) window.location.hash = "/syscalls";
  };

  const filterActive = Boolean(
    itemId || filters.query || filters.syscall || filters.category || filters.success !== "all"
    || filters.pid != null || filters.fromNs != null || filters.preset !== "behavior"
  );
  const indexHealth = indexHealthPresentation(status);

  return (
    <div className="syscall-explorer">
      <header className="syscall-page-header">
        <div>
          <h1>系统调用证据台</h1>
          <p>默认只看能解释行为的进程、文件与网络节点；需要时再展开全部原始调用。</p>
        </div>
        <div className="syscall-header-actions">
          <span className="scope-chip"><Icon name="session" size={15} />{status?.scope_label || "当前 Run · app-server 后代进程"}</span>
          <span className="profile-chip"><Icon name="syscall" size={15} />{status?.profile_label || "采集档位读取中"}</span>
          <button type="button" onClick={() => void rebuild()} disabled={loading}><Icon name="refresh" size={15} />重建索引</button>
        </div>
      </header>

      {error && <div className="syscall-error" role="alert"><Icon name="warning" size={18} /><span><strong>系统调用视图暂时无法更新</strong>{error}</span><button type="button" onClick={() => setError(null)}>关闭</button></div>}

      <section className="syscall-health-strip" aria-label="系统调用采集健康度">
        <CollectionState status={status} streamConnected={streamConnected} statusError={statusError} />
        <dl>
          <div><dt>已捕获</dt><dd>{formatSyscallCount(status?.collection.captured_events)}</dd><small>{status?.collection.filtered_events ? `采集端已降噪 ${formatSyscallCount(status.collection.filtered_events)} 条` : status?.profile_label || "读取档位"}</small></div>
          <div><dt>当前速率</dt><dd>{formatRate(status?.collection.rate_per_second)}</dd><small>{streamConnected ? "实时流在线" : "等待重连"}</small></div>
          <div><dt>进程</dt><dd>{formatSyscallCount(status?.summary.pids)}</dd><small>PID 去重</small></div>
          <div><dt>失败调用</dt><dd className={status?.summary.failed ? "has-failures" : ""}>{formatSyscallCount(status?.summary.failed)}</dd><small>返回 errno</small></div>
          <div><dt>原始记录</dt><dd>{formatSyscallBytes(status?.collection.raw_bytes)}</dd><small>脱敏 JSONL</small></div>
          <div><dt>索引状态</dt><dd className={indexHealth.warning ? "has-failures" : ""}>{indexHealth.value}</dd><small>{indexHealth.detail}</small></div>
        </dl>
      </section>

      <DensityRail
        buckets={density}
        selectedFrom={filters.fromNs}
        onSelect={(bucket) => updateFilters({ fromNs: bucket.from_ns, toNs: bucket.to_ns })}
      />

      <section className="syscall-workbench" aria-label="系统调用查询工作区">
        <ProcessTree processes={processes} selectedPid={filters.pid} onSelect={(pid) => updateFilters({ pid })} />
        <main className="syscall-list-panel">
          <div className="syscall-list-heading">
            <div><h2>{filters.preset === "behavior" ? "行为轨迹" : "原始调用"}</h2><p>{loading ? "正在同步索引…" : filters.preset === "behavior" && viewSummary?.matching_raw != null ? `${formatSyscallCount(filteredTotal)} 个行为节点 · 从 ${formatSyscallCount(viewSummary.matching_raw)} 条匹配调用中过滤与归并` : `${formatSyscallCount(filteredTotal)} 条匹配 · 浏览器最多保留最近 2,000 条`}</p></div>
            <div className="syscall-presets" role="group" aria-label="保存视图">
              <button type="button" className={filters.preset === "behavior" ? "active" : ""} onClick={() => updateFilters({ preset: "behavior" })}>行为轨迹</button>
              <button type="button" className={filters.preset === "all" ? "active" : ""} onClick={() => updateFilters({ preset: "all" })}>全部原始</button>
            </div>
          </div>
          <div className="syscall-filter-bar">
            <label className="syscall-main-search"><Icon name="search" size={17} /><span className="visually-hidden">搜索系统调用</span><input value={filters.query} onChange={(event) => updateFilters({ query: event.target.value })} placeholder="搜索调用、进程、路径或网络目标" /></label>
            <label><span>调用</span><input value={filters.syscall} onChange={(event) => updateFilters({ syscall: event.target.value })} placeholder="如 connect" /></label>
            <label><span>类别</span><select value={filters.category} onChange={(event) => updateFilters({ category: event.target.value })}><option value="">全部类别</option><option value="file">文件</option><option value="network">网络</option><option value="process">进程</option><option value="ipc">IPC</option><option value="diagnostic">诊断</option></select></label>
            <label><span>结果</span><select value={filters.success} onChange={(event) => updateFilters({ success: event.target.value as SuccessFilter })}><option value="all">全部结果</option><option value="success">成功</option><option value="failed">失败</option></select></label>
            <button type="button" className="clear-syscall-filters" disabled={!filterActive} onClick={clearFilters}>清除</button>
          </div>
          {(itemId || filters.pid != null || filters.fromNs != null) && (
            <div className="syscall-active-filters" aria-label="当前筛选">
              {itemId && <span>Agent Item · {association?.title || itemId}<a href="#/syscalls" aria-label="清除 Agent Item 筛选"><Icon name="close" size={13} /></a></span>}
              {filters.pid != null && <span>PID {filters.pid}<button type="button" onClick={() => updateFilters({ pid: null })} aria-label="清除 PID 筛选"><Icon name="close" size={13} /></button></span>}
              {filters.fromNs != null && <span>{formatTime(filters.fromNs)} – {formatTime(filters.toNs)}<button type="button" onClick={() => updateFilters({ fromNs: null, toNs: null })} aria-label="清除时间筛选"><Icon name="close" size={13} /></button></span>}
            </div>
          )}
          {itemId && association?.availability === "available_unassociated" && <div className="syscall-association-warning"><Icon name="warning" size={17} /><span><strong>{association.pid == null ? "该 Agent Item 没有 PID，未进行时间窗归因" : "该 Agent Item 的 PID 未被 OS 审计观察到"}</strong>{association.reason}</span></div>}
          <VirtualSyscallTable rows={rows} selectedSeq={selected?.seq || null} onSelect={(event) => setSelectedSeq(event.seq)} />
          <div className="syscall-pagination">
            <span>{rows.length ? `已加载 ${formatSyscallCount(rows.length)} 条` : "没有已加载记录"}</span>
            <button type="button" disabled={!hasMore || loadingOlder} onClick={() => void loadOlder()}>{loadingOlder ? "正在加载…" : hasMore ? "加载更早记录" : "已到当前筛选起点"}</button>
          </div>
        </main>
        <SyscallDetail event={selected} rows={rows} onSelectNeighbor={(event) => setSelectedSeq(event.seq)} />
      </section>

      <footer className="syscall-boundary-note">
        <Icon name="lock" size={17} />
        <div><strong>本地证据边界</strong><p>这里只覆盖当前 Run 中 Codex app-server 及其后代进程；行为轨迹会过滤例行外部读取、PATH 探测并按端点时间窗归并网络重复，但“全部原始”仍可核对当前档位实际保留的调用。缺失 PID 时显示“未关联”，有意过滤与采集缺口分开统计。</p></div>
      </footer>
    </div>
  );
}
