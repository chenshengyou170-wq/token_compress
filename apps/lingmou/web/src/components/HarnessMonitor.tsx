import { useEffect, useMemo, useState } from "react";
import type { HarnessLayer, HarnessMonitorSnapshot, HarnessTraceRecord } from "../types";
import { Icon, type IconName } from "./Icon";

const layerIcons: Record<HarnessLayer["id"], IconName> = {
  protocol: "link",
  harness: "session",
  os: "syscall",
  filesystem: "file",
};

const statusLabels: Record<string, string> = {
  running: "采集中",
  completed: "已完成",
  degraded: "有缺口",
  disabled: "未启用",
  unavailable: "不可用",
  failed: "已失败",
};

function formatCount(value: number | null | undefined): string {
  return new Intl.NumberFormat("zh-CN").format(Number(value || 0));
}

function formatTime(value: string | null | undefined, withDate = false): string {
  if (!value) return "尚无记录";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "时间未知";
  return new Intl.DateTimeFormat("zh-CN", {
    ...(withDate ? { month: "2-digit", day: "2-digit" } : {}),
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatDuration(value: number | null | undefined): string {
  if (value == null) return "—";
  if (value < 1) return `${Math.max(value * 1_000, 0).toFixed(0)} μs`;
  if (value < 1_000) return `${value.toFixed(value < 10 ? 2 : 1)} ms`;
  return `${(value / 1_000).toFixed(2)} s`;
}

function statusCopy(status: string | undefined): { title: string; detail: string } {
  if (status === "running") {
    return {
      title: "Harness 内部遥测正在采集",
      detail: "灵眸正在把 Harness 自报 Trace 与协议、系统调用和工作区证据放到同一个当前 Run 中。",
    };
  }
  if (status === "completed") {
    return {
      title: "本次 Harness 采集已经完成",
      detail: "下面保留的是该 Run 已落盘的安全字段，可以继续核对内部阶段与跨层证据。",
    };
  }
  if (status === "degraded") {
    return {
      title: "Harness 证据存在采集缺口",
      detail: "已记录的证据仍然可用，但不能用缺失记录证明某个内部操作从未发生。",
    };
  }
  if (status === "disabled") {
    return {
      title: "Harness 内部遥测未启用",
      detail: "下次启动 monitor 时加入 --harness-telemetry otel，即可接收 Trace-safe OTLP 数据。",
    };
  }
  if (status === "failed") {
    return {
      title: "Harness 内部遥测采集失败",
      detail: "已落盘证据仍可查看，但当前采集不再推进。请检查 monitor 日志，修复后重新启动本次监控。",
    };
  }
  return {
    title: "暂时无法确认 Harness 遥测状态",
    detail: "当前 Run 没有可读取的 Harness 配置或证据；页面不会把未知状态写成正常。",
  };
}

function attributeSummary(record: HarnessTraceRecord): string {
  const attributes = record.attributes || {};
  const parts: string[] = [];
  if (attributes["rpc.method"]) parts.push(`RPC ${String(attributes["rpc.method"])}`);
  if (attributes.tool_name) parts.push(`工具 ${String(attributes.tool_name)}`);
  if (attributes.model) parts.push(`模型 ${String(attributes.model)}`);
  if (attributes["http.response.status_code"]) {
    parts.push(`HTTP ${String(attributes["http.response.status_code"])}`);
  }
  if (attributes.outcome) parts.push(String(attributes.outcome));
  return parts.join(" · ") || "安全字段已收敛，无正文内容";
}

async function fetchHarness(): Promise<HarnessMonitorSnapshot> {
  const response = await fetch("/api/v1/harness", { headers: { Accept: "application/json" } });
  const value = await response.json().catch(() => ({})) as HarnessMonitorSnapshot & { detail?: string };
  if (!response.ok) throw new Error(value.detail || `Harness 状态读取失败 (${response.status})`);
  return value;
}

export function HarnessMonitor() {
  const [snapshot, setSnapshot] = useState<HarnessMonitorSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const refresh = async () => {
      try {
        const next = await fetchHarness();
        if (!stopped) {
          setSnapshot(next);
          setError(null);
        }
      } catch (reason) {
        if (!stopped) setError(reason instanceof Error ? reason.message : String(reason));
      } finally {
        if (!stopped) {
          setRefreshing(false);
          timer = window.setTimeout(refresh, 1_500);
        }
      }
    };
    void refresh();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [refreshKey]);

  const presentation = statusCopy(snapshot?.status);
  const maxOperationCount = useMemo(
    () => Math.max(1, ...(snapshot?.operations || []).map((item) => item.count)),
    [snapshot?.operations],
  );
  const status = snapshot?.status || "loading";
  const isRunning = status === "running";

  const refreshNow = () => {
    setRefreshing(true);
    setRefreshKey((value) => value + 1);
  };

  return (
    <main className="harness-monitor">
      <header className="harness-page-header">
        <div>
          <h1>Harness 监控</h1>
          <p>查看 Codex Harness 自身如何调度请求，并用协议、内部 Trace、系统调用和工作区变更交叉核对。</p>
        </div>
        <div className="harness-header-actions">
          <span className={`harness-status-chip status-${status}`} role="status" aria-live="polite" aria-atomic="true">
            <i aria-hidden="true" />
            {refreshing && !snapshot ? "正在读取" : statusLabels[status] || "状态未知"}
          </span>
          <button type="button" onClick={refreshNow} disabled={refreshing}>
            <Icon name="refresh" size={16} />
            {refreshing ? "刷新中" : "立即刷新"}
          </button>
        </div>
      </header>

      {error && (
        <div className="harness-error" role="alert">
          <span><Icon name="warning" size={19} /></span>
          <div><strong>Harness 状态更新失败</strong><p>{error}</p></div>
          <button type="button" onClick={refreshNow}>重试</button>
        </div>
      )}

      <section className={`harness-signal status-${status}`}>
        <div className="harness-signal-copy">
          <span className={`harness-live-mark ${isRunning ? "is-live" : ""}`} aria-hidden="true">
            <Icon name={status === "degraded" || status === "failed" ? "warning" : "eye"} size={30} />
          </span>
          <div>
            <h2>{refreshing && !snapshot ? "正在建立 Harness 证据视图" : presentation.title}</h2>
            <p>{refreshing && !snapshot ? "正在读取当前 Run 的采集配置和已落盘记录。" : presentation.detail}</p>
            <div className="harness-safety-facts">
              <span><Icon name="network" size={14} />仅监听本机回环地址</span>
              <span><Icon name="lock" size={14} />提示词与工具正文不入 Trace</span>
            </div>
          </div>
        </div>
        <dl className="harness-signal-metrics">
          <div><dt>内部记录</dt><dd>{snapshot ? formatCount(snapshot.summary.records) : "—"}</dd><small>{formatCount(snapshot?.summary.spans)} Span · {formatCount(snapshot?.summary.events)} 事件</small></div>
          <div><dt>内部操作</dt><dd>{snapshot ? formatCount(snapshot.summary.unique_operations) : "—"}</dd><small>按安全操作名聚合</small></div>
          <div><dt>系统行为</dt><dd>{snapshot ? formatCount(snapshot.summary.os_events) : "—"}</dd><small>从 {formatCount(snapshot?.summary.os_observed_events)} 条观测中保留</small></div>
          <div><dt>最近 Trace</dt><dd className="harness-time-value">{formatTime(snapshot?.summary.last_received_at)}</dd><small>{snapshot?.run_id ? `Run ${snapshot.run_id.slice(0, 8)}` : "等待 Run 信息"}</small></div>
        </dl>
      </section>

      <section className="harness-evidence-panel">
        <div className="harness-section-heading">
          <div><h2>四层证据视图</h2><p>并列展示当前 Run 可比较的四类证据；这些汇总尚未逐条绑定为同一行为链。</p></div>
          <span>{snapshot ? `${formatCount(snapshot.summary.protocol_messages)} 条协议消息` : "正在核对"}</span>
        </div>
        <ol className="harness-layer-flow">
          {(snapshot?.layers || []).map((layer) => (
            <li key={layer.id} className={`status-${layer.status}`}>
              <span className="harness-layer-mark"><Icon name={layerIcons[layer.id]} size={20} /></span>
              <div><strong>{layer.label}</strong><p>{layer.detail}</p></div>
              <div className="harness-layer-result">
                <b>{formatCount(layer.records)}</b>
                <small>{statusLabels[layer.status] || layer.status}</small>
              </div>
            </li>
          ))}
          {!snapshot && ["protocol", "harness", "os", "filesystem"].map((id) => (
            <li key={id} className="status-loading harness-layer-loading" aria-hidden="true">
              <span className="harness-layer-mark" /><div><strong>正在读取</strong><p>核对采集状态与记录数</p></div>
            </li>
          ))}
        </ol>
      </section>

      <div className="harness-analysis-grid">
        <section className="harness-operation-panel">
          <div className="harness-section-heading">
            <div><h2>Harness 在做什么</h2><p>按内部操作名汇总，不依赖提示词或工具正文。</p></div>
            <span>{formatCount(snapshot?.operations.length)} 类</span>
          </div>
          <div className="harness-operation-list">
            {(snapshot?.operations || []).slice(0, 10).map((operation) => (
              <div className="harness-operation-row" key={operation.name}>
                <div className="harness-operation-copy">
                  <strong>{operation.label}</strong>
                  <code>{operation.name}</code>
                </div>
                <div className="harness-operation-measure">
                  <span style={{ "--operation-scale": Math.max(.03, operation.count / maxOperationCount) } as React.CSSProperties} />
                </div>
                <div className="harness-operation-count"><b>{formatCount(operation.count)}</b><small>{operation.errors ? `${operation.errors} 条异常` : operation.average_duration_ms != null ? `均值 ${formatDuration(operation.average_duration_ms)}` : operation.record_kind === "event" ? "事件" : "Span"}</small></div>
              </div>
            ))}
            {snapshot && snapshot.operations.length === 0 && (
              <div className="harness-empty-state"><Icon name="session" size={30} /><strong>尚无内部 Trace</strong><p>{snapshot.telemetry.enabled ? "采集器已经就绪，等待 Harness 刷出第一批安全记录。" : "本次 Run 没有启用 Harness 内部遥测。"}</p></div>
            )}
            {!snapshot && <div className="harness-empty-state"><Icon name="refresh" size={30} /><strong>正在汇总操作</strong><p>首次读取会扫描已有记录，之后只处理新增内容。</p></div>}
          </div>
        </section>

        <section className="harness-boundary-panel">
          <div className="harness-section-heading"><div><h2>采集边界</h2><p>这里明确展示能证明什么，也明确展示不能证明什么。</p></div></div>
          <dl className="harness-config-list">
            <div><dt>采集后端</dt><dd>{snapshot?.telemetry.backend === "codex_trace_safe_otlp_http" ? "Codex Trace-safe OTLP" : snapshot?.telemetry.backend || "未配置"}</dd></div>
            <div><dt>传输范围</dt><dd>{snapshot?.telemetry.collector_scope === "loopback_only" ? "仅本机回环" : "未知"}</dd></div>
            <div><dt>内容采集</dt><dd>{snapshot?.telemetry.content_capture ? "已启用" : "关闭"}</dd></div>
            <div><dt>丢失记录</dt><dd className={snapshot?.telemetry.known_loss ? "has-gap" : ""}>{snapshot?.telemetry.known_loss ? formatCount(snapshot.telemetry.dropped_records) : "未发现"}</dd></div>
          </dl>
          <div className="harness-privacy-statement">
            <span><Icon name="shield" size={21} /></span>
            <div><strong>只保留低敏结构</strong><p>操作名、时序、耗时、结果和少量枚举属性可以进入页面；提示词、工具参数、工具输出和隐藏推理不会进入这条 Trace。</p></div>
          </div>
        </section>
      </div>

      <section className="harness-trace-panel">
        <div className="harness-section-heading">
          <div><h2>最新内部 Trace</h2><p>按接收时间倒序显示；每一行都来自当前 Run 的脱敏 OTEL 原始记录。</p></div>
          <span>{snapshot?.summary.last_received_at ? `更新于 ${formatTime(snapshot.summary.last_received_at)}` : "等待记录"}</span>
        </div>
        <div className="harness-trace-table" role="table" aria-label="最新 Harness 内部 Trace">
          <div className="harness-trace-head" role="row">
            <span role="columnheader">时间</span><span role="columnheader">类型</span><span role="columnheader">内部操作</span><span role="columnheader">安全证据</span><span role="columnheader">耗时</span><span role="columnheader">结果</span>
          </div>
          {(snapshot?.recent || []).slice(0, 24).map((record) => (
            <div className={`harness-trace-row outcome-${record.outcome}`} role="row" key={record.id}>
              <time role="cell" dateTime={record.received_at || undefined}>{formatTime(record.received_at, true)}</time>
              <span role="cell"><b>{record.record_kind === "event" ? "事件" : "Span"}</b><small>{record.category}</small></span>
              <span role="cell"><strong>{record.label}</strong><code>{record.name}</code></span>
              <span role="cell" className="harness-trace-evidence">{attributeSummary(record)}</span>
              <span role="cell" className="harness-trace-duration">{formatDuration(record.duration_ms)}</span>
              <span role="cell" className="harness-trace-outcome"><i aria-hidden="true" />{record.outcome === "error" ? "异常" : "正常"}</span>
            </div>
          ))}
          {snapshot && snapshot.recent.length === 0 && (
            <div className="harness-trace-empty"><Icon name="session" size={28} /><strong>尚未收到内部 Trace</strong><p>基础采集状态仍会如实展示；有新记录后，这里会自动更新。</p></div>
          )}
        </div>
      </section>

      <aside className="harness-proof-note">
        <Icon name="lock" size={20} />
        <div><strong>证据口径</strong><p>{snapshot?.proof_boundary.join(" ") || "正在读取当前 Run 的证据边界。"}</p></div>
      </aside>
    </main>
  );
}
