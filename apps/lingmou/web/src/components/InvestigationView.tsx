import { useEffect, useMemo, useRef, useState } from "react";
import {
  confidenceLabels,
  captureCompletenessLabel,
  formatDuration,
  formatInvestigationTime,
  evidenceStateLabel,
  fileAccessLabel,
  incidentEdges,
  investigationStatusLabel,
  isTimeGap,
  relationLabel,
  shortHash,
  stageLabels,
  stageOrder,
} from "../investigation";
import type {
  ConfidenceTier,
  HistoryResponse,
  InvestigationAnswer,
  InvestigationDetail,
  InvestigationEdge,
  InvestigationListItem,
  InvestigationListResponse,
  InvestigationNode,
  InvestigationStage,
} from "../types";
import { Icon, type IconName } from "./Icon";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `请求失败 (${response.status})`);
  return body as T;
}

const stageIcons: Record<InvestigationStage, IconName> = {
  entry: "user",
  access: "file",
  collect: "database",
  transform: "tool",
  egress: "network",
  outcome: "shield",
};

const answerRows: Array<{
  key: keyof InvestigationDetail["summary"];
  label: string;
  icon: IconName;
}> = [
  { key: "earliest_trigger", label: "最早可关联诱因", icon: "history" },
  { key: "key_asset", label: "关键资产 / 对象", icon: "lock" },
  { key: "dangerous_outlet", label: "高危操作 / 出口", icon: "network" },
  { key: "final_outcome", label: "最终结果 / 处置", icon: "shield" },
];

function ConfidenceBadge({ tier }: { tier: ConfidenceTier }) {
  return <span className={`chain-confidence confidence-${tier}`}>{confidenceLabels[tier]}</span>;
}

function AnswerCell({
  label,
  answer,
  icon,
}: {
  label: string;
  answer: InvestigationAnswer;
  icon: IconName;
}) {
  return (
    <div className="case-answer-cell">
      <span className="case-answer-icon"><Icon name={icon} size={18} /></span>
      <div>
        <div className="case-answer-label"><span>{label}</span><ConfidenceBadge tier={answer.confidence_tier} /></div>
        <strong>{answer.value}</strong>
        <p>{answer.detail}</p>
      </div>
    </div>
  );
}

function IncidentList({
  items,
  selectedId,
  onSelect,
  runCount,
}: {
  items: InvestigationListItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  runCount: number;
}) {
  return (
    <aside className="case-list" aria-label="调查事件列表">
      <div className="case-list-heading">
        <div><h2>风险锚点</h2><p>{runCount} 次运行中的可调查事件</p></div>
        <span>{items.length}</span>
      </div>
      <div className="case-list-items">
        {items.map((item) => (
          <button
            type="button"
            key={item.id}
            className={selectedId === item.id ? "active" : ""}
            aria-pressed={selectedId === item.id}
            onClick={() => onSelect(item.id)}
          >
            <span className={`case-risk-mark risk-${item.risk_level}`}><Icon name={item.blocked ? "shield" : "warning"} size={17} /></span>
            <span className="case-list-copy">
              <strong>{item.title}</strong>
              <small>{item.summary}</small>
              <span><time>{formatInvestigationTime(item.occurred_at)}</time><em>{item.blocking_rule || item.action || item.run_id.slice(0, 12)}</em></span>
            </span>
            <Icon name="arrowRight" size={16} />
          </button>
        ))}
      </div>
      <div className="case-list-legend">
        <strong>判读规则</strong>
        <span><i className="legend-fact" />事实</span>
        <span><i className="legend-strong" />强关联</span>
        <span><i className="legend-candidate" />候选</span>
      </div>
    </aside>
  );
}

function StageStrip({
  detail,
  selectedNodeId,
  onSelect,
}: {
  detail: InvestigationDetail;
  selectedNodeId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="case-stage-section" aria-labelledby="case-stage-title">
      <div className="case-section-heading">
        <div><h2 id="case-stage-title">最小充分链</h2><p>阶段缺失不会被模型补写；点击节点查看依据</p></div>
        <span className="chain-score">链路评分 <strong>{detail.chain_score}</strong>/100</span>
      </div>
      <ol className="case-stage-strip">
        {detail.stages.map((stage, index) => (
          <li key={stage.id} className={stage.status === "missing" ? "missing" : "present"}>
            <button
              type="button"
              disabled={!stage.node_id}
              className={stage.node_id === selectedNodeId ? "active" : ""}
              onClick={() => stage.node_id && onSelect(stage.node_id)}
              aria-label={`${stageLabels[stage.id]}：${stage.status === "present" ? confidenceLabels[stage.confidence_tier] : "没有足够证据"}`}
            >
              <span><Icon name={stageIcons[stage.id]} size={18} /></span>
              <strong>{stageLabels[stage.id]}</strong>
              <small>{stage.status === "present" ? confidenceLabels[stage.confidence_tier] : "证据缺失"}</small>
            </button>
            {index < detail.stages.length - 1 && <i className="stage-connector" aria-hidden="true" />}
          </li>
        ))}
      </ol>
    </section>
  );
}

function ReplayControls({
  nodes,
  index,
  playing,
  onIndex,
  onToggle,
}: {
  nodes: InvestigationNode[];
  index: number;
  playing: boolean;
  onIndex: (value: number) => void;
  onToggle: () => void;
}) {
  const current = nodes[Math.min(index, Math.max(0, nodes.length - 1))];
  return (
    <div className="replay-controls" aria-label="调查时间回放">
      <button type="button" onClick={onToggle} disabled={nodes.length < 2} aria-label={playing ? "暂停回放" : "开始回放"}>
        <Icon name={playing ? "pause" : "play"} size={17} />
      </button>
      <label>
        <span className="visually-hidden">选择回放节点</span>
        <input
          type="range"
          min={0}
          max={Math.max(0, nodes.length - 1)}
          value={Math.min(index, Math.max(0, nodes.length - 1))}
          onChange={(event) => onIndex(Number(event.target.value))}
          disabled={nodes.length < 2}
        />
      </label>
      <span><strong>{current ? stageLabels[current.stage] : "无节点"}</strong><time>{current ? formatInvestigationTime(current.occurred_at) : ""}</time></span>
      <em>{nodes.length ? `${Math.min(index + 1, nodes.length)} / ${nodes.length}` : "0 / 0"}</em>
    </div>
  );
}

function ChainTimeline({
  detail,
  selectedNodeId,
  onSelect,
}: {
  detail: InvestigationDetail;
  selectedNodeId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <ol className="chain-timeline">
      {detail.timeline.map((row) => {
        if (isTimeGap(row)) {
          return (
            <li className="timeline-gap" key={row.id}>
              <span><Icon name="history" size={15} /></span>
              <div><strong>{formatDuration(row.duration_seconds)}无相关事件</strong><small>{row.title}</small></div>
            </li>
          );
        }
        return (
          <li key={row.id} className={`timeline-node stage-${row.stage}`}>
            <span className="timeline-track" aria-hidden="true"><i><Icon name={stageIcons[row.stage]} size={16} /></i></span>
            <button
              type="button"
              className={selectedNodeId === row.id ? "active" : ""}
              onClick={() => onSelect(row.id)}
            >
              <span className="timeline-node-meta">
                <strong>{stageLabels[row.stage]}</strong>
                <time>{formatInvestigationTime(row.occurred_at)}</time>
                {row.run_id !== detail.minimal_chain.at(-1)?.run_id && <em>跨运行 · {row.run_id.slice(0, 12)}</em>}
              </span>
              <span className="timeline-node-copy">
                <strong>{row.title}</strong>
                <p>{row.summary || row.fact_scope}</p>
              </span>
              <span className="timeline-node-proof"><ConfidenceBadge tier={row.confidence_tier} /><small>{row.fact_scope}</small></span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function NodeInspector({
  node,
  edges,
  nodes,
  drawer,
  onClose,
  onSelect,
}: {
  node: InvestigationNode | null;
  edges: InvestigationEdge[];
  nodes: InvestigationNode[];
  drawer: boolean;
  onClose: () => void;
  onSelect: (id: string) => void;
}) {
  const inspectorRef = useRef<HTMLElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!drawer || !node || !inspectorRef.current) return;
    const inspector = inspectorRef.current;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusInspector = window.requestAnimationFrame(() => {
      inspector.querySelector<HTMLElement>(".case-inspector-close")?.focus();
    });
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = [...inspector.querySelectorAll<HTMLElement>(
        'button:not([disabled]), summary, a[href], input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )].filter((element) => !element.hasAttribute("hidden"));
      if (!focusable.length) {
        event.preventDefault();
        inspector.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1)!;
      if (event.shiftKey && (document.activeElement === first || document.activeElement === inspector)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => {
      window.cancelAnimationFrame(focusInspector);
      document.removeEventListener("keydown", handleKey);
      previousFocusRef.current?.focus();
    };
  }, [drawer, Boolean(node)]);

  if (!node) {
    return (
      <aside className="case-inspector empty" aria-label="链路证据详情">
        <Icon name="inspect" size={24} />
        <strong>选择一个链路节点</strong>
        <p>这里会显示文件版本、PID、策略和每条关系为什么成立。</p>
      </aside>
    );
  }
  const related = incidentEdges(node.id, edges);
  const nodeById = new Map(nodes.map((value) => [value.id, value]));
  const correlation = node.event.evidence?.correlation;
  const risk = node.event.explanation?.risk;
  return (
    <aside
      ref={inspectorRef}
      className="case-inspector"
      role={drawer ? "dialog" : undefined}
      aria-modal={drawer || undefined}
      aria-labelledby="case-inspector-title"
      tabIndex={drawer ? -1 : undefined}
    >
      <div className="case-inspector-heading">
        <div><h2 id="case-inspector-title">{node.title}</h2><p>{stageLabels[node.stage]} · {formatInvestigationTime(node.occurred_at)}</p></div>
        <button type="button" className="icon-button case-inspector-close" onClick={onClose} aria-label="关闭证据详情"><Icon name="close" /></button>
      </div>
      <div className="case-inspector-pills">
        <ConfidenceBadge tier={node.confidence_tier} />
        <span className={`case-node-status status-${node.status}`}>{investigationStatusLabel(node.status)}</span>
      </div>
      <section>
        <h3>事实边界</h3>
        <p>{node.fact_scope}</p>
      </section>
      <section>
        <h3>为什么进入这条链</h3>
        {related.length ? (
          <ul className="relation-evidence-list">
            {related.map((edge) => (
              <li key={edge.id}>
                <span><Icon name="link" size={15} /></span>
                <div>
                  <strong>{relationLabel(edge.relation)}</strong>
                  <button
                    type="button"
                    className="relation-peer"
                    onClick={() => onSelect(edge.source === node.id ? edge.target : edge.source)}
                  >
                    关联到：{nodeById.get(edge.source === node.id ? edge.target : edge.source)?.title || "未知节点"}
                  </button>
                  <p>{edge.evidence}</p>
                  <ConfidenceBadge tier={edge.confidence_tier} />
                </div>
              </li>
            ))}
          </ul>
        ) : <p className="muted-copy">该节点是调查锚点，直接来自已记录的风险或策略事件。</p>}
      </section>
      <section>
        <h3>进程、网络与策略实体</h3>
        {node.entities?.length ? (
          <dl className="case-correlation-grid entity-grid">
            {node.entities.map((entity) => (
              <div key={`${entity.entity_type}:${entity.scope_key}:${entity.entity_key}:${entity.role}`}>
                <dt>{entity.entity_type} · {entity.role}</dt>
                <dd>{entity.display_value}<small>{entity.source} · {confidenceLabels[entity.confidence_tier]}</small></dd>
              </div>
            ))}
          </dl>
        ) : <p className="muted-copy">该节点没有可用于跨事件关联的进程、网络或策略实体。</p>}
      </section>
      <section>
        <h3>文件身份与版本</h3>
        {node.file_snapshots.length ? (
          <div className="file-version-list">
            {node.file_snapshots.map((snapshot) => (
              <details key={`${snapshot.identity_id}:${snapshot.path}`}>
                <summary><Icon name="file" size={15} /><span>{snapshot.path}</span><ConfidenceBadge tier={snapshot.confidence_tier} /></summary>
                <dl>
                  <div><dt>操作</dt><dd>{snapshot.accesses.map(fileAccessLabel).join(" / ")}</dd></div>
                  <div><dt>身份</dt><dd>{snapshot.identity_basis === "device_inode" ? `${snapshot.device}/${snapshot.inode}` : "仅路径候选"}</dd></div>
                  <div><dt>版本</dt><dd>{shortHash(snapshot.version_id)}</dd></div>
                  <div><dt>SHA-256</dt><dd>{shortHash(snapshot.content_sha256)}</dd></div>
                  <div><dt>Git blob</dt><dd>{shortHash(snapshot.git_blob)}</dd></div>
                  <div><dt>访问区间</dt><dd>{formatInvestigationTime(snapshot.observed_from ?? snapshot.observed_at)} — {formatInvestigationTime(snapshot.observed_to ?? snapshot.observed_at)}</dd></div>
                  <div><dt>进程</dt><dd>{snapshot.processes?.length ? snapshot.processes.map((value) => `${value.pid ?? "?"}/${value.ppid ?? "?"}`).join(" · ") : "无可归因 PID"}</dd></div>
                  <div><dt>采集</dt><dd>{captureCompletenessLabel(snapshot.capture_completeness)}</dd></div>
                </dl>
              </details>
            ))}
          </div>
        ) : <p className="muted-copy">该节点没有可用的文件版本元数据。</p>}
      </section>
      <section>
        <h3>关联标识</h3>
        <dl className="case-correlation-grid">
          <div><dt>Run</dt><dd>{node.run_id}</dd></div>
          <div><dt>Turn</dt><dd>{node.turn_id || "无"}</dd></div>
          <div><dt>Item</dt><dd>{node.item_id || "无"}</dd></div>
          <div><dt>PID / PPID</dt><dd>{correlation?.pid ?? "无"} / {correlation?.ppid ?? "无"}</dd></div>
          <div><dt>策略</dt><dd>{risk?.blocking_rule || risk?.policy_id || "无"}</dd></div>
          <div><dt>证据</dt><dd>{evidenceStateLabel(node.evidence_availability)} / {evidenceStateLabel(node.evidence_completeness)}</dd></div>
        </dl>
      </section>
      <details className="case-raw-event">
        <summary>查看原始脱敏事件</summary>
        <pre>{JSON.stringify(node.event, null, 2)}</pre>
      </details>
    </aside>
  );
}

function FullGraph({ detail, onSelect }: { detail: InvestigationDetail; onSelect: (id: string) => void }) {
  const byStage = useMemo(
    () => Object.fromEntries(stageOrder.map((stage) => [stage, detail.graph.nodes.filter((node) => node.stage === stage)])) as Record<InvestigationStage, InvestigationNode[]>,
    [detail],
  );
  const nodeById = useMemo(
    () => new Map(detail.graph.nodes.map((node) => [node.id, node])),
    [detail],
  );
  return (
    <section className="full-chain-graph" aria-labelledby="full-graph-title">
      <div className="case-section-heading">
        <div><h2 id="full-graph-title">完整证据图</h2><p>{detail.graph.node_count} 个节点 · {detail.graph.edge_count} 条有据关系 · {detail.graph.entity_count ?? 0} 个结构化实体；时间邻近不自动画成因果边</p></div>
      </div>
      <div className="graph-stage-lanes">
        {stageOrder.map((stage) => (
          <section key={stage}>
            <h3><Icon name={stageIcons[stage]} size={15} />{stageLabels[stage]}<span>{byStage[stage].length}</span></h3>
            <div>
              {byStage[stage].map((node) => (
                <button type="button" key={node.id} onClick={() => onSelect(node.id)}>
                  <strong>{node.title}</strong><small>{formatInvestigationTime(node.occurred_at)}</small><ConfidenceBadge tier={node.confidence_tier} />
                </button>
              ))}
              {!byStage[stage].length && <p>没有可证明节点</p>}
            </div>
          </section>
        ))}
      </div>
      <div className="graph-relation-table" role="table" aria-label="完整图关系">
        <div role="row" className="graph-table-head"><span role="columnheader">关系</span><span role="columnheader">连接节点</span><span role="columnheader">依据</span><span role="columnheader">等级</span></div>
        {detail.graph.edges.map((edge) => {
          const source = nodeById.get(edge.source);
          const target = nodeById.get(edge.target);
          return (
            <div role="row" key={edge.id}>
              <span role="cell" className="graph-relation-kind">
                <strong>{relationLabel(edge.relation)}</strong>
                <small className={edge.causal ? "causal" : "associative"}>{edge.causal ? "因果" : "关联"}</small>
              </span>
              <span role="cell" className="graph-edge-endpoints">
                <button type="button" onClick={() => onSelect(edge.source)}>{source?.title || edge.source}</button>
                <Icon name={edge.causal ? "arrowRight" : "link"} size={13} />
                <button type="button" onClick={() => onSelect(edge.target)}>{target?.title || edge.target}</button>
              </span>
              <span role="cell">{edge.evidence}</span>
              <span role="cell"><ConfidenceBadge tier={edge.confidence_tier} /></span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function InvestigationView({ onOpenWorkbench }: { onOpenWorkbench: () => void }) {
  const [list, setList] = useState<InvestigationListResponse | null>(null);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [indexError, setIndexError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detailRevision, setDetailRevision] = useState(0);
  const [rebuilding, setRebuilding] = useState(false);
  const [fullGraph, setFullGraph] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [replayIndex, setReplayIndex] = useState(0);
  const [inspectorDrawer, setInspectorDrawer] = useState(() => window.innerWidth <= 1300);
  const error = detailError || indexError;

  const loadIndex = async (reportError = true) => {
    if (reportError) setIndexError(null);
    try {
      const [nextList, nextHistory] = await Promise.all([
        request<InvestigationListResponse>("/api/v1/investigations?limit=100"),
        request<HistoryResponse>("/api/v1/history?limit=100"),
      ]);
      setList(nextList);
      setHistory(nextHistory);
      setSelectedId((current) => current && nextList.items.some((item) => item.id === current) ? current : nextList.items[0]?.id || null);
    } catch (reason) {
      if (reportError) setIndexError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadIndex();
    const timer = window.setInterval(() => void loadIndex(false), 10_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const update = () => setInspectorDrawer(window.innerWidth <= 1300);
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      setDetailError(null);
      setSelectedNodeId(null);
      return;
    }
    let stopped = false;
    setDetail(null);
    setSelectedNodeId(null);
    setDetailError(null);
    setDetailLoading(true);
    const load = async (initial: boolean) => {
      try {
        const value = await request<InvestigationDetail>(`/api/v1/investigations/${encodeURIComponent(selectedId)}`);
        if (stopped) return;
        setDetail(value);
        setDetailError(null);
        if (initial) {
          const first = value.minimal_chain[0];
          setSelectedNodeId(window.innerWidth > 1300 ? first?.id || value.anchor_event_key : null);
          setReplayIndex(0);
          setPlaying(false);
          setFullGraph(false);
        } else {
          setSelectedNodeId((current) => current && value.graph.nodes.some((node) => node.id === current) ? current : value.minimal_chain[0]?.id || null);
          setReplayIndex((current) => Math.min(current, Math.max(0, value.minimal_chain.length - 1)));
        }
      } catch (reason) {
        if (!stopped && initial) {
          setDetail(null);
          setDetailError(reason instanceof Error ? reason.message : String(reason));
        }
      } finally {
        if (!stopped && initial) setDetailLoading(false);
      }
    };
    void load(true);
    const timer = window.setInterval(() => void load(false), 5_000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [selectedId, detailRevision]);

  useEffect(() => {
    if (!playing || !detail?.minimal_chain.length) return;
    const timer = window.setInterval(() => {
      setReplayIndex((current) => {
        const next = current + 1;
        if (next >= detail.minimal_chain.length) {
          setPlaying(false);
          return current;
        }
        setSelectedNodeId(detail.minimal_chain[next].id);
        return next;
      });
    }, 1_200);
    return () => window.clearInterval(timer);
  }, [playing, detail]);

  const selectedNode = detail?.graph.nodes.find((node) => node.id === selectedNodeId) || null;
  const selectInvestigation = (investigationId: string) => {
    if (investigationId !== selectedId) {
      setDetail(null);
      setSelectedNodeId(null);
      setDetailError(null);
      setDetailLoading(true);
    }
    setSelectedId(investigationId);
  };
  const selectNode = (nodeId: string) => {
    setSelectedNodeId(nodeId);
    const index = detail?.minimal_chain.findIndex((node) => node.id === nodeId) ?? -1;
    if (index >= 0) setReplayIndex(index);
    setPlaying(false);
  };
  const rebuild = async () => {
    setRebuilding(true);
    setIndexError(null);
    setDetailError(null);
    try {
      await request("/api/v1/history/rebuild", { method: "POST" });
      await loadIndex();
      setDetailRevision((value) => value + 1);
    } catch (reason) {
      setIndexError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setRebuilding(false);
    }
  };

  return (
    <main className="investigation-center">
      <header className="investigation-header">
        <div><h1>调查回放</h1><p>持续从真实运行中抽取风险锚点，关联文件、进程、网络和策略证据，再按时间回放。</p></div>
        <div className="investigation-header-actions">
          <span><Icon name="database" size={16} />{history?.runs.length ?? 0} 次运行已索引</span>
          <button type="button" onClick={() => void rebuild()} disabled={rebuilding}>
            <Icon name="refresh" size={16} />{rebuilding ? "正在重建…" : "从原始日志重建"}
          </button>
        </div>
      </header>

      {error && (
        <div className="investigation-error" role="alert">
          <span><Icon name="warning" size={19} /></span>
          <div><strong>调查历史暂不可用</strong><p>{error}</p></div>
          <button type="button" onClick={() => { setDetailRevision((value) => value + 1); void loadIndex(); }}>重试</button>
        </div>
      )}

      {loading && (
        <div className="investigation-loading" role="status" aria-live="polite">
          <span className="loading-pulse" /><div><strong>正在整理项目级证据</strong><p>读取运行索引、文件版本和风险锚点…</p></div>
        </div>
      )}

      {!loading && list && !list.items.length && (
        <section className="investigation-empty">
          <span><Icon name="graph" size={30} /></span>
          <h2>还没有可调查的风险锚点</h2>
          <p>在 Agent 工作台运行真实任务。灵眸记录到凭证访问、侦察、持久化、外联、破坏或执行前阻断后，会自动生成案卷；缺失阶段会如实标记。</p>
          <div><button type="button" className="primary-button" onClick={onOpenWorkbench}>开始真实任务</button><button type="button" className="secondary-button" onClick={() => void rebuild()}>扫描已有运行</button></div>
        </section>
      )}

      {!loading && list && list.items.length > 0 && (
        <div className={`investigation-workspace ${selectedNode ? "inspector-open" : ""}`}>
          <IncidentList items={list.items} selectedId={selectedId} onSelect={selectInvestigation} runCount={history?.runs.length || 0} />
          <section className="case-canvas" aria-label="调查链主体">
            {detailLoading && <div className="case-detail-loading" role="status"><span className="loading-pulse" />正在抽取最小充分链…</div>}
            {detail && !detailLoading && (
              <>
                <section className="case-brief" aria-labelledby="case-brief-title">
                  <div className="case-brief-heading">
                    <div><h2 id="case-brief-title">这次事件发生了什么</h2><p>结论只来自已索引事实与带等级的关系，不展示敏感正文</p></div>
                    <span className={`case-outcome outcome-${detail.summary.final_outcome.status || "recorded"}`}><Icon name="shield" size={16} />{investigationStatusLabel(detail.summary.final_outcome.status)}</span>
                  </div>
                  <div className="case-answer-grid">
                    {answerRows.map((row) => <AnswerCell key={row.key} label={row.label} answer={detail.summary[row.key]} icon={row.icon} />)}
                  </div>
                </section>
                <StageStrip detail={detail} selectedNodeId={selectedNodeId} onSelect={selectNode} />
                <section className="case-replay-section" aria-labelledby="case-replay-title">
                  <div className="case-section-heading replay-heading">
                    <div><h2 id="case-replay-title">按时间回放</h2><p>长时间无相关事件的区间会压缩，但不会被删除</p></div>
                    <button type="button" className={fullGraph ? "active" : ""} onClick={() => setFullGraph((value) => !value)}><Icon name="graph" size={16} />{fullGraph ? "返回最小链" : "查看完整图"}</button>
                  </div>
                  <ReplayControls
                    nodes={detail.minimal_chain}
                    index={replayIndex}
                    playing={playing}
                    onIndex={(value) => { setReplayIndex(value); setSelectedNodeId(detail.minimal_chain[value]?.id || null); setPlaying(false); }}
                    onToggle={() => {
                      if (replayIndex >= detail.minimal_chain.length - 1) {
                        setReplayIndex(0);
                        setSelectedNodeId(detail.minimal_chain[0]?.id || null);
                      }
                      setPlaying((value) => !value);
                    }}
                  />
                  {!fullGraph && <ChainTimeline detail={detail} selectedNodeId={selectedNodeId} onSelect={selectNode} />}
                  {fullGraph && <FullGraph detail={detail} onSelect={selectNode} />}
                </section>
                {detail.evidence_gaps.length > 0 && (
                  <section className="evidence-gap-panel" aria-labelledby="evidence-gap-title">
                    <span><Icon name="attention" size={20} /></span>
                    <div><h2 id="evidence-gap-title">有 {detail.evidence_gaps.length} 处无法证明</h2>{detail.evidence_gaps.map((gap) => <p key={gap.node_id}><strong>{gap.title}：</strong>{gap.impact}</p>)}</div>
                  </section>
                )}
                <footer className="case-proof-boundary">
                  <Icon name="lock" size={17} />
                  <div><strong>本地取证边界</strong><p>{detail.proof_boundary.join(" ")}</p></div>
                </footer>
              </>
            )}
          </section>
          {detail && inspectorDrawer && selectedNode && (
            <button type="button" className="case-inspector-scrim" onClick={() => setSelectedNodeId(null)} aria-label="关闭证据详情" />
          )}
          {detail && (
            <NodeInspector
              node={selectedNode}
              nodes={detail.graph.nodes}
              edges={detail.graph.edges}
              drawer={inspectorDrawer}
              onClose={() => setSelectedNodeId(null)}
              onSelect={selectNode}
            />
          )}
        </div>
      )}
    </main>
  );
}
