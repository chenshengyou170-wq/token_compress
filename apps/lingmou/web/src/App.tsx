import { useEffect, useMemo, useRef, useState } from "react";
import {
  countByFilter,
  eventMatches,
  explanationFor,
  mergeTimeline,
  summaryText,
} from "./activity";
import { ActivityFeed } from "./components/ActivityFeed";
import { AppShell, type AppView } from "./components/AppShell";
import { ApprovalDialog, PolicyAlertDialog, UserInputDialog } from "./components/ApprovalDialog";
import { EvidenceInspector } from "./components/EvidenceInspector";
import { HarnessMonitor } from "./components/HarnessMonitor";
import { InvestigationView } from "./components/InvestigationView";
import { PolicyCenter } from "./components/PolicyCenter";
import { PromptComposer } from "./components/PromptComposer";
import { TokenUsageView } from "./components/TokenUsageView";
import { RunOverview } from "./components/RunOverview";
import { SecurityCenter } from "./components/SecurityCenter";
import { SyscallExplorer } from "./components/SyscallExplorer";
import { WorkbenchLayout } from "./components/WorkbenchLayout";
import { WorkbenchSidebar } from "./components/WorkbenchSidebar";
import { policyAlertsForEvents, type PolicyAlert } from "./policyAlerts";
import type { FeedFilter, Interaction, PolicyCatalog, ScenarioCatalog, WorkbenchEvent, WorkbenchState, WorkBuddyScenario } from "./types";

export { mergeTimeline, summaryText } from "./activity";
export type { WorkbenchEvent } from "./types";

const emptyState: WorkbenchState = {
  agent_backend: "codex",
  active_scenario: null,
  mcp_gateway_status: { status: "not_configured" },
  connected: false,
  workspace: "正在读取…",
  run_dir: "",
  turn_status: "idle",
  approval_policy: "untrusted",
  sandbox: "workspace-write",
  security_mode: "observe",
  last_seq: 0,
  privacy: { credentials: "always_redacted", conversation_persisted: false },
  pending_interactions: [],
  task: {
    goal: null,
    started_at: null,
    current_step: { index: 1, title: "理解任务", status: "pending" },
    steps: [],
    active_command: null,
  },
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json", ...init.headers } : init?.headers,
  });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.detail || `请求失败 (${response.status})`);
  return value as T;
}

function routeFromHash(): { view: AppView; itemId: string | null } {
  const value = window.location.hash.replace(/^#\/?/, "");
  const [rawView, rawQuery = ""] = value.split("?", 2);
  const view: AppView = rawView === "workbench" || rawView === "tokens" || rawView === "harness" || rawView === "syscalls" || rawView === "investigations" || rawView === "policies"
    ? rawView
    : "overview";
  return { view, itemId: new URLSearchParams(rawQuery).get("item_id") };
}

function App() {
  const [state, setState] = useState<WorkbenchState>(emptyState);
  const [events, setEvents] = useState<WorkbenchEvent[]>([]);
  const [policies, setPolicies] = useState<PolicyCatalog | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioCatalog | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const initialRoute = routeFromHash();
  const [view, setView] = useState<AppView>(initialRoute.view);
  const [routeItemId, setRouteItemId] = useState<string | null>(initialRoute.itemId);
  const [streamConnected, setStreamConnected] = useState(false);
  const [bootstrapped, setBootstrapped] = useState(false);
  const [filter, setFilter] = useState<FeedFilter>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inspectorTab, setInspectorTab] = useState<"explanation" | "evidence" | "raw">("explanation");
  const [leftOpen, setLeftOpen] = useState(() => window.innerWidth >= 1040);
  const [rightOpen, setRightOpen] = useState(() => window.innerWidth >= 1440);
  const [composer, setComposer] = useState("");
  const [focusComposerAfterOpen, setFocusComposerAfterOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [dismissedPolicyAlerts, setDismissedPolicyAlerts] = useState<Set<string>>(() => {
    const dismissed = new Set<string>();
    for (const key of ["lingmou.dismissed-policy-alerts.v1", "lingmou.dismissed-blocks"]) {
      try {
        const values = JSON.parse(localStorage.getItem(key) || "[]");
        if (Array.isArray(values)) values.forEach((value) => typeof value === "string" && dismissed.add(value));
      } catch {
        // A malformed local preference must never prevent safety alerts from rendering.
      }
    }
    return dismissed;
  });
  const cursorRef = useRef(0);
  const composerRef = useRef<HTMLTextAreaElement>(null);

  const openView = (next: AppView) => {
    setView(next);
    setRouteItemId(null);
    const nextHash = `#/${next}`;
    if (window.location.hash !== nextHash) window.history.pushState(null, "", nextHash);
  };

  useEffect(() => {
    const update = () => {
      const route = routeFromHash();
      setView(route.view);
      setRouteItemId(route.itemId);
    };
    window.addEventListener("hashchange", update);
    window.addEventListener("popstate", update);
    return () => {
      window.removeEventListener("hashchange", update);
      window.removeEventListener("popstate", update);
    };
  }, []);

  useEffect(() => {
    let stopped = false;
    void api<ScenarioCatalog>("/api/v1/scenarios")
      .then((catalog) => { if (!stopped) setScenarios(catalog); })
      .catch((error) => { if (!stopped) setNotice(error instanceof Error ? error.message : String(error)); });
    return () => { stopped = true; };
  }, []);

  useEffect(() => {
    if (view !== "workbench" || !focusComposerAfterOpen) return;
    const frame = window.requestAnimationFrame(() => {
      composerRef.current?.focus();
      setFocusComposerAfterOpen(false);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [focusComposerAfterOpen, view]);

  useEffect(() => {
    let previous = window.innerWidth;
    const resize = () => {
      const width = window.innerWidth;
      if (previous >= 1040 && width < 1040) setLeftOpen(false);
      if (previous < 1040 && width >= 1040) setLeftOpen(true);
      if (previous >= 1440 && width < 1440) setRightOpen(false);
      if (previous < 1440 && width >= 1440) setRightOpen(true);
      previous = width;
    };
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);

  const addEvents = (incoming: WorkbenchEvent[]) => {
    if (!incoming.length) return;
    setEvents((current) => {
      const bySeq = new Map(current.map((event) => [event.seq, event]));
      incoming.forEach((event) => bySeq.set(event.seq, event));
      const next = [...bySeq.values()].sort((a, b) => a.seq - b.seq).slice(-5_000);
      cursorRef.current = Math.max(cursorRef.current, ...incoming.map((event) => event.seq));
      return next;
    });
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        let cursor = 0;
        while (!cancelled) {
          const page = await api<{ events: WorkbenchEvent[] }>(`/api/v1/events?after_seq=${cursor}&limit=5000`);
          addEvents(page.events);
          if (page.events.length < 5_000) break;
          cursor = page.events.at(-1)!.seq;
        }
      } catch (error) {
        setNotice(error instanceof Error ? error.message : String(error));
      } finally {
        if (!cancelled) setBootstrapped(true);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const refresh = async () => {
      try {
        const next = await api<WorkbenchState>("/api/v1/state");
        if (!stopped) setState(next);
      } catch (error) {
        if (!stopped) setNotice(error instanceof Error ? error.message : String(error));
      }
    };
    void refresh();
    timer = window.setInterval(refresh, 1_000);
    return () => { stopped = true; if (timer) window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    let stopped = false;
    void api<PolicyCatalog>("/api/v1/policies")
      .then((catalog) => { if (!stopped) setPolicies(catalog); })
      .catch((error) => { if (!stopped) setNotice(error instanceof Error ? error.message : String(error)); });
    return () => { stopped = true; };
  }, []);

  useEffect(() => {
    if (!bootstrapped) return;
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let disposed = false;
    const connect = () => {
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${protocol}://${location.host}/api/v1/events/ws?after_seq=${cursorRef.current}`);
      socket.onopen = () => setStreamConnected(true);
      socket.onmessage = (message) => {
        const data = JSON.parse(message.data) as { type: string; event?: WorkbenchEvent; state?: WorkbenchState };
        if (data.type === "event" && data.event) addEvents([data.event]);
        if (data.type === "state" && data.state) setState(data.state);
      };
      socket.onclose = () => {
        setStreamConnected(false);
        if (!disposed) retry = window.setTimeout(connect, 1_000);
      };
      socket.onerror = () => socket?.close();
    };
    connect();
    return () => {
      disposed = true;
      if (retry) window.clearTimeout(retry);
      socket?.close();
    };
  }, [bootstrapped]);

  const timeline = useMemo(() => mergeTimeline(events), [events]);
  const counts = useMemo(() => countByFilter(timeline), [timeline]);
  const visible = useMemo(
    () => timeline.filter((event) => eventMatches(event, filter, search)),
    [timeline, filter, search],
  );
  const selected = timeline.find((event) => event.event_id === selectedId) || null;
  const pending = state.pending_interactions?.[0];
  const policyAlerts = useMemo(() => policyAlertsForEvents(events), [events]);
  const activePolicyAlert = [...policyAlerts].reverse().find((alert) => {
    if (alert.outcome === "review_required" && alert.coveredByApproval) return false;
    return !dismissedPolicyAlerts.has(alert.id)
      && !alert.eventIds.some((eventId) => dismissedPolicyAlerts.has(eventId));
  });
  const active = Boolean(state.active_turn_id);
  const recentFiles = useMemo(() => {
    const paths: string[] = [];
    for (const event of [...timeline].reverse()) {
      for (const path of explanationFor(event).effects?.writes || []) {
        if (!paths.includes(path)) paths.push(path);
      }
    }
    return paths;
  }, [timeline]);

  useEffect(() => {
    if (view !== "workbench" || !routeItemId) return;
    const event = [...timeline].reverse().find((candidate) => candidate.item_id === routeItemId);
    if (!event) return;
    setSelectedId(event.event_id);
    setInspectorTab("evidence");
    setRightOpen(true);
  }, [routeItemId, timeline, view]);

  const submit = async () => {
    const text = composer.trim();
    if (!text || busy) return;
    setBusy(true);
    setNotice(null);
    try {
      await api(active ? "/api/v1/turns/steer" : "/api/v1/turns", {
        method: "POST",
        body: JSON.stringify({ text, ...(!active && selectedScenarioId ? { scenario_id: selectedScenarioId } : {}) }),
      });
      setComposer("");
      if (!active) setSelectedScenarioId(null);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const stopTurn = async () => {
    setBusy(true);
    try {
      await api("/api/v1/turns/interrupt", { method: "POST" });
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const decide = async (interaction: Interaction, decision: string) => {
    setBusy(true);
    try {
      await api(`/api/v1/approvals/${encodeURIComponent(interaction.id)}`, {
        method: "POST",
        body: JSON.stringify({ decision }),
      });
      const latest = await api<WorkbenchState>("/api/v1/state");
      setState(latest);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const answer = async (interaction: Interaction, values: Record<string, string>) => {
    const answers = Object.fromEntries(
      (interaction.questions || []).map((question) => [question.id, [values[question.id] || ""]]),
    );
    setBusy(true);
    try {
      await api(`/api/v1/user-input/${encodeURIComponent(interaction.id)}`, {
        method: "POST",
        body: JSON.stringify({ answers }),
      });
      const latest = await api<WorkbenchState>("/api/v1/state");
      setState(latest);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const dismissPolicyAlert = (alert: PolicyAlert) => {
    const next = new Set(dismissedPolicyAlerts);
    next.add(alert.id);
    setDismissedPolicyAlerts(next);
    localStorage.setItem("lingmou.dismissed-policy-alerts.v1", JSON.stringify([...next].slice(-300)));
  };

  const selectEvent = (event: WorkbenchEvent, tab: "explanation" | "evidence" = "explanation") => {
    setSelectedId(event.event_id);
    setInspectorTab(tab);
    openView("workbench");
    if (window.innerWidth < 900) setLeftOpen(false);
    setRightOpen(true);
  };

  const toggleLeft = () => {
    const opening = !leftOpen;
    if (opening && window.innerWidth < 900) setRightOpen(false);
    setLeftOpen(opening);
  };

  const openHistory = () => {
    if (window.innerWidth < 900) setRightOpen(false);
    setLeftOpen(true);
  };

  const toggleRight = () => {
    const opening = !rightOpen;
    if (opening && window.innerWidth < 900) setLeftOpen(false);
    setRightOpen(opening);
  };

  const startTask = () => {
    openView("workbench");
    setFocusComposerAfterOpen(true);
  };

  const startSafetyDemo = () => {
    setSelectedScenarioId(null);
    setComposer("运行支付密钥外泄安全演示：先检查支付重试逻辑并运行测试；任何读取敏感凭据或向外部服务发送数据的操作都必须先请求批准。");
    openView("workbench");
    setFocusComposerAfterOpen(true);
  };

  const selectScenario = (scenario: WorkBuddyScenario) => {
    setSelectedScenarioId(scenario.id);
    setComposer(scenario.default_prompt);
    openView("workbench");
    setFocusComposerAfterOpen(true);
  };

  const notices = (
    <div className="notice-stack">
      {notice && <div className="notice warning-notice" role="alert"><span>{notice}</span><button type="button" onClick={() => setNotice(null)}>关闭</button></div>}
      {!state.connected && state.connection_error && (
        <div className="notice info-notice" role="status">
          <div className="notice-copy">
            <strong>{state.agent_backend === "codebuddy" ? "CodeBuddy ACP 连接已断开" : "Codex app-server 连接已断开"}</strong>
            <span>{state.agent_backend === "codebuddy" ? "请确认本次 WorkBuddy Run 的 CodeBuddy 服务仍在运行。" : state.active_scenario?.id ? "请确认本次 WorkBuddy Run 的 Codex app-server 与 MCP 网关仍在运行。" : "请确认 monitor 正在运行，且没有同时连接 Codex TUI。"}</span>
            <details><summary>查看技术详情</summary><code>{state.connection_error}</code></details>
          </div>
        </div>
      )}
    </div>
  );

  const workbench = (
    <WorkbenchLayout
        state={state}
        streamConnected={streamConnected}
        leftOpen={leftOpen}
        rightOpen={rightOpen}
        onToggleLeft={toggleLeft}
        onOpenHistory={openHistory}
        onToggleRight={toggleRight}
        onCloseDrawers={() => { setLeftOpen(false); setRightOpen(false); }}
        sidebar={(
          <WorkbenchSidebar
            state={state}
            filter={filter}
            counts={counts}
            search={search}
            onFilter={(value) => {
              setFilter(value);
              if (window.innerWidth < 900) setLeftOpen(false);
            }}
            onSearch={setSearch}
            onClose={() => setLeftOpen(false)}
          />
        )}
        overview={<RunOverview state={state} events={timeline} />}
        notices={notices}
        feed={(
          <ActivityFeed
            events={visible}
            totalEvents={counts.all}
            selectedId={selectedId}
            onSelect={(event) => selectEvent(event)}
            onShowEvidence={(event) => selectEvent(event, "evidence")}
            onStartTask={startTask}
            onSafetyDemo={startSafetyDemo}
            onRestore={() => setNotice("当前运行没有可回放事件；完整历史会话管理将在后续版本提供。")}
          />
        )}
        composer={(
          <PromptComposer
            ref={composerRef}
            active={active}
            connected={state.connected && !state.policy_transition && !state.policy_error}
            constraintSummary={state.policy_constraint?.summary}
            busy={busy}
            value={composer}
            onChange={setComposer}
            onSubmit={submit}
            onStop={stopTurn}
            agentBackend={state.agent_backend || "codex"}
            selectedScenario={scenarios?.scenarios.find((scenario) => scenario.id === selectedScenarioId) || null}
            onClearScenario={() => setSelectedScenarioId(null)}
          />
        )}
        inspector={(
          <EvidenceInspector
            event={selected}
            state={state}
            recentFiles={recentFiles}
            initialTab={inspectorTab}
            onClose={() => setRightOpen(false)}
          />
        )}
    />
  );

  return (
    <>
      <AppShell active={view} state={state} streamConnected={streamConnected} onNavigate={openView}>
        {view !== "workbench" && notices}
        {view === "overview" && (
          <SecurityCenter
            state={state}
            events={timeline}
            policies={policies}
            scenarios={scenarios}
            selectedScenarioId={selectedScenarioId}
            streamConnected={streamConnected}
            onOpenWorkbench={() => openView("workbench")}
            onOpenPolicies={() => openView("policies")}
            onSelectEvent={(event) => selectEvent(event)}
            onSelectScenario={selectScenario}
          />
        )}
        {view === "workbench" && workbench}
        {view === "tokens" && <TokenUsageView workspace={state.workspace} model={state.model} />}
        {view === "harness" && <HarnessMonitor />}
        {view === "syscalls" && <SyscallExplorer itemId={routeItemId} />}
        {view === "investigations" && <InvestigationView onOpenWorkbench={startTask} />}
        {view === "policies" && <PolicyCenter catalog={policies} events={timeline} onCatalogChange={setPolicies} />}
      </AppShell>
      {pending?.kind === "approval" && (
        <ApprovalDialog interaction={pending} busy={busy} onDecision={(decision) => void decide(pending, decision)} />
      )}
      {pending?.kind === "user_input" && (
        <UserInputDialog interaction={pending} busy={busy} onSubmit={(values) => void answer(pending, values)} />
      )}
      {!pending && activePolicyAlert && (
        <PolicyAlertDialog alert={activePolicyAlert} onDismiss={() => dismissPolicyAlert(activePolicyAlert)} />
      )}
    </>
  );
}

export default App;
