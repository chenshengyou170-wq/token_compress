import type {
  ActivityEvidence,
  ActivityExplanation,
  ActivityGroup,
  ActivityStep,
  FeedFilter,
  WorkbenchEvent,
} from "./types";
import { policyEventNeedsAlert, policyOutcomeForEvent } from "./policyAlerts";

export function summaryText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value == null) return "";
  if (typeof value === "object" && "omitted" in (value as Record<string, unknown>)) {
    const data = value as { characters?: number };
    return `内容未落盘${data.characters ? ` · ${data.characters} 字符` : ""}`;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function payloadObject(event: WorkbenchEvent): Record<string, unknown> {
  return event.payload && typeof event.payload === "object"
    ? (event.payload as Record<string, unknown>)
    : {};
}

export function mergeTimeline(events: WorkbenchEvent[]): WorkbenchEvent[] {
  const result: WorkbenchEvent[] = [];
  const locations = new Map<string, number>();
  const keyFor = (event: WorkbenchEvent): string | null => {
    if (!event.item_id) return null;
    if (["agent_delta", "agent_message"].includes(event.kind)) return `agent:${event.item_id}`;
    if (["plan", "plan_delta"].includes(event.kind)) return `plan:${event.item_id}`;
    if (["command", "command_output", "command_evidence"].includes(event.kind)) return `command:${event.item_id}`;
    if (["file_change", "diff"].includes(event.kind)) return `${event.kind}:${event.item_id}`;
    if (["tool", "agent_tool", "web_search"].includes(event.kind)) return `tool:${event.item_id}`;
    return null;
  };

  for (const event of events) {
    const key = keyFor(event);
    if (!key) {
      result.push({ ...event });
      continue;
    }
    const existingIndex = locations.get(key);
    if (existingIndex == null) {
      const initial = { ...event, payload: { ...payloadObject(event) } };
      if (event.kind === "agent_delta") initial.kind = "agent_message";
      if (event.kind === "plan_delta") initial.kind = "plan";
      if (event.kind === "command_output") {
        initial.kind = "command";
        initial.title = "命令正在输出";
        initial.summary = "";
        initial.payload = { output: summaryText(event.summary) };
      }
      locations.set(key, result.length);
      result.push(initial);
      continue;
    }

    const previous = result[existingIndex];
    if (event.kind === "agent_delta" || event.kind === "plan_delta") {
      previous.summary = `${summaryText(previous.summary)}${summaryText(event.summary)}`;
      previous.seq = event.seq;
      previous.occurred_at = event.occurred_at;
      previous.status = "streaming";
      continue;
    }
    if (event.kind === "command_output") {
      const oldPayload = payloadObject(previous);
      previous.payload = {
        ...oldPayload,
        output: `${summaryText(oldPayload.output)}${summaryText(event.summary)}`,
      };
      previous.seq = event.seq;
      previous.status = "streaming";
      continue;
    }
    if (event.kind === "command_evidence") {
      previous.evidence = event.evidence;
      previous.payload = { ...payloadObject(previous), evidence_update: true };
      continue;
    }
    const preservedOutput = payloadObject(previous).output;
    result[existingIndex] = {
      ...event,
      payload: preservedOutput
        ? { ...payloadObject(event), output: preservedOutput }
        : { ...payloadObject(event) },
    };
  }
  return result.sort((a, b) => a.seq - b.seq);
}

const HIGH_LEVEL_KINDS = new Set([
  "policy_evaluation",
  "user_prompt",
  "agent_message",
  "plan",
  "reasoning_summary",
  "command",
  "file_change",
  "diff",
  "tool",
  "agent_tool",
  "web_search",
  "approval_request",
  "approval_required",
  "approval",
  "policy_block",
  "user_input_request",
  "user_input_response",
  "turn",
  "error",
  "warning",
]);

export function isHighLevelEvent(event: WorkbenchEvent): boolean {
  return HIGH_LEVEL_KINDS.has(event.kind) || policyEventNeedsAlert(event);
}

function searchableText(event: WorkbenchEvent): string {
  return [
    event.title,
    summaryText(event.summary),
    summaryText(event.payload),
    summaryText(event.explanation),
    summaryText(event.evidence),
    event.kind,
    event.source,
  ].join("\n").toLocaleLowerCase("zh-CN");
}

export function eventMatches(
  event: WorkbenchEvent,
  filter: FeedFilter,
  search = "",
): boolean {
  if (!isHighLevelEvent(event)) return false;
  let matches = true;
  if (filter === "needs_action") {
    matches = ["approval_request", "approval_required", "user_input_request"].includes(event.kind) && event.status === "pending";
  } else if (filter === "changes") {
    matches = ["file_change", "diff"].includes(event.kind);
  } else if (filter === "tools") {
    matches = ["command", "tool", "agent_tool", "web_search"].includes(event.kind);
  } else if (filter === "risk") {
    matches = ["approval_request", "approval_required", "approval", "policy_block", "error", "warning"].includes(event.kind)
      || policyEventNeedsAlert(event)
      || riskRank(event.explanation?.risk?.level) >= 2;
  }
  if (!matches) return false;
  const query = search.trim().toLocaleLowerCase("zh-CN");
  return !query || searchableText(event).includes(query);
}

function fallbackStep(event: WorkbenchEvent): ActivityStep {
  const isUnderstanding = ["user_prompt", "agent_message", "plan", "reasoning_summary", "turn"].includes(event.kind);
  return {
    id: `${event.turn_id || "session"}:${isUnderstanding ? "understand" : "execute"}`,
    index: isUnderstanding ? 1 : 2,
    title: isUnderstanding ? "理解任务" : "执行任务",
    status: event.status === "running" || event.status === "streaming" ? "in_progress" : "completed",
    source: "workbench_fallback",
  };
}

export function groupTimeline(events: WorkbenchEvent[]): ActivityGroup[] {
  const groups: ActivityGroup[] = [];
  const locations = new Map<string, number>();
  for (const event of events) {
    const step = event.step?.id ? event.step : fallbackStep(event);
    const id = String(step.id);
    const existing = locations.get(id);
    if (existing == null) {
      locations.set(id, groups.length);
      groups.push({ id, step: { ...step }, events: [event] });
    } else {
      groups[existing].events.push(event);
      groups[existing].step = { ...groups[existing].step, ...step };
    }
  }
  return groups;
}

export function fallbackExplanation(event: WorkbenchEvent): ActivityExplanation {
  const raw = summaryText(event.summary);
  const policyOutcome = policyOutcomeForEvent(event);
  if (event.kind === "command") {
    return {
      headline: event.title || "执行命令",
      action: "unknown",
      description: "系统暂时无法判断该命令的完整副作用，请查看原始命令和审批范围。",
      purpose: {
        text: "完成当前任务中的执行步骤",
        source: "contextual_inference",
        confidence: "contextual",
      },
      effects: { reads: [], writes: [], network: [], processes: [] },
      risk: { level: "warning", reasons: ["旧事件没有持久化解释"], basis: "conservative_fallback" },
      result: { status: event.status, summary: "请查看命令输出与原始数据" },
      sources: ["conservative_fallback"],
      conservative_fallback: true,
    };
  }
  if (["tool", "agent_tool", "web_search"].includes(event.kind)) {
    return {
      headline: event.title || "调用工具",
      action: "tool_call",
      description: "副作用尚未登记，请在批准前检查工具参数。",
      purpose: { text: "完成当前任务所需的工具步骤", source: "contextual_inference", confidence: "contextual" },
      effects: { reads: [], writes: [], network: [], processes: [], external_write: null },
      risk: { level: "warning", reasons: ["工具能力尚未登记"], basis: "conservative_fallback" },
      result: { status: event.status, summary: raw || "暂无结果摘要" },
      sources: ["conservative_fallback"],
      conservative_fallback: true,
    };
  }
  if (["file_change", "diff"].includes(event.kind)) {
    return {
      headline: event.title || "修改文件",
      action: "file_change",
      description: "该事件会修改工作区文件；旧记录没有完整的影响范围解释。",
      purpose: { text: "落实当前任务所需的文件修改", source: "contextual_inference", confidence: "contextual" },
      effects: { reads: [], writes: raw ? [raw] : [], network: [], processes: [] },
      risk: { level: "warning", reasons: ["操作会修改文件"], basis: "conservative_fallback" },
      result: { status: event.status, summary: "请查看 diff 或原始事件" },
      sources: ["conservative_fallback"],
      conservative_fallback: true,
    };
  }
  return {
    headline: event.title,
    action: event.kind,
    description: raw || "该活动没有附加说明。",
    purpose: { text: "记录 Agent 的公开活动与系统处置", source: event.source, confidence: "observed" },
    effects: { reads: [], writes: [], network: [], processes: [] },
    risk: { level: policyOutcome === "blocked" ? "critical" : policyOutcome ? "warning" : "low", reasons: [], basis: event.source },
    result: { status: event.status, summary: raw },
    sources: [event.source],
    conservative_fallback: false,
  };
}

export function explanationFor(event: WorkbenchEvent): ActivityExplanation {
  return event.explanation && Object.keys(event.explanation).length
    ? event.explanation
    : fallbackExplanation(event);
}

export function evidenceFor(event: WorkbenchEvent): ActivityEvidence {
  return event.evidence && Object.keys(event.evidence).length
    ? event.evidence
    : {
        availability: "unavailable",
        completeness: "none",
        summary: "暂无 OS 级证据",
        observations: [],
        negative_observations: [],
        correlation: { turn_id: event.turn_id, item_id: event.item_id, confidence: "none" },
      };
}

export function rawCommand(event: WorkbenchEvent): string {
  const payload = payloadObject(event);
  const item = payload.item && typeof payload.item === "object"
    ? payload.item as Record<string, unknown>
    : {};
  return String(item.command || payload.command || event.summary || "");
}

export function statusLabel(status?: string): string {
  return {
    running: "运行中",
    streaming: "运行中",
    started: "运行中",
    submitted: "已提交",
    completed: "成功",
    approved: "已批准",
    pending: "等待处理",
    updated: "已更新",
    blocked: "已阻断",
    deny: "已阻断",
    review: "待复核",
    review_required: "待复核",
    transformed: "已安全调整",
    detected: "已识别",
    observed: "已记录",
    declined: "已拒绝",
    failed: "失败",
    interrupted: "已停止",
    interrupting: "正在停止",
    connected: "已连接",
    warning: "需注意",
    idle: "空闲",
  }[status || ""] || status || "未知";
}

export function stepStatusLabel(status?: string): string {
  return statusLabel(status === "in_progress" ? "running" : status);
}

export function sourceLabel(source?: string): string {
  return {
    deterministic_command_analysis: "确定性命令解析",
    deterministic_file_change_analysis: "确定性文件分析",
    tool_capability_registry: "工具能力声明",
    agent_plan: "Agent 公开计划",
    contextual_inference: "上下文推断",
    os_observation: "OS 实际观测",
    security_policy: "安全策略决定",
    codexscope_policy: "安全策略决定",
    codex_app_server: "Agent 协议事实",
    user_decision: "用户决定",
    business_policy: "生活化业务策略",
    workbuddy_transaction_gateway: "WorkBuddy 事务策略",
    lingmou_workbuddy: "WorkBuddy 事务策略",
    conservative_fallback: "保守回退",
    lingmou_workbench: "灵眸工作台",
    user: "用户操作",
  }[source || ""] || source || "未标注";
}

export function riskRank(level?: string): number {
  return { low: 0, normal: 0, notice: 1, warning: 2, medium: 2, high: 3, critical: 4 }[level || ""] ?? 2;
}

export function riskLabel(level?: string): string {
  return { low: "低风险", normal: "低风险", notice: "提示", warning: "需注意", medium: "中风险", high: "高风险", critical: "严重风险" }[level || ""] || "风险待确认";
}

export function evidenceLabel(value?: string): string {
  return {
    complete: "完整",
    partial: "部分",
    none: "暂无",
    available: "已有证据",
    unavailable: "暂无证据",
    available_unassociated: "尚未关联",
    pre_execution: "执行前证据",
  }[value || ""] || value || "暂无";
}

export function hasSideEffects(explanation?: ActivityExplanation): boolean {
  const effects = explanation?.effects;
  return Boolean(
    effects?.writes?.length
    || effects?.network?.length
    || effects?.external_write,
  );
}

export function formatTime(seconds: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(seconds * 1000));
}

export function countByFilter(events: WorkbenchEvent[]): Record<FeedFilter, number> {
  return {
    all: events.filter((event) => eventMatches(event, "all")).length,
    needs_action: events.filter((event) => eventMatches(event, "needs_action")).length,
    changes: events.filter((event) => eventMatches(event, "changes")).length,
    tools: events.filter((event) => eventMatches(event, "tools")).length,
    risk: events.filter((event) => eventMatches(event, "risk")).length,
  };
}
