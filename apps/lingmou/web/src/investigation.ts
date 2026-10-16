import type {
  ConfidenceTier,
  InvestigationEdge,
  InvestigationNode,
  InvestigationStage,
  InvestigationTimeGap,
} from "./types";

export const stageOrder: InvestigationStage[] = [
  "entry",
  "access",
  "collect",
  "transform",
  "egress",
  "outcome",
];

export const stageLabels: Record<InvestigationStage, string> = {
  entry: "入口",
  access: "访问 / 侦察",
  collect: "收集",
  transform: "加工 / 准备",
  egress: "外联 / 高危执行",
  outcome: "结果 / 处置",
};

export const confidenceLabels: Record<ConfidenceTier, string> = {
  fact: "已观察事实",
  strong: "强关联",
  candidate: "候选关联",
  unproven: "无法证明",
};

export function relationLabel(value: string): string {
  return {
    SAME_ITEM_LIFECYCLE: "同一 Item 生命周期",
    SAME_FILE_VERSION: "同一文件版本",
    SAME_FILE_IDENTITY: "同一文件身份",
    SAME_PATH_CANDIDATE: "同路径候选",
    SAME_PROCESS: "同一进程",
    SAME_NETWORK_TARGET: "同一网络目标",
    SAME_EXECUTABLE: "同一执行体",
    DECLARED_CONTEXT: "公开任务语境",
    TURN_SEQUENCE: "同回合记录顺序",
    POLICY_DECIDES: "策略决定",
    ACTION_RESULT: "操作与最终结果",
  }[value] || value;
}

export function investigationStatusLabel(value?: string | null): string {
  return {
    blocked: "已阻断",
    completed: "已执行",
    executed: "已执行",
    failed: "执行失败",
    attempt_failed: "尝试失败",
    interrupted: "已中断",
    attempt_interrupted: "尝试中断",
    requested_not_executed: "已请求、未执行",
    requested: "已请求",
    pending: "等待审批",
    running: "执行中",
    started: "执行中",
  }[value || ""] || "已记录";
}

export function evidenceStateLabel(value?: string | null): string {
  return {
    available: "可用",
    available_unassociated: "可用但未归因",
    pre_execution: "执行前证据",
    unavailable: "不可用",
    complete: "完整",
    partial: "部分",
    none: "无",
  }[value || ""] || value || "未知";
}

export function fileAccessLabel(value: string): string {
  return {
    read: "读取",
    write: "写入",
    rename: "重命名",
    delete: "删除",
    execute: "执行",
    metadata_write: "修改元数据",
    attempted_read: "请求读取（未执行）",
    attempted_write: "请求写入（未执行）",
  }[value] || value;
}

export function captureCompletenessLabel(value?: string | null): string {
  return {
    content_hash: "元数据与内容哈希",
    metadata_only: "仅元数据",
    unavailable: "不可用",
  }[value || ""] || value || "未知";
}

export function formatInvestigationTime(value?: number | null): string {
  if (!value) return "时间未知";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(value * 1_000);
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))} 秒`;
  if (seconds < 3_600) return `${Math.round(seconds / 60)} 分钟`;
  if (seconds < 86_400) return `${Math.round(seconds / 3_600)} 小时`;
  return `${Math.round(seconds / 86_400)} 天`;
}

export function isTimeGap(
  value: InvestigationNode | InvestigationTimeGap,
): value is InvestigationTimeGap {
  return value.node_type === "time_gap";
}

export function incidentEdges(
  nodeId: string,
  edges: InvestigationEdge[],
): InvestigationEdge[] {
  return edges.filter((edge) => edge.source === nodeId || edge.target === nodeId);
}

export function shortHash(value?: string | null, length = 12): string {
  if (!value) return "未采集";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}
