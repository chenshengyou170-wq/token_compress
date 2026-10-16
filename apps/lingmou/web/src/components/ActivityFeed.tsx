import { useEffect, useMemo, useRef, useState } from "react";
import { groupTimeline, stepStatusLabel } from "../activity";
import type { WorkbenchEvent } from "../types";
import { ActivityCard } from "./ActivityCard";
import { CommandCard } from "./CommandCard";
import { FileChangeCard } from "./FileChangeCard";
import { Icon } from "./Icon";
import { ToolCard } from "./ToolCard";

function EventCard({
  event,
  selectedId,
  onSelect,
  onShowEvidence,
}: {
  event: WorkbenchEvent;
  selectedId: string | null;
  onSelect: (event: WorkbenchEvent) => void;
  onShowEvidence: (event: WorkbenchEvent) => void;
}) {
  const props = {
    event,
    selected: event.event_id === selectedId,
    onSelect: () => onSelect(event),
    onShowEvidence: () => onShowEvidence(event),
  };
  if (event.kind === "command") return <CommandCard {...props} />;
  if (["tool", "agent_tool", "web_search"].includes(event.kind)) return <ToolCard {...props} />;
  if (["file_change", "diff"].includes(event.kind)) return <FileChangeCard {...props} />;
  return <ActivityCard {...props} />;
}

function StepGroup({
  group,
  selectedId,
  onSelect,
  onShowEvidence,
}: {
  group: ReturnType<typeof groupTimeline>[number];
  selectedId: string | null;
  onSelect: (event: WorkbenchEvent) => void;
  onShowEvidence: (event: WorkbenchEvent) => void;
}) {
  const completed = group.step.status === "completed";
  const containsSelected = group.events.some((event) => event.event_id === selectedId);
  const [open, setOpen] = useState(!completed || containsSelected);
  useEffect(() => {
    if (containsSelected) setOpen(true);
  }, [containsSelected]);
  return (
    <details
      className="step-group virtual-step"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="step-heading">
        <span className="step-index">{group.step.index || 1}</span>
        <span className="step-title">
          <strong>{group.step.title || "执行任务"}</strong>
          <small>{completed ? `${group.events.length} 项活动 · 点击展开` : `${group.events.length} 项活动`}</small>
        </span>
        <span className={`step-status status-${group.step.status || "running"}`}>{stepStatusLabel(group.step.status)}</span>
        <span className="step-chevron"><Icon name="chevronDown" size={17} /></span>
      </summary>
      <div className="step-events">
        {group.events.map((event) => (
          <EventCard
            key={`${event.event_id}:${event.seq}`}
            event={event}
            selectedId={selectedId}
            onSelect={onSelect}
            onShowEvidence={onShowEvidence}
          />
        ))}
      </div>
    </details>
  );
}

export function ActivityFeed({
  events,
  totalEvents,
  selectedId,
  onSelect,
  onShowEvidence,
  onStartTask,
  onSafetyDemo,
  onRestore,
}: {
  events: WorkbenchEvent[];
  totalEvents: number;
  selectedId: string | null;
  onSelect: (event: WorkbenchEvent) => void;
  onShowEvidence: (event: WorkbenchEvent) => void;
  onStartTask: () => void;
  onSafetyDemo: () => void;
  onRestore: () => void;
}) {
  const groups = useMemo(() => groupTimeline(events), [events]);
  const feedRef = useRef<HTMLDivElement>(null);
  const previousLength = useRef(events.length);
  const following = useRef(true);
  const [newCount, setNewCount] = useState(0);

  useEffect(() => {
    const delta = Math.max(0, events.length - previousLength.current);
    previousLength.current = events.length;
    const node = feedRef.current;
    if (!node || !delta) return;
    if (following.current) {
      requestAnimationFrame(() => node.scrollTo({ top: node.scrollHeight, behavior: "smooth" }));
    } else {
      setNewCount((value) => value + delta);
    }
  }, [events.length, events.at(-1)?.seq]);

  const catchUp = () => {
    const node = feedRef.current;
    if (node) node.scrollTo({ top: node.scrollHeight, behavior: "smooth" });
    following.current = true;
    setNewCount(0);
  };

  const scroll = () => {
    const node = feedRef.current;
    if (!node) return;
    following.current = node.scrollHeight - node.scrollTop - node.clientHeight < 180;
    if (following.current) setNewCount(0);
  };

  return (
    <section className="feed-region" aria-labelledby="activity-feed-title">
      <div className="feed-heading">
        <div><h2 id="activity-feed-title">活动流</h2><p>按执行步骤组织</p></div>
        <span>{events.length === totalEvents ? `${events.length} 项高层活动` : `显示 ${events.length} / ${totalEvents} 项`}</span>
      </div>
      <div
        className={`activity-feed ${events.length > 300 ? "browser-virtualized" : ""}`}
        ref={feedRef}
        onScroll={scroll}
        aria-live="polite"
      >
        {!events.length && (
          <div className="empty-feed">
            <div className="empty-symbol"><Icon name="spark" size={24} /></div>
            <h3>{totalEvents ? "没有匹配的活动" : "从一个具体任务开始"}</h3>
            <p>{totalEvents ? "调整筛选条件或搜索关键词后再试。" : "灵眸会把 Agent 的计划、操作、结果和安全处置组织成可理解的任务流。"}</p>
            {!totalEvents && (
              <div className="empty-actions">
                <button type="button" className="primary-button" onClick={onStartTask}>输入任务</button>
                <button type="button" className="secondary-button" onClick={onSafetyDemo}>安全演示</button>
                <button type="button" className="secondary-button" onClick={onRestore}>恢复历史运行</button>
              </div>
            )}
          </div>
        )}
        {groups.map((group) => (
          <StepGroup
            key={`${group.id}:${group.step.status}`}
            group={group}
            selectedId={selectedId}
            onSelect={onSelect}
            onShowEvidence={onShowEvidence}
          />
        ))}
      </div>
      {newCount > 0 && (
        <button type="button" className="new-events-button" onClick={catchUp}>有 {newCount} 条新事件 <Icon name="arrowDown" size={15} /></button>
      )}
    </section>
  );
}
