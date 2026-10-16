import type { KeyboardEvent, ReactNode } from "react";
import {
  explanationFor,
  formatTime,
  riskLabel,
  sourceLabel,
  statusLabel,
} from "../activity";
import type { ActivityEffects, WorkbenchEvent } from "../types";

export function StatusPill({ status }: { status?: string }) {
  return <span className={`status-pill status-${status || "unknown"}`}>{statusLabel(status)}</span>;
}

export function RiskPill({ level }: { level?: string }) {
  return <span className={`risk-pill risk-${level || "unknown"}`}>{riskLabel(level)}</span>;
}

export function SourceBadge({ source }: { source?: string }) {
  return <span className="source-badge">来源：{sourceLabel(source)}</span>;
}

function EffectRow({ label, values, empty = "无" }: { label: string; values?: string[]; empty?: string }) {
  return (
    <div className="effect-row">
      <dt>{label}</dt>
      <dd className={values?.length ? "" : "effect-empty"}>{values?.length ? values.join("、") : empty}</dd>
    </div>
  );
}

export function EffectsGrid({ effects }: { effects?: ActivityEffects }) {
  return (
    <dl className="effects-grid">
      <EffectRow label="文件读取" values={effects?.reads} />
      <EffectRow label="文件写入" values={effects?.writes} />
      <EffectRow label="网络访问" values={effects?.network} />
      <EffectRow label="本地进程" values={effects?.processes} />
    </dl>
  );
}

export function EventShell({
  event,
  selected,
  icon,
  children,
  onSelect,
}: {
  event: WorkbenchEvent;
  selected: boolean;
  icon: ReactNode;
  children: ReactNode;
  onSelect: () => void;
}) {
  const explanation = explanationFor(event);
  const keyDown = (keyboardEvent: KeyboardEvent<HTMLElement>) => {
    if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
      keyboardEvent.preventDefault();
      onSelect();
    }
  };
  return (
    <article
      className={`activity-card ${selected ? "selected" : ""} risk-border-${explanation.risk?.level || "low"}`}
      onClick={onSelect}
      onKeyDown={keyDown}
      tabIndex={0}
      aria-current={selected ? "true" : undefined}
    >
      <div className="activity-card-icon" aria-hidden="true">{icon}</div>
      <div className="activity-card-content">
        <header className="activity-card-header">
          <div>
            <h3>{explanation.headline || event.title}</h3>
            <time dateTime={new Date(event.occurred_at * 1000).toISOString()}>{formatTime(event.occurred_at)}</time>
          </div>
          <StatusPill status={event.status} />
        </header>
        {children}
      </div>
    </article>
  );
}

export function ExplanationBlock({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="explanation-block">
      <h4>{label}</h4>
      {children}
    </section>
  );
}
