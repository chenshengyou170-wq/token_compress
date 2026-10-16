import { explanationFor, evidenceFor, rawCommand, riskRank } from "../activity";
import type { WorkbenchEvent } from "../types";
import { EffectsGrid, EventShell, ExplanationBlock, SourceBadge } from "./CardPrimitives";
import { Icon } from "./Icon";

export function CommandCard({
  event,
  selected,
  onSelect,
  onShowEvidence,
}: {
  event: WorkbenchEvent;
  selected: boolean;
  onSelect: () => void;
  onShowEvidence: () => void;
}) {
  const explanation = explanationFor(event);
  const evidence = evidenceFor(event);
  const command = rawCommand(event);
  const dangerous = riskRank(explanation.risk?.level) >= 3;
  return (
    <EventShell event={event} selected={selected} icon={<Icon name="terminal" size={17} />} onSelect={onSelect}>
      <ExplanationBlock label="作用">
        <p>{explanation.description}</p>
        {explanation.conservative_fallback && (
          <p className="fallback-note">系统暂时无法判断完整副作用，请在执行前检查原始命令与审批范围。</p>
        )}
      </ExplanationBlock>
      <ExplanationBlock label="为什么执行">
        <p>{explanation.purpose?.text || "完成当前任务中的执行步骤"}</p>
        <SourceBadge source={explanation.purpose?.source} />
      </ExplanationBlock>
      <ExplanationBlock label="影响范围">
        <EffectsGrid effects={explanation.effects} />
      </ExplanationBlock>
      <ExplanationBlock label="结果">
        <p className="result-summary">{explanation.result?.summary || "暂无结果摘要"}</p>
      </ExplanationBlock>
      <div className="card-actions">
        <details onClick={(clickEvent) => clickEvent.stopPropagation()}>
          <summary>展开原始命令</summary>
          <pre className={dangerous ? "raw-command dangerous-command" : "raw-command"}>{command || "原始命令未提供"}</pre>
        </details>
        <button
          type="button"
          className="text-button"
          onClick={(clickEvent) => {
            clickEvent.stopPropagation();
            onShowEvidence();
          }}
        >
          {evidence.availability === "unavailable" ? "查看证据状态" : "查看系统证据"}
        </button>
      </div>
    </EventShell>
  );
}
