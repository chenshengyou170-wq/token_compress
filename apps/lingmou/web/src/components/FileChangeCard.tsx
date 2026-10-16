import { explanationFor, payloadObject } from "../activity";
import type { WorkbenchEvent } from "../types";
import { EffectsGrid, EventShell, ExplanationBlock, SourceBadge } from "./CardPrimitives";
import { Icon } from "./Icon";

export function FileChangeCard({
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
  const payload = payloadObject(event);
  const diff = typeof payload.diff === "string" ? payload.diff : "";
  return (
    <EventShell event={event} selected={selected} icon={<Icon name="file" size={17} />} onSelect={onSelect}>
      <ExplanationBlock label="发生了什么">
        <p>{explanation.description}</p>
        <SourceBadge source={explanation.sources?.[0]} />
      </ExplanationBlock>
      <ExplanationBlock label="影响范围">
        <EffectsGrid effects={explanation.effects} />
      </ExplanationBlock>
      <ExplanationBlock label="结果">
        <p className="result-summary">{explanation.result?.summary || "文件变更已记录"}</p>
      </ExplanationBlock>
      <div className="card-actions">
        {diff && (
          <details onClick={(clickEvent) => clickEvent.stopPropagation()}>
            <summary>展开 diff</summary>
            <pre className="diff-preview">{diff}</pre>
          </details>
        )}
        <button
          type="button"
          className="text-button"
          onClick={(clickEvent) => {
            clickEvent.stopPropagation();
            onShowEvidence();
          }}
        >查看变更证据</button>
      </div>
    </EventShell>
  );
}
