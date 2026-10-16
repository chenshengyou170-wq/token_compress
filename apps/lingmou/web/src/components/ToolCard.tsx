import { explanationFor } from "../activity";
import type { WorkbenchEvent } from "../types";
import { EventShell, ExplanationBlock, SourceBadge } from "./CardPrimitives";
import { Icon } from "./Icon";

function yesNoUnknown(value: boolean | null | undefined, yes: string, no: string): string {
  if (value == null) return "尚未登记";
  return value ? yes : no;
}

export function ToolCard({
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
  const effects = explanation.effects;
  const registered = explanation.tool?.side_effects_registered;
  return (
    <EventShell event={event} selected={selected} icon={<Icon name={event.kind === "agent_tool" ? "agents" : "tool"} size={17} />} onSelect={onSelect}>
      <ExplanationBlock label="用途">
        <p>{explanation.description}</p>
        <SourceBadge source={explanation.sources?.[0]} />
      </ExplanationBlock>
      <dl className="tool-facts">
        <div><dt>工具</dt><dd>{[explanation.tool?.server, explanation.tool?.name].filter(Boolean).join(" / ") || event.title}</dd></div>
        <div><dt>外部通信</dt><dd>{yesNoUnknown(registered === false ? null : Boolean(effects?.network?.length), "会离开本机", "无")}</dd></div>
        <div><dt>文件修改</dt><dd>{yesNoUnknown(registered === false ? null : Boolean(effects?.writes?.length), "可能修改", "无")}</dd></div>
        <div><dt>外部状态</dt><dd>{yesNoUnknown(effects?.external_write, "可能修改", "不会修改")}</dd></div>
      </dl>
      {!explanation.tool?.side_effects_registered && (
        <p className="fallback-note">副作用尚未登记，请在批准前检查工具参数。</p>
      )}
      <ExplanationBlock label="结果">
        <p className="result-summary">{explanation.result?.summary || "暂无结果摘要"}</p>
      </ExplanationBlock>
      <div className="card-actions">
        <details onClick={(clickEvent) => clickEvent.stopPropagation()}>
          <summary>查看非敏感参数</summary>
          <pre className="raw-data-inline">{JSON.stringify(explanation.tool?.non_sensitive_arguments ?? {}, null, 2)}</pre>
        </details>
        <button
          type="button"
          className="text-button"
          onClick={(clickEvent) => {
            clickEvent.stopPropagation();
            onShowEvidence();
          }}
        >查看调用证据</button>
      </div>
    </EventShell>
  );
}
