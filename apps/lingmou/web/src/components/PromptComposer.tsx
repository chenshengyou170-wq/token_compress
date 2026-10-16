import { forwardRef, type FormEvent, type KeyboardEvent } from "react";
import { Icon } from "./Icon";
import type { WorkBuddyScenario } from "../types";

export const PromptComposer = forwardRef<HTMLTextAreaElement, {
  active: boolean;
  connected: boolean;
  busy: boolean;
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  onStop: () => void;
  agentBackend: string;
  constraintSummary?: string;
  selectedScenario?: WorkBuddyScenario | null;
  onClearScenario: () => void;
}>(function PromptComposer({ active, connected, busy, value, onChange, onSubmit, onStop, agentBackend, constraintSummary, selectedScenario, onClearScenario }, ref) {
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit();
  };
  const keyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      onSubmit();
    }
  };
  const supportsSteer = agentBackend !== "codebuddy";
  const helper = !connected
    ? "正在连接本地 Agent"
    : active
      ? supportsSteer ? "Agent 运行中，可实时修正方向" : "CodeBuddy 运行中；需要改动时请停止后重新提交"
      : selectedScenario ? `将发送到 ${selectedScenario.id} 的独立沙箱` : "任务会通过本机工作台发送";
  return (
    <form className={`prompt-composer ${active ? "steer-mode" : ""}`} onSubmit={submit} aria-busy={busy}>
      {constraintSummary && <div className="composer-constraint"><strong>当前策略已生效</strong><span>{constraintSummary}</span><a href="#/policies">管理规则</a></div>}
      <label className="composer-label" htmlFor="workbench-prompt">
        <span>{active ? "补充当前任务" : "输入新任务"}</span>
        <small id="composer-helper">{helper}</small>
      </label>
      {selectedScenario && !active && (
        <div className="composer-scenario">
          <span><Icon name="tool" size={15} /><strong>{selectedScenario.id}</strong>{selectedScenario.title}</span>
          <button type="button" onClick={onClearScenario}>取消场景</button>
        </div>
      )}
      <textarea
        id="workbench-prompt"
        ref={ref}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={keyDown}
        placeholder={!connected ? "等待 Agent 连接后即可输入任务" : active ? supportsSteer ? "补充要求、修正方向或提供新信息…" : "CodeBuddy 正在运行；可先停止当前回合" : "告诉 Agent 你想完成什么…"}
        rows={3}
        disabled={!connected || busy || (active && !supportsSteer)}
        aria-describedby="composer-helper composer-shortcut"
        aria-keyshortcuts="Control+Enter Meta+Enter"
      />
      <div className="composer-actions">
        <span id="composer-shortcut">Ctrl / ⌘ + Enter 发送</span>
        <div>
          {active && <button type="button" className="stop-button" onClick={onStop} disabled={busy}><Icon name="stop" size={15} />停止</button>}
          {(!active || supportsSteer) && <button type="submit" className="primary-button" disabled={!value.trim() || !connected || busy}>
            {busy ? "处理中…" : active ? "实时补充" : "发送任务"}
          </button>}
        </div>
      </div>
    </form>
  );
});
