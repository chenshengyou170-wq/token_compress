import type { WorkbenchState } from "../types";
import { TokenUsagePanel } from "./TokenUsagePanel";

export function TokenUsageView({ workspace, model }: Pick<WorkbenchState, "workspace" | "model">) {
  const workspaceName = workspace.split("/").filter(Boolean).at(-1) || workspace;
  return (
    <main className="token-center" aria-labelledby="token-page-title">
      <header className="token-center-header">
        <div>
          <h1 id="token-page-title">Token 用量</h1>
          <p>当前工作区：<span title={workspace}>{workspaceName}</span> · {model || "模型尚未确认"}</p>
        </div>
      </header>
      <TokenUsagePanel />
    </main>
  );
}
