import { useId, useState } from "react";
import type { TokenUsage } from "../types";

const number = (value?: number | null) => value == null ? "—" : value.toLocaleString("zh-CN");

export function TokenBreakdown({ usage }: { usage: TokenUsage | null }) {
  const id = useId();
  const [scope, setScope] = useState("run");
  const breakdown = usage?.breakdown;
  const measured = Boolean(breakdown?.requests);
  const current = scope === "latest" ? breakdown?.latest : breakdown;
  const partial = scope === "latest" ? measured && !breakdown?.latest.complete : Boolean(breakdown?.incomplete_requests);
  return (
    <section className="token-components" aria-labelledby={`${id}-title`}>
      <header className="token-components-heading">
        <div>
          <h3 id={`${id}-title`}>各组件用量</h3>
          <p className="token-caption">{measured ? `已采集 ${number(breakdown?.requests)} 次实际发送请求 · 最新 ${breakdown?.latest.request_id}` : !usage ? "正在读取实际请求记录…" : usage.relay_enabled ? "等待新请求，发送后自动更新各组件用量。" : "请求采集未接入，暂无组件用量明细。"}</p>
        </div>
        <label className="token-scope">统计范围
          <select value={scope} onChange={event => setScope(event.target.value)}>
            <option value="run">本次运行累计</option>
            <option value="latest">最近一次发送</option>
          </select>
        </label>
      </header>
      {measured && <>
        <div className="token-table-scroll"><table className="token-table token-component-table">
          <caption>实际发送内容的本地估算，并非官方计费拆分；历史内容随请求再次发送时重复计入。</caption>
          <thead><tr><th>请求组成</th><th>Token 数（估算）</th></tr></thead>
          <tbody>{current?.components.map(row => <tr key={row.id}>
            <th scope="row">{row.label}</th><td>{number(row.after)}</td>
          </tr>)}</tbody>
        </table></div>
        {partial && <p className="token-caption">部分请求含服务端上下文、多模态或加密字段，以上只统计可观测内容。</p>}
        <h3 className="token-tools-title">各工具明细</h3>
        {current?.tools.length ? <div className="token-table-scroll"><table className="token-table">
          <caption>按实际发送内容估算 Token 数，已包含在上方组件用量中，不重复相加。</caption>
          <thead><tr><th>工具</th><th>工具定义</th><th>调用参数</th><th>返回内容</th></tr></thead>
          <tbody>{current.tools.map(tool => <tr key={tool.name}>
            <th scope="row" title={tool.name}>{tool.name === "unknown" ? "未关联到名称的工具" : tool.name === "__other_tools__" ? "其他工具（超出单列上限）" : tool.name}</th>
            <td>{number(tool.definition_after)}</td><td>{number(tool.call_after)}</td><td>{number(tool.result_after)}</td>
          </tr>)}</tbody>
        </table></div> : <p className="token-caption">所选范围内尚未出现工具定义、调用或返回。</p>}
      </>}
    </section>
  );
}
