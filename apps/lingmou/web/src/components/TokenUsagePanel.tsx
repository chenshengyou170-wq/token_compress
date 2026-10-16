import { useEffect, useId, useState } from "react";
import type { TokenUsage } from "../types";
import { Icon } from "./Icon";
import { TokenBreakdown } from "./TokenBreakdown";

const number = (value?: number | null) => value == null ? "—" : value.toLocaleString("zh-CN");

export function TokenUsagePanel() {
  const id = useId();
  const [usage, setUsage] = useState<TokenUsage | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      try {
        const response = await fetch("/api/v1/tokens", { signal: controller.signal });
        if (!response.ok) throw new Error("Token 数据暂时无法读取，正在重试。");
        const next = await response.json() as TokenUsage;
        if (!controller.signal.aborted) { setUsage(next); setError(""); }
      } catch (reason) {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Token 数据暂时无法读取。");
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 1000);
      }
    };
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, []);

  const official = usage?.official;
  return (
    <section className="token-panel" aria-labelledby={`${id}-title`} aria-busy={!usage && !error}>
      <header className="token-panel-heading">
        <div><Icon name="database" size={19} /><h2 id={`${id}-title`}>本次运行用量</h2></div>
        <span className="token-status">{!usage ? "正在读取" : usage.capture_state === "finished" ? "已结束" : usage.capture_state === "live" ? "实时更新" : "采集未接入"}</span>
      </header>
      {error && <p className="token-notice" role="status">{error}{usage ? " 下方保留上次数据。" : ""}</p>}
      <div className="token-official">
        <p>模型已确认用量 <span>{official?.source === "app_server" ? "会话累计" : official?.measured_requests && !official.missing_requests ? "官方 usage" : "已返回部分"}</span></p>
        <strong className="token-total">{number(official?.total_tokens)}<small>tokens</small></strong>
        <dl className="token-breakdown">
          <div><dt>输入</dt><dd>{number(official?.input_tokens)}</dd></div>
          <div><dt>输出</dt><dd>{number(official?.output_tokens)}</dd></div>
          <div><dt>缓存命中 <small>输入的一部分</small></dt><dd>{number(official?.cached_input_tokens)}</dd></div>
        </dl>
        <p className="token-caption">{official?.total_tokens == null ? "等待模型返回官方用量。" : official.missing_requests ? `${official.missing_requests} 次请求尚无官方用量，以上为已知小计。` : "输入与输出来自模型已返回的官方用量。"}</p>
        {official && (official.known_compression_tokens > 0 || official.missing_compression_calls > 0) && <p className="token-caption">辅助模型另消耗 {number(official.compression_tokens ?? official.known_compression_tokens)} tokens{official.missing_compression_calls ? `（已知小计，另有 ${official.missing_compression_calls} 次调用用量未知）` : ""}，未计入上方模型用量。</p>}
        {usage?.capture_state === "live" && usage.local.current_input != null && <p className="token-caption">当前请求输入：{number(usage.local.current_input)} tokens（{usage.local.current_input_quality === "provider_exact_preflight" ? "服务商预计算" : "运行中估算"}）。</p>}
      </div>
      <TokenBreakdown usage={usage} />
      <section className="token-requests" aria-labelledby={`${id}-requests`}>
        <h3 id={`${id}-requests`}>逐请求明细</h3>
        {usage?.recent_requests.length ? <div className="token-table-scroll"><table className="token-table">
          <caption>最近 {usage.recent_requests.length} 次已结束请求，显示模型返回的官方用量。</caption>
          <thead><tr><th>请求</th><th>输入 Token</th><th>输出 Token</th><th>合计</th></tr></thead>
          <tbody>{[...usage.recent_requests].reverse().map((row, index) => <tr key={`${row.request_id}:${index}`}>
            <th scope="row">{row.request_id || `请求 ${index + 1}`}<small>{row.status === "completed" ? "已完成" : "未完整完成"}</small></th>
            <td>{number(row.official_input)}</td><td>{number(row.official_output)}</td><td>{number(row.official_input == null || row.official_output == null ? null : row.official_input + row.official_output)}</td>
          </tr>)}</tbody>
        </table></div> : <p className="token-caption">还没有逐请求记录。运行任务后自动更新。</p>}
      </section>
    </section>
  );
}
