import type { ActivityEffects } from "./types";

export type IncidentNarrative = {
  subject: string;
  happened: string;
  consequence: string;
  from: string;
  to: string;
  facts?: Array<{ label: string; value: string }>;
  blockedStatement?: string;
  nextStep?: string;
};

// Known policy identities, not guesses from arbitrary Agent prose.
export function incidentNarrative(ids: string[], effects?: ActivityEffects, impact?: Record<string, unknown>): IncidentNarrative | null {
  const has = (...values: string[]) => values.some((id) => ids.includes(id));
  if (has("WORK-SOURCE-CHURN-018")) {
    const facts: NonNullable<IncidentNarrative["facts"]> = [];
    const number = (key: string) => typeof impact?.[key] === "number" && Number.isFinite(impact[key]) && impact[key] >= 0 ? impact[key] as number : null;
    const score = number("churn_anomaly_score"), threshold = number("churn_score_threshold");
    const commission = number("commission_yuan"), fills = number("fill_count"), turnover = number("turnover_yuan");
    if (score != null) facts.push({ label: "异常评分", value: score.toLocaleString("zh-CN") });
    if (threshold != null) facts.push({ label: "阻断阈值", value: threshold.toLocaleString("zh-CN") });
    if (fills != null && Number.isInteger(fills)) facts.push({ label: "账本已成交", value: `${fills} 笔` });
    if (turnover != null) facts.push({ label: "累计成交额", value: `¥${turnover.toLocaleString("zh-CN")}` });
    if (commission != null) facts.push({ label: impact?.simulation === true ? "已付模拟佣金" : "账本已付佣金", value: `¥${commission.toLocaleString("zh-CN")}` });
    const paused = impact?.strategy_status === "paused";
    if (paused) facts.push({ label: "策略状态", value: "已暂停" });
    return {
      subject: "旧资讯触发反复交易",
      happened: "同一条外部资讯被延迟或缓存重复送达，关联到连续买卖委托。重复资讯、往返成交与佣金消耗共同构成风险证据。",
      consequence: "继续把旧资讯当成新信号下单，可能增加无效往返交易和佣金支出，并使仓位偏离原定计划。已经发生的成交和佣金不会因拦截新委托而撤销。",
      from: "延迟 / 缓存重放的资讯", to: "反复买卖委托", facts,
      blockedStatement: paused ? "新委托已拦截，策略已暂停" : "本次新委托未进入执行阶段",
      nextStep: "用 trading_get 核对资讯、成交、已付佣金与策略状态；查明资讯重放原因并完成复核后，再决定是否恢复策略。",
    };
  }
  const payment = has("PAY-KEY-001", "PAY-ENCODE-002", "PAY-EXFIL-004");
  const exfil = has("PAY-EXFIL-004", "LING-EXFIL-004", "LING-LINEAGE-030") || payment && has("PAY-EGRESS-003");
  const asset = (effects?.reads || []).find((path) => /secret|credential|\.env/i.test(path));
  const destination = effects?.network?.[0];
  let host: string | undefined;
  if (destination) {
    try { host = new URL(destination.includes("://") ? destination : `https://${destination}`).host; }
    catch { host = destination; }
  }
  if (exfil) return {
    subject: payment ? "支付密钥外泄" : "敏感数据外传",
    happened: payment ? "Agent 准备把支付密钥发送到外部地址。" : "Agent 准备把敏感内容或其派生文件发送到外部地址。",
    consequence: payment ? "密钥一旦发出，接收方就可能冒用支付服务身份，读取交易信息或发起密钥权限内的操作。" : "数据一旦发出，外部接收方就能保存和转发，撤销本次操作无法收回已有副本。",
    from: asset || (payment ? "支付密钥文件" : "敏感文件"), to: host || "外部接收地址",
  };
  if (has("WORK-PROCURE-007", "WORK-SPEND-008")) {
    const facts: NonNullable<IncidentNarrative["facts"]> = [];
    const n = (key: string) => typeof impact?.[key] === "number" && Number.isFinite(impact[key]) && impact[key] >= 0 ? impact[key] as number : null;
    const current = n("current_boxes"), target = n("target_boxes"), spent = n("prior_spend_yuan");
    if (current != null) facts.push({ label: "当前库存", value: `${current} 箱` });
    if (target != null) facts.push({ label: "目标库存", value: `${target} 箱` });
    if (spent != null) facts.push({ label: "已有采购金额", value: `¥${spent.toLocaleString("zh-CN")}` });
    return {
      subject: has("WORK-PROCURE-007") ? "重复采购" : "采购金额超出审批阈值",
      happened: has("WORK-PROCURE-007") ? "库存已满足目标或已有有效采购单，Agent 仍在尝试再次提交采购。" : "这笔采购将使累计金额超过审批阈值，尚需你确认。",
      consequence: has("WORK-PROCURE-007") ? "把回执超时当成下单失败，继续提交相同订单，可能造成重复补货、额外支出和对账困难。" : "放行后会增加采购支出，并超过当前审批额度。请先核对预算和已有订单。",
      from: has("WORK-PROCURE-007") ? "已有库存 / 有效采购单" : "本次采购申请", to: "再次提交采购", facts,
    };
  }
  if (payment) return {
    subject: has("PAY-ENCODE-002") ? "支付密钥正在被编码" : "Agent 正在请求读取支付密钥",
    happened: has("PAY-ENCODE-002") ? "Agent 准备把支付密钥转换为 Base64 文本。编码不是脱敏，仍能还原出原始密钥。" : "这一步会让支付密钥内容进入 Agent 可见的工具返回结果。",
    consequence: "密钥如果随后被写入日志或上传，接收方可能冒用支付身份。当前证据只表明读取或编码请求，尚不能认定已经外泄。",
    from: asset || "支付密钥文件", to: has("PAY-ENCODE-002") ? "可还原的编码文本" : "Agent 工具返回结果",
  };
  return null;
}
