"use strict";

const api = window.lingmouCompression;
const element = (id) => document.getElementById(id);
const number = (value) => typeof value === "number" && Number.isFinite(value) ? value.toLocaleString("zh-CN") : "—";
const DEFAULT_UPSTREAM = { chatgpt: "https://chatgpt.com/backend-api/codex", api: "https://api.openai.com/v1" };
const MODE_LABELS = { off: "仅采集用量", structure: "结构压缩", extract: "按任务选段", auto: "本地自动", full: "完整压缩" };
const MODE_HINTS = {
  off: "压缩已关闭。请求仍通过本地服务，用量采集继续；解除接入后恢复直连。",
  structure: "结构压缩仅处理工具结果和显式参考材料；没有收益时保留原文。",
  extract: "按任务选段属于有损压缩。原文保留供补读；当前请求没有补读工具时使用结构压缩。",
  auto: "本地自动组合结构压缩与原文选段，属于有损压缩；没有补读工具时使用结构压缩。",
  full: "完整压缩会裁剪整轮旧历史、整理工具结果并按需加载技能说明，属于有损压缩。原文保留供补读；没有补读工具时使用结构压缩。",
};
let state = { enabled: false, running: false, connection: null };
let environment = {};
let inspected = null;
let busy = false;
let polling = false;
let closed = false;
let operationError = "";
let modeDirty = false;
let transportError = false;

function message(text, error = false) {
  if (error) operationError = text;
  const target = element(error ? "error-banner" : "feedback");
  target.textContent = text;
  target.hidden = !text;
}

function page(name) {
  document.querySelectorAll(".page").forEach((section) => { section.hidden = section.id !== `page-${name}`; });
  document.querySelectorAll("[data-page]").forEach((button) => {
    if (button.dataset.page === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
}

function controls() {
  ["choose-config", "inspect-config", "auth-kind", "upstream", "initial-mode"].forEach((id) => {
    element(id).disabled = busy || state.enabled;
  });
  if (inspected?.custom_provider) element("auth-kind").disabled = true;
  element("upstream").readOnly = element("auth-kind").value === "existing";
  element("connect").disabled = busy || !inspected || state.enabled;
  element("connect").textContent = busy && !state.enabled ? "正在处理…" : "保存配置并接入";
  element("active-mode").disabled = busy || !state.running;
  element("save-mode").disabled = busy || !state.running || !modeDirty;
  element("restart-service").disabled = busy || !state.enabled || state.active_requests > 0;
  element("disconnect").disabled = busy || state.active_requests > 0;
  element("clear-sources").disabled = busy || state.enabled;
  element("refresh").disabled = busy;
  element("auto-start").disabled = busy || !environment.autoStartSupported;
  for (const prefix of ["initial", "active"]) {
    const mode = element(`${prefix}-mode`).value;
    element(`${prefix}-remote-options`).hidden = mode !== "full";
    element(`${prefix}-remote`).disabled = busy || mode !== "full" || (prefix === "initial" ? state.enabled : !state.running);
    element(prefix === "initial" ? "initial-mode-hint" : "mode-hint").textContent = MODE_HINTS[mode] || MODE_HINTS.structure;
    const remote = state.remote_configuration || {};
    const missing = [!remote.kimi_configured && "Kimi", !remote.jev_configured && "TypeSafe / Jev"].filter(Boolean);
    element(`${prefix}-remote-status`).textContent = remote.ready
      ? "已检测到 Kimi 与 Jev 配置；是否可调用将在实际请求时确认。调用受预算限制，额外用量在 Token 用量页单独列出。"
      : `尚未检测到 ${missing.join("、")} 配置。开启后仍先使用本地压缩；配置完成并重新打开灵眸后，远程功能才可用。`;
  }
}

function draftChanged() {
  modeDirty = element("active-mode").value !== state.connection?.mode
    || element("active-remote").checked !== Boolean(state.connection?.remote_enabled);
  controls();
}

function compressionStatus() {
  if (!state.last_mode) return "等待请求处理";
  const mode = MODE_LABELS[state.last_mode] || "压缩";
  if (state.last_reason === "source_tool_unavailable") return "本次缺少补读工具，使用结构压缩";
  if (state.last_status === "error") return "本次压缩未完成，已保留原文转发";
  if (state.last_reason === "server_managed_context") return "上下文由模型服务管理，本次保留原文";
  if (state.last_mode === "off") return "本次仅采集用量";
  if (state.last_reason === "tool_loading_deferred") return "已设置工具按需加载，实际用量以模型返回为准";
  return state.last_status === "compressed" ? `${mode}已应用` : `${mode}未获得有效缩减，本次保留原文`;
}

function rows(targetId, data, columns, empty) {
  const target = element(targetId);
  const fragment = document.createDocumentFragment();
  if (!data.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = columns.length;
    cell.className = "empty-row";
    cell.textContent = empty;
    row.append(cell);
    fragment.append(row);
  } else {
    for (const dataRow of data) {
      const row = document.createElement("tr");
      for (const column of columns) {
        const cell = document.createElement("td");
        cell.textContent = String(column.value(dataRow));
        if (column.numeric) cell.className = "numeric";
        row.append(cell);
      }
      fragment.append(row);
    }
  }
  target.replaceChildren(fragment);
}

function render(next) {
  state = next;
  const connection = state.connection;
  const received = state.request_count > 0;
  const badge = element("connection-badge");
  badge.textContent = state.error ? "服务需要处理" : state.running
    ? received ? "已收到请求" : "已配置 · 等待请求" : state.enabled ? "连接待恢复" : "尚未接入";
  badge.dataset.status = state.error ? "error" : received && state.running ? "connected" : "idle";
  element("setup-status").textContent = badge.textContent;
  if (!state.enabled && connection?.legacy_provider_preserved) {
    element("setup-status").textContent = "旧版连接已恢复，历史会话兼容项已保留。请完全退出并重新打开 Codex；需要压缩时可重新接入。";
  }
  element("connection-form").hidden = Boolean(state.enabled);
  element("active-connection").hidden = !state.enabled;
  if (!element("config-path").value && state.default_config_path) element("config-path").value = state.default_config_path;
  if (connection) {
    element("active-config").textContent = connection.config_path;
    element("active-upstream").textContent = connection.upstream;
    element("backup-path").textContent = connection.backup_path;
    if (!modeDirty) {
      element("active-mode").value = connection.mode;
      element("active-remote").checked = Boolean(connection.remote_enabled);
    }
  }
  element("traffic-state").textContent = state.running
    ? `${number(state.request_count || 0)} 次请求 · ${number(state.active_requests || 0)} 次进行中${state.relay_errors ? ` · ${number(state.relay_errors)} 次转发异常` : ""}`
    : "后台尚未运行，请恢复服务或解除接入。";
  element("reader-state").textContent = state.source_reader_seen ? "最近请求已包含补读工具" : "尚未在请求中确认";
  const excerpt = ["extract", "auto", "full"].includes(connection?.mode);
  element("applied-mode").textContent = (MODE_LABELS[connection?.mode] || "—")
    + (connection?.mode === "full" ? connection.remote_enabled ? " · 已允许远程改写与校验" : " · 仅本地" : "");
  element("compression-state").textContent = compressionStatus();
  element("reader-hint").hidden = !(excerpt && state.last_reason === "source_tool_unavailable");
  element("source-size").textContent = state.source_count
    ? `${number(state.source_count)} 份 · ${number(Math.round(state.source_bytes / 1024))} KiB`
    : "没有保留原文";
  const error = operationError || state.error || "";
  element("error-banner").textContent = error;
  element("error-banner").hidden = !error;
  const tokens = state.tokens || {};
  const official = tokens.official || {};
  element("official-total").textContent = number(official.total_tokens);
  element("official-input").textContent = number(official.input_tokens);
  element("official-output").textContent = number(official.output_tokens);
  element("official-cached").textContent = number(official.cached_input_tokens);
  element("auxiliary-usage").hidden = !(official.known_compression_tokens > 0 || official.missing_compression_calls > 0);
  element("auxiliary-usage").textContent = `远程改写与校验另消耗 ${number(official.compression_tokens ?? official.known_compression_tokens)} tokens`
    + (official.missing_compression_calls ? `（已知小计，另有 ${number(official.missing_compression_calls)} 次调用用量未知）` : "")
    + "，未计入上方模型用量。输入缩短不代表整体费用下降。";
  element("usage-quality").textContent = !official.measured_requests ? "等待官方 usage"
    : official.missing_requests ? `已知小计 · ${number(official.missing_requests)} 次缺少用量`
      : `${number(official.measured_requests)} 次已确认`;
  element("usage-period").textContent = state.running
    ? "当前后台运行中的模型请求；多个 Codex 会话合计展示，重启后台后重新累计。"
    : "最近一次保存的后台运行记录。缺失记录时显示未知。";
  const components = tokens.breakdown?.requests ? tokens.breakdown.components || [] : [];
  rows("component-rows", components, [
    { value: (row) => row.label }, { value: (row) => number(row.after), numeric: true },
  ], "尚未收到可统计的请求。继续在 Codex 中工作后，这里会显示实际发送的组件。");
  const statusLabels = { completed: "已结束", failed: "失败", interrupted: "中断", pending: "进行中" };
  rows("request-rows", [...(tokens.recent_requests || [])].reverse(), [
    { value: (row) => row.request_id }, { value: (row) => statusLabels[row.status] || "未知" },
    { value: (row) => number(row.official_input), numeric: true },
    { value: (row) => number(row.official_output), numeric: true },
  ], "还没有请求记录。用量来自模型返回的数据，未返回的数值保持未知。");
  element("footer-status").textContent = state.running ? "本机服务运行中 · 关闭窗口后继续在托盘运行" : "本机服务未运行";
  controls();
}

async function command(method, params = {}, quiet = false) {
  const reply = await api.command(method, params);
  if (reply.canceled) return null;
  if (!reply.ok) throw new Error(reply.error || "操作未完成，请重试。");
  if (reply.environment) environment = reply.environment;
  if (reply.result?.schema_version === 1) render(reply.result);
  if (!quiet) { operationError = ""; element("error-banner").hidden = !state.error; }
  return reply.result;
}

async function action(work) {
  if (busy) return;
  busy = true;
  operationError = "";
  message("");
  controls();
  try { await work(); }
  catch (error) { message(error.message || "操作未完成。", true); }
  finally { busy = false; controls(); }
}

async function inspect() {
  inspected = null;
  controls();
  const result = await command("inspect", { config_path: element("config-path").value });
  inspected = result;
  element("config-summary").textContent = `当前供应商：${result.provider} · ${result.model}${result.exists ? "" : " · 将创建配置文件"}`;
  element("auth-kind").value = result.custom_provider ? "existing" : element("auth-kind").value === "existing" ? "chatgpt" : element("auth-kind").value;
  updateUpstream();
  controls();
}

function updateUpstream() {
  const kind = element("auth-kind").value;
  element("upstream").value = inspected?.upstream || (kind === "existing" ? "" : DEFAULT_UPSTREAM[kind]);
  element("upstream").readOnly = kind === "existing";
}

document.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", () => page(button.dataset.page)));
element("security-home").addEventListener("click", () => api.securityHome());
element("auth-kind").addEventListener("change", updateUpstream);
element("inspect-config").addEventListener("click", () => { void action(inspect); });
element("choose-config").addEventListener("click", () => {
  void action(async () => {
    const chosen = await api.chooseConfig();
    if (!chosen) return;
    element("config-path").value = chosen;
    await inspect();
  });
});
element("connection-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void action(async () => {
    await command("connect", {
      config_path: element("config-path").value, auth_kind: element("auth-kind").value,
      upstream: element("upstream").value.trim(), mode: element("initial-mode").value,
      remote_enabled: element("initial-mode").value === "full" && element("initial-remote").checked,
    });
    modeDirty = false;
    message("接入配置已保存。请重新打开 Codex；收到实际请求后，连接状态和用量会更新。");
  });
});
element("initial-mode").addEventListener("change", controls);
element("active-mode").addEventListener("change", draftChanged);
element("active-remote").addEventListener("change", draftChanged);
element("save-mode").addEventListener("click", () => {
  void action(async () => {
    const result = await command("set_mode", { mode: element("active-mode").value,
      remote_enabled: element("active-remote").checked });
    modeDirty = false;
    render(result);
    message("压缩方式已保存，从下一次请求开始使用。");
  });
});
element("disconnect").addEventListener("click", () => {
  void action(async () => {
    const result = await command("disconnect");
    if (!result) return;
    inspected = null;
    modeDirty = false;
    message("已恢复原连接。请重新打开 Codex；需要再次接入时，先读取配置。");
  });
});
element("restart-service").addEventListener("click", () => {
  void action(async () => { await command("restart"); message("后台服务已重新启动，等待 Codex 的下一次请求。用量从本次启动重新累计。"); });
});
element("clear-sources").addEventListener("click", () => {
  void action(async () => { if (await command("clear_sources")) message("保留原文已清理，配置备份与用量记录保留。"); });
});
element("show-files").addEventListener("click", () => {
  void action(async () => { const error = await api.showFiles(); if (error) throw new Error("无法打开数据目录，请检查系统文件管理器。"); });
});
element("auto-start").addEventListener("change", () => {
  const wanted = element("auto-start").checked;
  void action(async () => {
    const reply = await api.setAutoStart(wanted);
    if (!reply.ok) { element("auto-start").checked = !wanted; throw new Error(reply.error); }
    environment = reply.result;
    element("auto-start").checked = environment.autoStart;
    message(environment.autoStart ? "已设置登录 Windows 时在后台启动。" : "已关闭登录启动。接入期间请先手动打开灵眸。");
  });
});
element("refresh").addEventListener("click", () => { void action(async () => { await command("status"); }); });

api.onState(render);
window.addEventListener("beforeunload", () => { closed = true; });

async function poll() {
  if (closed) return;
  if (!busy && !polling) {
    polling = true;
    try {
      await command("status", {}, true);
      if (transportError) { operationError = ""; transportError = false; render(state); }
    }
    catch { transportError = true; message("暂时无法读取后台状态。已有配置保留，请刷新状态或重新打开灵眸。", true); }
    finally { polling = false; }
  }
  if (!closed) setTimeout(poll, document.hidden ? 10000 : 2000);
}

async function initialize() {
  try {
    environment = await api.environment();
    element("auto-start").checked = environment.autoStart;
    if (!environment.autoStartSupported) element("auto-start-hint").textContent = "登录启动在打包后的 Windows 应用中提供。源码运行时，请保持桌面程序开启。";
    await command("status");
    if (!state.enabled) await inspect();
  } catch (error) {
    message(error.message || "未能读取后台状态。", true);
  }
  controls();
  void poll();
}

void initialize();
