const api = window.lingmouDesktop;
const title = document.querySelector("#status-title");
const message = document.querySelector("#status-message");
const detail = document.querySelector("#status-detail");
const progress = document.querySelector("#progress-track");
const errorBox = document.querySelector("#error-box");
const recent = document.querySelector("#last-workspace");
const recentName = document.querySelector("#last-workspace-name");
const recentPath = document.querySelector("#last-workspace-path");
const choose = document.querySelector("#choose-workspace");
const startLast = document.querySelector("#start-last");
const connectExisting = document.querySelector("#connect-existing");
const remoteServiceForm = document.querySelector("#remote-service-form");
const serviceUrl = document.querySelector("#service-url");
const serviceFingerprint = document.querySelector("#service-fingerprint");
const connectService = document.querySelector("#connect-service");

function workspaceName(value) {
  return value.split(/[\\/]/).filter(Boolean).at(-1) || value;
}

function render(state) {
  const busy = state.phase === "starting" || state.phase === "ready";
  title.textContent = state.title;
  message.textContent = state.message;
  detail.textContent = state.detail || "";
  progress.hidden = !busy;
  errorBox.hidden = state.phase !== "error";
  errorBox.textContent = state.phase === "error" ? state.message : "";
  choose.disabled = busy || state.localMonitorSupported === false;
  startLast.disabled = busy || state.localMonitorSupported === false;
  connectExisting.disabled = busy || state.localMonitorSupported === false;
  if (state.localMonitorSupported === false && state.phase === "idle") {
    title.textContent = "连接现有灵眸服务";
    message.textContent = "Windows 本机请使用 Token 压缩；安全工作台可在下方连接已有灵眸服务。";
    document.querySelector("#launcher-title").textContent = "连接你的灵眸安全中心";
    document.querySelector(".launcher-description").textContent = "通过服务登录链接和证书指纹打开现有安全工作台。本机 Token 压缩从独立入口管理。";
    document.querySelector(".launcher-capabilities").hidden = true;
    document.querySelector(".launch-contract").hidden = true;
  }
  serviceUrl.disabled = busy;
  serviceFingerprint.disabled = busy;
  connectService.disabled = busy;
  if (state.lastWorkspace) {
    recent.hidden = false;
    recentName.textContent = workspaceName(state.lastWorkspace);
    recentPath.textContent = state.lastWorkspace;
    recentPath.title = state.lastWorkspace;
  } else {
    recent.hidden = true;
  }
}

choose.addEventListener("click", () => { void api.chooseAndStart(); });
document.querySelector("#open-compression").addEventListener("click", () => { void api.openCompression(); });
startLast.addEventListener("click", () => { void api.startLast(); });
connectExisting.addEventListener("click", () => { void api.connectExisting(); });
remoteServiceForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!remoteServiceForm.reportValidity()) return;
  connectService.disabled = true;
  void api.connectService(serviceUrl.value.trim(), serviceFingerprint.value.trim())
    .then((result) => {
      if (!result?.ok) serviceUrl.focus();
    })
    .finally(() => { void api.getState().then(render); });
});
document.querySelector("#quit-app").addEventListener("click", () => api.quit());

api.onStatus(render);
void api.getState().then(render);
