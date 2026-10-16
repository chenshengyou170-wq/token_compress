const { app, BrowserWindow, Menu, Tray, nativeImage, dialog, ipcMain, session, shell } = require("electron");
const { spawn } = require("node:child_process");
const { X509Certificate } = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const readline = require("node:readline");
const { fileURLToPath, pathToFileURL } = require("node:url");
const { CompressionCompanion } = require("./compression-companion.cjs");
const {
  ACCESS_COOKIE,
  normalizedFingerprint,
  parseRemoteServiceUrl,
  probeRemoteService,
} = require("./remote-service.cjs");

const installerStartup = process.platform === "win32" && require("electron-squirrel-startup");
const ownsInstance = !installerStartup && app.requestSingleInstanceLock();
if (installerStartup || !ownsInstance) app.quit();
app.enableSandbox();
if (process.platform === "win32") app.setAppUserModelId("com.squirrel.Lingmou.lingmou-agent-security");

const DESKTOP_ROOT = path.resolve(__dirname, "..");
const PROJECT_ROOT = path.resolve(DESKTOP_ROOT, "..");
const LAUNCHER_HTML = path.join(DESKTOP_ROOT, "ui", "index.html");
const LAUNCHER_URL = pathToFileURL(LAUNCHER_HTML).href;
const COMPRESSION_HTML = path.join(DESKTOP_ROOT, "ui", "compression.html");
const MAX_LOG_LINES = 80;
let automaticServiceUrl = process.env.LINGMOU_SERVICE_URL || null;
let automaticServiceFingerprint = process.env.LINGMOU_SERVICE_CERT_SHA256 || null;
delete process.env.LINGMOU_SERVICE_URL;
delete process.env.LINGMOU_SERVICE_CERT_SHA256;

let launcherWindow = null;
let mainWindow = null;
let compressionWindow = null;
let compressionCompanion = null;
let tray = null;
let monitorHandle = null;
let workbenchHandle = null;
let workbenchUrl = null;
let starting = false;
let shutdownStarted = false;
let shutdownComplete = false;
let remoteService = null;
let remoteBrowserSession = null;
const navigationGrants = new WeakMap();

let launcherState = {
  phase: "idle",
  title: "选择一个工作区开始保护",
  message: "灵眸会启动本地 Agent 监控、执行前策略门和安全工作台。",
  detail: "",
  lastWorkspace: null,
};

function appendLog(scope, message) {
  if (!app.isReady()) return;
  const line = `${new Date().toISOString()} [${scope}] ${String(message).replaceAll("\n", " ")}\n`;
  fs.appendFile(path.join(app.getPath("logs"), "lingmou-desktop.log"), line, () => {});
}

function safeLauncherState(next) {
  const allowedPhases = new Set(["idle", "starting", "ready", "error"]);
  return {
    phase: allowedPhases.has(next.phase) ? next.phase : "idle",
    title: String(next.title || "灵眸 Agent 安全中心").slice(0, 120),
    message: String(next.message || "").slice(0, 360),
    detail: String(next.detail || "").slice(0, 600),
    lastWorkspace: typeof next.lastWorkspace === "string" ? next.lastWorkspace.slice(0, 2_000) : null,
    localMonitorSupported: process.platform !== "win32",
  };
}

function updateLauncher(next) {
  launcherState = safeLauncherState({ ...launcherState, ...next });
  if (launcherWindow && !launcherWindow.isDestroyed()) {
    launcherWindow.webContents.send("launcher:status", launcherState);
  }
}

function settingsPath() {
  return path.join(app.getPath("userData"), "settings.json");
}

function readSettings() {
  try {
    const value = JSON.parse(fs.readFileSync(settingsPath(), "utf8"));
    if (value && typeof value.lastWorkspace === "string" && value.lastWorkspace.length <= 2_000) {
      return { lastWorkspace: value.lastWorkspace };
    }
  } catch {
    // First launch or an invalid local preference file; start with no workspace.
  }
  return { lastWorkspace: null };
}

function saveLastWorkspace(workspace) {
  const target = settingsPath();
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify({ lastWorkspace: workspace }, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, target);
}

function executable(pathname) {
  try {
    fs.accessSync(pathname, fs.constants.X_OK);
    return pathname;
  } catch {
    return null;
  }
}

function executableOnPath(name) {
  const pathValue = process.env.PATH || "";
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) continue;
    const candidate = executable(path.join(directory, name));
    if (candidate) return candidate;
  }
  return null;
}

function resolveBackendExecutable() {
  if (process.env.LINGMOU_CODEXSCOPE_BIN) return process.env.LINGMOU_CODEXSCOPE_BIN;

  const packaged = process.platform === "win32"
    ? path.join(process.resourcesPath, "lingmou-backend", "lingmou-backend.exe")
    : path.join(process.resourcesPath, "lingmou-backend", "lingmou-backend");
  if (app.isPackaged && executable(packaged)) return packaged;

  const development = process.platform === "win32"
    ? path.join(PROJECT_ROOT, ".venv", "Scripts", "codexscope.exe")
    : path.join(PROJECT_ROOT, ".venv", "bin", "codexscope");
  return executable(development) || "codexscope";
}

function resolveCodexExecutable() {
  if (process.env.LINGMOU_CODEX_BIN) return process.env.LINGMOU_CODEX_BIN;
  const binaryName = process.platform === "win32" ? "codex.exe" : "codex";
  const development = path.resolve(PROJECT_ROOT, "..", "codex", "codex-rs", "target", "debug", binaryName);
  const home = app.getPath("home");
  const commonLocations = process.platform === "win32"
    ? [path.join(home, "AppData", "Roaming", "npm", binaryName)]
    : [
        path.join(home, ".local", "bin", binaryName),
        path.join(home, ".npm-global", "bin", binaryName),
        path.join("/usr/local/bin", binaryName),
      ];
  return executable(development)
    || commonLocations.map(executable).find(Boolean)
    || executableOnPath(binaryName);
}

function spawnLogged(args, cwd, label) {
  const command = resolveBackendExecutable();
  appendLog(label, `spawn ${command} ${args.join(" ")}`);
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, PYTHONUNBUFFERED: "1", NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const emitter = new EventEmitter();
  const handle = { child, emitter, lines: [], exited: false, code: null, signal: null, label };

  const collect = (stream, channel) => {
    const reader = readline.createInterface({ input: stream });
    reader.on("line", (line) => {
      const value = String(line).slice(0, 4_000);
      handle.lines.push(value);
      if (handle.lines.length > MAX_LOG_LINES) handle.lines.splice(0, handle.lines.length - MAX_LOG_LINES);
      appendLog(`${label}:${channel}`, value);
      emitter.emit("line", value);
    });
  };
  collect(child.stdout, "out");
  collect(child.stderr, "err");
  child.on("error", (error) => {
    appendLog(label, `error ${error.message}`);
    emitter.emit("failure", error);
  });
  child.on("exit", (code, signal) => {
    handle.exited = true;
    handle.code = code;
    handle.signal = signal;
    appendLog(label, `exit code=${code} signal=${signal}`);
    emitter.emit("exit", code, signal);
  });
  return handle;
}

function processFailure(handle, fallback) {
  const useful = handle.lines
    .filter((line) => /cannot|error|failed|not found|unavailable|active|拒绝|失败/i.test(line))
    .slice(-3);
  return useful.length ? useful.join(" · ") : fallback;
}

function waitForLine(handle, fragment, timeoutMs) {
  if (handle.lines.some((line) => line.includes(fragment))) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error(`等待 ${fragment} 超时`)), timeoutMs);
    const onLine = (line) => { if (line.includes(fragment)) finish(); };
    const onExit = () => finish(new Error(processFailure(handle, `${handle.label} 已提前退出`)));
    const onFailure = (error) => finish(error);
    const finish = (error) => {
      clearTimeout(timeout);
      handle.emitter.off("line", onLine);
      handle.emitter.off("exit", onExit);
      handle.emitter.off("failure", onFailure);
      if (error) reject(error); else resolve();
    };
    handle.emitter.on("line", onLine);
    handle.emitter.once("exit", onExit);
    handle.emitter.once("failure", onFailure);
  });
}

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => {
        if (error) reject(error);
        else if (port === null) reject(new Error("无法分配本机工作台端口"));
        else resolve(port);
      });
    });
  });
}

function workbenchConnected(url) {
  return new Promise((resolve) => {
    const request = http.get(url, { timeout: 800 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        if (body.length < 65_536) body += chunk;
      });
      response.on("end", () => {
        try {
          const state = JSON.parse(body);
          resolve(response.statusCode === 200 && state?.connected === true);
        } catch {
          resolve(false);
        }
      });
    });
    request.on("timeout", () => { request.destroy(); resolve(false); });
    request.on("error", () => resolve(false));
  });
}

async function waitForHttp(url, handle, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (handle.exited) throw new Error(processFailure(handle, "工作台服务已提前退出"));
    if (await workbenchConnected(url)) return;
    await new Promise((resolve) => setTimeout(resolve, 180));
  }
  throw new Error("工作台服务未能连接 monitor");
}

function waitForExit(handle, timeoutMs) {
  if (!handle || handle.exited) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timeout = setTimeout(() => finish(false), timeoutMs);
    const onExit = () => finish(true);
    const finish = (value) => {
      clearTimeout(timeout);
      handle.emitter.off("exit", onExit);
      resolve(value);
    };
    handle.emitter.once("exit", onExit);
  });
}

async function stopHandle(handle, signal, gracefulMs) {
  if (!handle || handle.exited) return;
  try { handle.child.kill(signal); } catch { return; }
  if (await waitForExit(handle, gracefulMs)) return;
  try { handle.child.kill("SIGTERM"); } catch { return; }
  if (await waitForExit(handle, 3_000)) return;
  try { handle.child.kill("SIGKILL"); } catch { /* Process already ended. */ }
  await waitForExit(handle, 1_000);
}

async function stopOwnedSession() {
  const currentWorkbench = workbenchHandle;
  const currentMonitor = monitorHandle;
  workbenchHandle = null;
  monitorHandle = null;
  workbenchUrl = null;
  await stopHandle(currentWorkbench, "SIGTERM", 3_000);
  await stopHandle(currentMonitor, "SIGINT", 18_000);
}

function installRemoteCertificateVerification() {
  remoteBrowserSession = session.fromPartition("lingmou-remote");
  const certificateFingerprint = (certificate) => {
    if (typeof certificate?.data === "string" && certificate.data.trim()) {
      return normalizedFingerprint(new X509Certificate(certificate.data).fingerprint256);
    }
    return normalizedFingerprint(certificate?.fingerprint);
  };

  const certificateMatches = (hostname, certificate) => {
    const trusted = remoteService;
    return Boolean(
      trusted
      && String(hostname || "").toLowerCase() === trusted.hostname
      && certificateFingerprint(certificate) === trusted.fingerprint
    );
  };

  remoteBrowserSession.setCertificateVerifyProc((request, callback) => {
    try {
      const fingerprintMatches = certificateMatches(request.hostname, request.certificate);
      appendLog(
        "certificate",
        `verify host=${String(request.hostname || "unknown")} pinned=${Boolean(remoteService)} match=${fingerprintMatches}`,
      );
      if (fingerprintMatches) {
        callback(0);
        return;
      }
    } catch {
      // Invalid or missing fingerprints fall through to Chromium's normal verifier.
    }
    callback(-3);
  });

  app.on("certificate-error", (event, webContents, url, _error, certificate, callback) => {
    let matches = false;
    let hostname = "unknown";
    try {
      const target = new URL(url);
      hostname = target.hostname;
      matches = Boolean(
        webContents === mainWindow?.webContents
        && target.protocol === "https:"
        && certificateMatches(target.hostname, certificate)
      );
    } catch {
      matches = false;
    }
    appendLog("certificate", `renderer host=${hostname} match=${matches}`);
    if (matches) {
      event.preventDefault();
      callback(true);
      return;
    }
    callback(false);
  });
}

async function setRemoteCookie(origin, token) {
  if (!remoteBrowserSession) throw new Error("远程灵眸会话尚未初始化");
  await remoteBrowserSession.cookies.set({
    url: `${origin}/`,
    name: ACCESS_COOKIE,
    value: token,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "strict",
  });
}

function cleanRemoteRoute(value) {
  if (!value) return "#/overview";
  return /^#\/(?:overview|workbench|harness|syscalls|investigations|policies)(?:\?.*)?$/.test(value)
    ? value
    : "#/overview";
}

async function loadGrantedUrl(window, target) {
  navigationGrants.set(window, target);
  try {
    await window.loadURL(target);
  } finally {
    if (navigationGrants.get(window) === target) navigationGrants.delete(window);
  }
}

async function loadRemoteOrigin(window, origin, fragment = "#/overview") {
  const trusted = remoteService;
  const token = trusted?.credentials.get(origin);
  if (!trusted || !token) throw new Error("该灵眸服务尚未通过 App 校验");
  await setRemoteCookie(origin, token);
  await loadGrantedUrl(window, `${origin}/${cleanRemoteRoute(fragment)}`);
}

async function openRemoteNavigation(window, target) {
  const trusted = remoteService;
  if (!trusted) throw new Error("远程灵眸服务尚未连接");
  const parsed = new URL(target);
  if (parsed.protocol !== "https:" || String(parsed.hostname).toLowerCase() !== trusted.hostname) {
    throw new Error("灵眸 App 拒绝了不同主机的导航");
  }

  let origin = parsed.origin;
  let token = trusted.credentials.get(origin);
  if (parsed.search) {
    const checked = await probeRemoteService(target, trusted.fingerprint, 8_000);
    if (checked.hostname !== trusted.hostname) throw new Error("目标服务不属于当前灵眸主机");
    origin = checked.origin;
    token = checked.token;
    trusted.credentials.set(origin, token);
  } else if (parsed.pathname !== "/" || !token) {
    throw new Error("目标服务不是已校验的灵眸工作台");
  }

  await setRemoteCookie(origin, token);
  await loadGrantedUrl(window, `${origin}/${cleanRemoteRoute(parsed.hash)}`);
}

function handleRemoteNavigationError(window, error) {
  const message = error instanceof Error ? error.message : String(error);
  appendLog("remote-navigation", message);
  void dialog.showMessageBox(window, {
    type: "error",
    title: "无法打开灵眸服务",
    message,
    detail: "请确认目标场景仍在运行，并从统一入口重新进入。",
  });
}

async function validateWorkspace(workspace) {
  const resolved = await fs.promises.realpath(workspace);
  const stat = await fs.promises.stat(resolved);
  if (!stat.isDirectory()) throw new Error("所选路径不是文件夹");
  return resolved;
}

async function startMonitor(workspace) {
  updateLauncher({
    phase: "starting",
    title: "正在启动 Agent 防护",
    message: "加载执行前阻断、文件审计和系统行为证据…",
    detail: "步骤 1 / 3 · 启动本地 monitor",
  });
  const args = [
    "monitor", "-C", workspace,
    "--file-audit", "auto",
    "--os-audit", "auto",
    "--os-audit-profile", "behavior",
    "--security-policy", "enforce",
  ];
  const codex = resolveCodexExecutable();
  if (codex) args.push("--codex-bin", codex);
  monitorHandle = spawnLogged(args, workspace, "monitor");
  await waitForLine(monitorHandle, "CodexScope interactive monitor is ready.", 60_000);
}

async function startWorkbench() {
  updateLauncher({
    phase: "starting",
    title: "防护已就绪",
    message: "正在连接 Agent 工作台和实时安全事件流…",
    detail: "步骤 2 / 3 · 启动本机工作台",
  });
  const port = await reservePort();
  workbenchUrl = `http://127.0.0.1:${port}/`;
  workbenchHandle = spawnLogged(
    ["workbench", "--host", "127.0.0.1", "--port", String(port)],
    PROJECT_ROOT,
    "workbench",
  );
  await waitForHttp(`${workbenchUrl}api/v1/state`, workbenchHandle, 25_000);
}

function configureRendererSecurity(window, allowedOrigin, allowedFileUrl = null) {
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (remoteService) {
      void openRemoteNavigation(window, url).catch((error) => handleRemoteNavigationError(window, error));
    }
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, target) => {
    if (navigationGrants.get(window) === target) {
      navigationGrants.delete(window);
      return;
    }
    try {
      const url = new URL(target);
      if (allowedFileUrl && target === allowedFileUrl) return;
      if (remoteService) {
        const currentUrl = window.webContents.getURL();
        const currentOrigin = currentUrl ? new URL(currentUrl).origin : null;
        const known = remoteService.credentials.has(url.origin);
        if (known && url.origin === currentOrigin && !url.search) return;
        if (
          url.protocol === "https:"
          && String(url.hostname).toLowerCase() === remoteService.hostname
          && (known || url.searchParams.has("access_token"))
        ) {
          event.preventDefault();
          void openRemoteNavigation(window, target)
            .catch((error) => handleRemoteNavigationError(window, error));
          return;
        }
      }
      if (allowedOrigin && url.origin === allowedOrigin) return;
    } catch {
      // Invalid navigation target is denied below.
    }
    event.preventDefault();
  });
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  window.webContents.session.on("will-download", (event) => event.preventDefault());
}

function installApplicationMenu() {
  const navigate = (fragment) => {
    if (mainWindow && !mainWindow.isDestroyed() && workbenchUrl) {
      if (remoteService) {
        let origin = remoteService.mainOrigin;
        try {
          const currentOrigin = new URL(mainWindow.webContents.getURL()).origin;
          if (remoteService.credentials.has(currentOrigin)) origin = currentOrigin;
        } catch {
          // Fall back to the verified main service.
        }
        void loadRemoteOrigin(mainWindow, origin, `#/${fragment}`)
          .catch((error) => handleRemoteNavigationError(mainWindow, error));
      } else {
        void mainWindow.loadURL(`${workbenchUrl}#/${fragment}`);
      }
    }
  };
  const returnToPortal = () => {
    if (mainWindow && !mainWindow.isDestroyed() && remoteService) {
      void loadRemoteOrigin(mainWindow, remoteService.mainOrigin, "#/overview")
        .catch((error) => handleRemoteNavigationError(mainWindow, error));
    }
  };
  const template = [
    {
      label: "灵眸",
      submenu: [
        { label: "Token 压缩与应用接入", accelerator: "CmdOrCtrl+7", click: () => openCompressionWindow() },
        { label: "安全总览", accelerator: "CmdOrCtrl+1", click: () => navigate("overview") },
        { label: "Agent 工作台", accelerator: "CmdOrCtrl+2", click: () => navigate("workbench") },
        { label: "Harness 监控", accelerator: "CmdOrCtrl+3", click: () => navigate("harness") },
        { label: "系统调用", accelerator: "CmdOrCtrl+4", click: () => navigate("syscalls") },
        { label: "调查回放", accelerator: "CmdOrCtrl+5", click: () => navigate("investigations") },
        { label: "策略中心", accelerator: "CmdOrCtrl+6", click: () => navigate("policies") },
        ...(remoteService ? [
          { type: "separator" },
          { label: "返回统一入口", accelerator: "CmdOrCtrl+0", click: returnToPortal },
        ] : []),
        { type: "separator" },
        { label: "退出灵眸", accelerator: "CmdOrCtrl+Q", click: () => app.quit() },
      ],
    },
    {
      label: "视图",
      submenu: [
        { role: "reload", label: "重新载入" },
        { role: "togglefullscreen", label: "切换全屏" },
        ...(!app.isPackaged ? [{ role: "toggleDevTools", label: "开发者工具" }] : []),
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

async function openWorkbenchWindow() {
  const remote = Boolean(remoteService);
  updateLauncher({
    phase: "ready",
    title: remote ? "已连接灵眸服务" : "Agent 防护已开启",
    message: remote ? "服务身份与访问令牌已校验，正在打开安全中心。" : "正在打开灵眸安全中心。",
    detail: remote ? `安全连接 · ${remoteService.mainOrigin}` : "步骤 3 / 3 · 加载安全总览",
  });
  const target = workbenchUrl;
  if (!target) throw new Error("工作台地址不可用");
  const allowedOrigin = new URL(target).origin;
  const window = new BrowserWindow({
    title: "灵眸 Agent 安全中心",
    width: 1440,
    height: 900,
    minWidth: 1120,
    minHeight: 720,
    show: false,
    backgroundColor: "#f2f5f7",
    autoHideMenuBar: false,
    icon: path.join(DESKTOP_ROOT, "assets", "icon.png"),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
      ...(remote ? { session: remoteBrowserSession } : {}),
    },
  });
  configureRendererSecurity(window, allowedOrigin);
  mainWindow = window;
  window.once("ready-to-show", () => {
    if (launcherWindow && !launcherWindow.isDestroyed()) launcherWindow.destroy();
    launcherWindow = null;
    window.show();
  });
  window.on("closed", () => {
    if (mainWindow === window) mainWindow = null;
    if (!shutdownStarted && compressionCompanion?.connected) void stopOwnedSession();
    else if (!shutdownStarted && !compressionWindow) app.quit();
  });
  if (remoteService) {
    await loadRemoteOrigin(window, remoteService.mainOrigin, "#/overview");
  } else {
    await window.loadURL(`${target}#/overview`);
  }
  installApplicationMenu();
}

async function startProtectedWorkspace(workspace) {
  if (process.platform === "win32") return { ok: false, error: "Windows 本地压缩请使用 Token 压缩入口；安全工作台可连接现有灵眸服务。" };
  if (starting) return { ok: false, error: "启动正在进行中" };
  starting = true;
  try {
    const resolved = await validateWorkspace(workspace);
    remoteService = null;
    await stopOwnedSession();
    await startMonitor(resolved);
    await startWorkbench();
    saveLastWorkspace(resolved);
    launcherState.lastWorkspace = resolved;
    await openWorkbenchWindow();
    return { ok: true };
  } catch (error) {
    appendLog("desktop", error?.stack || error);
    await stopOwnedSession();
    const message = error instanceof Error ? error.message : String(error);
    updateLauncher({
      phase: "error",
      title: "未能启动 Agent 防护",
      message,
      detail: "请确认 Codex 已安装并登录，或查看桌面应用日志后重试。",
    });
    return { ok: false, error: message };
  } finally {
    starting = false;
  }
}

async function connectExistingMonitor() {
  if (process.platform === "win32") return { ok: false, error: "Windows 本机 Unix monitor 尚未适配，请连接现有灵眸服务。" };
  if (starting) return { ok: false, error: "启动正在进行中" };
  starting = true;
  try {
    remoteService = null;
    await stopHandle(workbenchHandle, "SIGTERM", 3_000);
    workbenchHandle = null;
    updateLauncher({
      phase: "starting",
      title: "正在连接现有监控",
      message: "不会启动或接管另一个 monitor。",
      detail: "正在建立本机工作台连接…",
    });
    await startWorkbench();
    await openWorkbenchWindow();
    return { ok: true };
  } catch (error) {
    await stopHandle(workbenchHandle, "SIGTERM", 2_000);
    workbenchHandle = null;
    const message = error instanceof Error ? error.message : String(error);
    updateLauncher({
      phase: "error",
      title: "没有可连接的监控",
      message,
      detail: "可以选择一个工作区，让桌面应用直接启动完整保护。",
    });
    return { ok: false, error: message };
  } finally {
    starting = false;
  }
}

async function connectRemoteService(serviceUrl, fingerprint) {
  if (starting) return { ok: false, error: "启动正在进行中" };
  starting = true;
  try {
    updateLauncher({
      phase: "starting",
      title: "正在校验灵眸服务",
      message: "先核对私网地址与 TLS 证书，再验证访问令牌。",
      detail: "令牌不会写入设置、日志或页面地址栏",
    });
    const checked = await probeRemoteService(serviceUrl, fingerprint, 10_000);
    await stopOwnedSession();
    remoteService = {
      hostname: checked.hostname,
      fingerprint: checked.fingerprint,
      mainOrigin: checked.origin,
      credentials: new Map([[checked.origin, checked.token]]),
    };
    workbenchUrl = `${checked.origin}/`;
    await setRemoteCookie(checked.origin, checked.token);
    await openWorkbenchWindow();
    return { ok: true };
  } catch (error) {
    remoteService = null;
    workbenchUrl = null;
    const message = error instanceof Error ? error.message : String(error);
    appendLog("remote-service", message);
    updateLauncher({
      phase: "error",
      title: "未能连接灵眸服务",
      message,
      detail: "请复制最新完整登录链接，并核对服务端显示的 SHA-256 证书指纹。",
    });
    return { ok: false, error: message };
  } finally {
    starting = false;
  }
}

function loginItemOptions() {
  // Squirrel's stable stub survives version-directory updates. ZIP builds use
  // their own executable, which the user must keep at the installed location.
  const stub = path.resolve(path.dirname(process.execPath), "..", path.basename(process.execPath));
  return { path: fs.existsSync(stub) ? stub : process.execPath, args: ["--background"] };
}

function compressionEnvironment() {
  const supported = process.platform === "win32" && app.isPackaged;
  let autoStart = false;
  if (supported) autoStart = app.getLoginItemSettings(loginItemOptions()).openAtLogin;
  return { platform: process.platform, packaged: app.isPackaged, autoStartSupported: supported, autoStart };
}

function setCompressionAutoStart(value) {
  if (process.platform !== "win32" || !app.isPackaged) {
    if (value) throw new Error("登录启动仅在打包后的 Windows 应用中提供。");
    return compressionEnvironment();
  }
  app.setLoginItemSettings({ ...loginItemOptions(), openAtLogin: Boolean(value), name: "Lingmou" });
  return compressionEnvironment();
}

function openCompressionWindow() {
  if (compressionWindow && !compressionWindow.isDestroyed()) {
    if (compressionWindow.isMinimized()) compressionWindow.restore();
    compressionWindow.show();
    compressionWindow.focus();
    return;
  }
  const window = new BrowserWindow({
    title: "灵眸 · Token 压缩", width: 1120, height: 820, minWidth: 820, minHeight: 600,
    show: false, backgroundColor: "#f2f6f4", autoHideMenuBar: true,
    icon: path.join(DESKTOP_ROOT, "assets", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "compression-preload.cjs"), contextIsolation: true,
      nodeIntegration: false, sandbox: true, webSecurity: true, devTools: !app.isPackaged,
    },
  });
  compressionWindow = window;
  configureRendererSecurity(window, null, pathToFileURL(COMPRESSION_HTML).href);
  window.once("ready-to-show", () => {
    if (!(process.argv.includes("--background") && compressionCompanion?.connected)) window.show();
  });
  window.on("close", (event) => {
    if (!shutdownStarted && compressionCompanion?.connected) {
      event.preventDefault();
      window.hide();
    }
  });
  window.on("closed", () => {
    if (compressionWindow === window) compressionWindow = null;
    if (!shutdownStarted && !mainWindow && !launcherWindow && !compressionCompanion?.connected) app.quit();
  });
  void window.loadFile(COMPRESSION_HTML);
  installApplicationMenu();
}

function installCompressionTray() {
  const icon = nativeImage.createFromPath(path.join(DESKTOP_ROOT, "assets", "icon.png")).resize({ width: 20, height: 20 });
  tray = new Tray(icon);
  tray.setToolTip("灵眸 · Token 压缩");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "打开 Token 压缩", click: () => openCompressionWindow() },
    { label: "打开安全中心入口", click: () => {
      if (launcherWindow && !launcherWindow.isDestroyed()) launcherWindow.show();
      else createLauncherWindow();
    } },
    { type: "separator" },
    { label: "退出灵眸…", click: () => app.quit() },
  ]));
  tray.on("double-click", () => openCompressionWindow());
  tray.on("click", () => openCompressionWindow());
}

function requireCompressionSender(event) {
  if (!compressionWindow || event.sender !== compressionWindow.webContents
      || event.senderFrame !== compressionWindow.webContents.mainFrame
      || event.senderFrame.url !== pathToFileURL(COMPRESSION_HTML).href) {
    throw new Error("compression IPC refused");
  }
}

function registerCompressionIpc() {
  ipcMain.handle("compression:command", async (event, method, params = {}) => {
    requireCompressionSender(event);
    try {
      if (!["status", "inspect", "connect", "disconnect", "set_mode", "restart", "clear_sources"].includes(method)) {
        throw new Error("不支持的压缩操作。");
      }
      if (!params || typeof params !== "object" || Array.isArray(params) || JSON.stringify(params).length > 8192) {
        throw new Error("参数格式不正确。");
      }
      if (method === "disconnect") {
        const answer = await dialog.showMessageBox(compressionWindow, {
          type: "question", title: "解除 Codex 接入", message: "恢复 Codex 原来的连接？",
          detail: "请先结束任务并关闭 Codex。配置恢复后重新打开 Codex；灵眸仅撤销自己写入的接入字段，原文和用量记录暂时保留。",
          buttons: ["恢复原连接", "取消"], defaultId: 1, cancelId: 1,
        });
        if (answer.response !== 0) return { ok: false, canceled: true };
      }
      if (method === "clear_sources") {
        const answer = await dialog.showMessageBox(compressionWindow, {
          type: "question", message: "清理保留的原文？",
          detail: "请先关闭所有使用这些原文的 Codex 会话。清理后旧 source_id 将无法补读；配置备份和用量记录保留。",
          buttons: ["清理原文", "取消"], defaultId: 1, cancelId: 1,
        });
        if (answer.response !== 0) return { ok: false, canceled: true };
      }
      const result = await compressionCompanion.call(method, params);
      return { ok: true, result, environment: compressionEnvironment() };
    } catch (error) {
      if (method === "status") {
        return { ok: true, result: { ...compressionCompanion.state,
          enabled: compressionCompanion.connected, running: false,
          error: error instanceof Error ? error.message : "压缩后台未连接。" }, environment: compressionEnvironment() };
      }
      return { ok: false, error: error instanceof Error ? error.message : "操作失败，请重试。" };
    }
  });
  ipcMain.handle("compression:environment", (event) => { requireCompressionSender(event); return compressionEnvironment(); });
  ipcMain.handle("compression:auto-start", (event, enabled) => {
    requireCompressionSender(event);
    try { return { ok: true, result: setCompressionAutoStart(enabled === true) }; }
    catch { return { ok: false, error: "未能设置登录启动，请检查 Windows 启动应用设置。" }; }
  });
  ipcMain.handle("compression:choose-config", async (event) => {
    requireCompressionSender(event);
    const result = await dialog.showOpenDialog(compressionWindow, {
      title: "选择 Codex 实际使用的配置文件", buttonLabel: "使用此配置",
      properties: ["openFile"], filters: [{ name: "Codex 配置", extensions: ["toml"] }],
    });
    return result.canceled ? null : result.filePaths[0];
  });
  ipcMain.handle("compression:show-files", async (event) => {
    requireCompressionSender(event);
    fs.mkdirSync(compressionCompanion.root, { recursive: true, mode: 0o700 });
    return shell.openPath(compressionCompanion.root);
  });
  ipcMain.on("compression:security-home", (event) => {
    requireCompressionSender(event);
    if (launcherWindow && !launcherWindow.isDestroyed()) launcherWindow.show();
    else createLauncherWindow();
  });
}

function launcherSenderAllowed(event) {
  try {
    return path.normalize(fileURLToPath(event.senderFrame.url)) === path.normalize(LAUNCHER_HTML);
  } catch {
    return false;
  }
}

function requireLauncherSender(event) {
  if (!launcherSenderAllowed(event)) throw new Error("launcher IPC refused");
}

function registerLauncherIpc() {
  ipcMain.handle("launcher:open-compression", (event) => {
    requireLauncherSender(event);
    openCompressionWindow();
    return { ok: true };
  });
  ipcMain.handle("launcher:get-state", (event) => {
    requireLauncherSender(event);
    return launcherState;
  });
  ipcMain.handle("launcher:choose-and-start", async (event) => {
    requireLauncherSender(event);
    const result = await dialog.showOpenDialog(launcherWindow, {
      title: "选择要保护的 Agent 工作区",
      buttonLabel: "保护此工作区",
      properties: ["openDirectory"],
    });
    if (result.canceled || !result.filePaths[0]) return { ok: false, canceled: true };
    return startProtectedWorkspace(result.filePaths[0]);
  });
  ipcMain.handle("launcher:start-last", async (event) => {
    requireLauncherSender(event);
    if (!launcherState.lastWorkspace) return { ok: false, error: "没有最近使用的工作区" };
    return startProtectedWorkspace(launcherState.lastWorkspace);
  });
  ipcMain.handle("launcher:connect-existing", async (event) => {
    requireLauncherSender(event);
    return connectExistingMonitor();
  });
  ipcMain.handle("launcher:connect-service", async (event, serviceUrl, fingerprint) => {
    requireLauncherSender(event);
    if (typeof serviceUrl !== "string" || serviceUrl.length > 2_048) {
      return { ok: false, error: "请输入有效的灵眸服务登录链接" };
    }
    if (typeof fingerprint !== "string" || fingerprint.length > 160) {
      return { ok: false, error: "请输入有效的 SHA-256 证书指纹" };
    }
    return connectRemoteService(serviceUrl, fingerprint);
  });
  ipcMain.on("launcher:quit", (event) => {
    requireLauncherSender(event);
    app.quit();
  });
}

function createLauncherWindow() {
  const window = new BrowserWindow({
    title: "灵眸 Agent 安全中心",
    width: 860,
    height: 640,
    minWidth: 760,
    minHeight: 560,
    show: false,
    backgroundColor: "#eef3f1",
    autoHideMenuBar: true,
    icon: path.join(DESKTOP_ROOT, "assets", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
    },
  });
  configureRendererSecurity(window, null, LAUNCHER_URL);
  launcherWindow = window;
  window.once("ready-to-show", () => window.show());
  window.on("closed", () => {
    if (launcherWindow === window) launcherWindow = null;
    if (!mainWindow && !compressionWindow && !shutdownStarted && !compressionCompanion?.connected) app.quit();
  });
  void window.loadFile(LAUNCHER_HTML);
}

app.whenReady().then(() => {
  if (!ownsInstance) return;
  const settings = readSettings();
  launcherState = safeLauncherState({ ...launcherState, lastWorkspace: settings.lastWorkspace });
  registerLauncherIpc();
  compressionCompanion = new CompressionCompanion(app, DESKTOP_ROOT);
  compressionCompanion.on("state", (state) => {
    if (compressionWindow && !compressionWindow.isDestroyed()) compressionWindow.webContents.send("compression:state", state);
    if (tray) tray.setToolTip(state.running ? "灵眸 · 压缩服务运行中" : "灵眸 · Token 压缩");
  });
  registerCompressionIpc();
  installCompressionTray();
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  installRemoteCertificateVerification();
  if (process.platform === "win32" || compressionCompanion.connected) openCompressionWindow();
  else createLauncherWindow();
  if (compressionCompanion.connected) {
    void compressionCompanion.start().catch(() => {
      openCompressionWindow();
      compressionWindow?.show();
    });
  }
  const serviceUrl = automaticServiceUrl;
  const fingerprint = automaticServiceFingerprint;
  automaticServiceUrl = null;
  automaticServiceFingerprint = null;
  if (serviceUrl && fingerprint) {
    void connectRemoteService(serviceUrl, fingerprint);
  } else if (serviceUrl || fingerprint) {
    updateLauncher({
      phase: "error",
      title: "自动连接配置不完整",
      message: "服务登录链接与 SHA-256 证书指纹必须同时提供。",
      detail: "也可以在下方手动填写后重新连接。",
    });
  }
  app.on("activate", () => {
    if (process.platform === "win32" || compressionCompanion?.connected) openCompressionWindow();
    else if (!BrowserWindow.getAllWindows().length) createLauncherWindow();
  });
});

app.on("second-instance", () => {
  if (!app.isReady()) return;
  if (process.platform === "win32" || compressionCompanion?.connected) openCompressionWindow();
  else if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); }
  else if (launcherWindow && !launcherWindow.isDestroyed()) { launcherWindow.show(); launcherWindow.focus(); }
  else createLauncherWindow();
});

app.on("before-quit", (event) => {
  if (shutdownComplete || !ownsInstance) return;
  event.preventDefault();
  if (shutdownStarted) return;
  shutdownStarted = true;
  void (async () => {
    try {
      if (compressionCompanion?.connected) {
        const answer = await dialog.showMessageBox({
          type: "question", title: "退出灵眸", message: "恢复 Codex 原连接并退出？",
          detail: "请先结束任务并关闭 Codex。退出会恢复连接配置；再次打开 Codex 后直接使用原模型服务。只想收起窗口时，请选择继续后台运行。",
          buttons: ["恢复连接并退出", "继续后台运行"], defaultId: 1, cancelId: 1,
        });
        if (answer.response !== 0) { shutdownStarted = false; return; }
        await compressionCompanion.call("disconnect");
      }
      await stopOwnedSession();
      if (compressionCompanion?.child) await compressionCompanion.stop();
      if (tray) { tray.destroy(); tray = null; }
      shutdownComplete = true;
      app.quit();
    } catch (error) {
      shutdownStarted = false;
      openCompressionWindow();
      await dialog.showMessageBox(compressionWindow, {
        type: "error", message: "尚未退出，连接仍由灵眸管理", detail: String(error.message || "请检查配置后重试。"),
      });
    }
  })();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin" && !compressionCompanion?.connected) app.quit();
});

process.on("uncaughtException", (error) => {
  appendLog("uncaught", error?.stack || error);
  if (app.isReady()) dialog.showErrorBox("灵眸桌面应用发生错误", error?.message || String(error));
});
