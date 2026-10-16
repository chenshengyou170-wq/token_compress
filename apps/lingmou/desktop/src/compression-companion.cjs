"use strict";

const { spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

class CompressionCompanion extends EventEmitter {
  constructor(app, desktopRoot) {
    super();
    this.app = app;
    this.desktopRoot = desktopRoot;
    this.projectRoot = path.resolve(desktopRoot, "..");
    this.root = path.join(app.getPath("userData"), "compression");
    this.child = null;
    this.starting = null;
    this.pending = new Map();
    this.sequence = 0;
    this.stopping = false;
    this.retries = 0;
    this.retryTimer = null;
    this.needsManualRestart = false;
    this.state = { schema_version: 1, enabled: this.configuredOnDisk(), running: false, error: "", connection: null,
      default_config_path: path.join(process.env.CODEX_HOME || path.join(app.getPath("home"), ".codex"), "config.toml") };
  }

  configuredOnDisk() {
    const target = path.join(this.root, "connection.json");
    try {
      const record = JSON.parse(fs.readFileSync(target, "utf8"));
      return ["prepared", "connected", "restoring"].includes(record.phase);
    } catch {
      // A damaged journal is not permission to abandon an installed route.
      return fs.existsSync(target);
    }
  }

  get connected() { return this.state.enabled || this.configuredOnDisk(); }

  launch() {
    if (this.app.isPackaged) {
      const executable = process.platform === "win32" ? "lingmou-backend.exe" : "lingmou-backend";
      const command = path.join(process.resourcesPath, "lingmou-backend", executable);
      if (!fs.existsSync(command)) throw new Error("安装包缺少压缩后台，请重新安装完整版本。");
      return { command, args: ["compression-companion", "serve", "--state-dir", this.root], env: process.env };
    }
    const command = process.platform === "win32"
      ? path.join(this.projectRoot, ".venv", "Scripts", "python.exe")
      : path.join(this.projectRoot, ".venv", "bin", "python");
    if (!fs.existsSync(command)) throw new Error("缺少项目 Python 环境，请先安装 desktop 可选依赖。");
    return {
      command, args: ["-m", "codexscope.desktop_companion", "serve", "--state-dir", this.root],
      env: { ...process.env, PYTHONPATH: [path.join(this.projectRoot, "src"), process.env.PYTHONPATH].filter(Boolean).join(path.delimiter) },
    };
  }

  publish(state) {
    this.state = state;
    this.emit("state", state);
  }

  async start() {
    if (this.starting) return this.starting;
    if (this.child && this.child.exitCode === null && !this.child.killed) return;
    this.stopping = false;
    this.starting = this.startProcess();
    try { await this.starting; } finally { this.starting = null; }
  }

  async startProcess() {
    const launch = this.launch();
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
    const child = spawn(launch.command, launch.args, {
      cwd: this.app.isPackaged ? this.root : this.projectRoot,
      env: { ...launch.env, PYTHONUNBUFFERED: "1", PYTHONUTF8: "1", NO_COLOR: "1" },
      windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    let readyResolve;
    let readyReject;
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const timer = setTimeout(() => readyReject(new Error("压缩后台启动超时，请检查安装后重试。")), 25000);
    const lines = readline.createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      if (line.length > 2 * 1024 * 1024) return;
      let message;
      try { message = JSON.parse(line); } catch { return; }
      if (message.event === "ready") { clearTimeout(timer); readyResolve(); return; }
      if (message.event === "fatal") { readyReject(new Error(String(message.error || "后台未能启动。"))); return; }
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(String(message.error)));
      else {
        if (message.result?.schema_version === 1) this.publish(message.result);
        pending.resolve(message.result);
      }
    });
    // Library diagnostics can contain source/config snippets. Do not retain or
    // forward raw stdout/stderr to desktop logs or renderers.
    child.stderr.resume();
    child.stdin.on("error", () => {});
    child.on("error", () => readyReject(new Error("无法启动压缩后台，请检查 Python 环境或安装包。")));
    // A failed spawn emits close without exit. Both paths must clear the
    // child handle before a user action or automatic recovery can retry.
    child.once("close", () => {
      clearTimeout(timer);
      lines.close();
      if (this.child === child) this.child = null;
      readyReject(new Error("压缩后台已退出。"));
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("后台连接中断，配置备份已保留。"));
      }
      this.pending.clear();
      if (!this.stopping) {
        this.publish({ ...this.state, enabled: this.configuredOnDisk(), running: false, error: "压缩后台已退出，正在尝试恢复。" });
        if (this.connected && this.retries < 3) {
          const delay = [1000, 3000, 10000][this.retries++];
          this.retryTimer = setTimeout(() => {
            this.retryTimer = null;
            void this.start().catch(() => this.publish({ ...this.state, error: "后台恢复失败。请重启服务，或解除接入恢复原连接。" }));
          }, delay);
        } else {
          this.needsManualRestart = true;
          this.publish({ ...this.state, error: "后台已停止自动恢复。请重启服务或检查安装与配置；接入记录仍然保留。" });
        }
      }
    });
    try {
      await ready;
      await this.send("status");
    } catch (error) {
      clearTimeout(timer);
      if (this.child === child) {
        child.stdin.end();
        const terminate = setTimeout(() => {
          if (this.child === child && child.exitCode === null) child.kill();
        }, 5000);
        terminate.unref();
        child.once("close", () => clearTimeout(terminate));
      }
      throw error;
    }
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const child = this.child;
      if (!child || !child.stdin.writable) { reject(new Error("压缩后台未连接。")); return; }
      const id = ++this.sequence;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("操作仍未返回，请刷新状态后再决定是否重试。"));
      }, 30000);
      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(`${JSON.stringify({ id, method, params })}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error("无法发送后台控制消息。"));
      });
    });
  }

  async call(method, params = {}) {
    if (method === "status" && !this.child && (this.retryTimer || this.needsManualRestart)) return this.state;
    if (method !== "status") {
      this.needsManualRestart = false;
      this.retries = 0;
      if (this.retryTimer) clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    await this.start();
    return this.send(method, params);
  }

  async stop() {
    this.stopping = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    const child = this.child;
    if (!child) return;
    await this.send("shutdown");
    child.stdin.end();
    await new Promise((resolve) => {
      if (child.exitCode !== null) { resolve(); return; }
      const timeout = setTimeout(() => { child.kill(); resolve(); }, 5000);
      child.once("exit", () => { clearTimeout(timeout); resolve(); });
    });
  }
}

module.exports = { CompressionCompanion };
