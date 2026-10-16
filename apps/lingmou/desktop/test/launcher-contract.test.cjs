const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");

test("launcher renderer stays behind a narrow context bridge", () => {
  const preload = fs.readFileSync(path.join(root, "src", "preload.cjs"), "utf8");
  const html = fs.readFileSync(path.join(root, "ui", "index.html"), "utf8");
  assert.match(preload, /contextBridge\.exposeInMainWorld/);
  assert.doesNotMatch(preload, /exposeInMainWorld\([^)]*ipcRenderer/);
  assert.match(html, /Content-Security-Policy/);
  assert.doesNotMatch(html, /<script[^>]+https?:/);
  assert.match(preload, /connectService/);
  assert.match(html, /type="password"/);
  assert.match(html, /证书 SHA-256 指纹/);
});

test("desktop process starts enforce mode with local audits", () => {
  const main = fs.readFileSync(path.join(root, "src", "main.cjs"), "utf8");
  assert.match(main, /"--file-audit", "auto"/);
  assert.match(main, /"--os-audit", "auto"/);
  assert.match(main, /"--os-audit-profile", "behavior"/);
  assert.match(main, /"--security-policy", "enforce"/);
  assert.match(main, /\.local", "bin", binaryName/);
  assert.match(main, /state\?\.connected === true/);
  assert.match(main, /nodeIntegration: false/);
  assert.match(main, /contextIsolation: true/);
  assert.match(main, /sandbox: true/);
  assert.match(main, /setCertificateVerifyProc/);
  assert.match(main, /fromPartition\("lingmou-remote"\)/);
  assert.doesNotMatch(main, /fromPartition\("persist:lingmou-remote"\)/);
  assert.match(main, /X509Certificate/);
  assert.match(main, /certificate-error/);
  assert.match(main, /probeRemoteService/);
  assert.match(main, /httpOnly: true/);
  assert.match(main, /Harness 监控/);
});
