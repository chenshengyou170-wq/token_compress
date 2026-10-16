# 灵眸 Agent 安全中心桌面版

Windows 10/11 x64 下载：[最新 GitHub Release](https://github.com/chenshengyou170-wq/token_compress/releases/latest)。
安装器为 `Lingmou-Setup.exe`，便携版为 `Lingmou-win-x64.zip`。
0.1.2 修复 provider 引用失效与退出恢复问题，升级步骤见 [发行说明](RELEASE_NOTES.md)。
以后推送与 `desktop/package.json` 版本一致的 `lingmou-vX.Y.Z` 标签，会自动在 Windows 上
测试、打包并发布；构建或冻结后端检查失败时不发布安装包。

桌面版把工作台、`codexscope monitor` 和本机工作台服务打包成一个应用。不用再开两个终端：
选好工作区，应用会自动开启文件审计、系统审计和 `enforce` 强制策略，然后进入安全总览。

| 平台 | 提供的功能 | 状态 |
|---|---|---|
| Linux x64（Ubuntu / Debian） | 完整安全工作台 | 已交付 `.deb` 和 ZIP |
| Windows x64 | Token 压缩伴侣：给自己的 Codex 接入压缩和用量统计 | 有未签名测试包，**尚未在真实 Windows 上安装和验收** |
| macOS | — | 未适配 |

## Linux：安装与使用

### 前提

安装包已内置后端，但**不包含 Codex**。先在终端确认 `codex login status` 正常。

### 安装

```bash
sudo apt install ./lingmou-agent-security_0.1.0_amd64.deb
```

或者解压 ZIP，直接运行其中的 `lingmou-agent-security`。

### 使用

1. 打开「灵眸 Agent 安全中心」，选择要保护的工作区；
2. 等待三步启动完成，自动进入「安全总览」；
3. 按需使用各页面：

   | 页面 | 用途 |
   |---|---|
   | Agent 工作台 | 提交任务、处理审批 |
   | Harness | 查看 Agent 内部遥测 |
   | 系统调用 | 查看已降噪的进程、文件、网络行为 |
   | 策略中心 | 查看和编辑 52 条分组策略（43 条通用/业务 + 9 条 WorkBuddy） |

4. 用完后关闭应用，或选择「结束保护并退出」。应用会先关闭工作台，再结束自己启动的 monitor，
   等最终报告生成后退出。

页面的详细用法见[工作台使用说明](../doc/LINGMOU_WORKBENCH.md)。

### 连接已有的服务

**本机已在终端启动了 monitor：** 在启动页选择「连接已在运行的 monitor」。
应用不会接管或结束这个 monitor；同一时刻只能有一个工作台连接它。

**工作台以内网 HTTPS 服务运行：** 在启动页填写两项：

1. 服务打印的完整登录链接，如 `https://192.168.31.108:8766/?access_token=…`；
2. 服务证书的 SHA-256 指纹。在服务端用下面的命令取得，并通过独立可信渠道核对：

   ```bash
   openssl x509 -in /path/to/lingmou.crt -noout -fingerprint -sha256
   ```

应用只接受 localhost 或私网 IP + HTTPS + 明确端口 + 单个访问令牌。它先不带令牌建立 TLS 连接，
核对主机名、有效期和指纹，通过后才发送令牌。令牌只存在 Electron 的内存 Cookie 中，
不写入设置、日志或地址栏。关闭应用不会停止远端服务。WorkBuddy 链接同样逐个校验证书，
菜单中的「返回统一入口」可切回主工作台。

## Windows：Token 压缩伴侣

Windows 版不包含安全工作台的 monitor。它让你继续使用自己的 Codex App / CLI，
由本机代理压缩请求并统计用量。Windows 默认打开这个入口；Linux 的启动页和菜单也能进入。
Windows 上的「安全工作台」入口只能连接已有的远程灵眸服务。

- 测试安装包：`out/windows-x64/`（安装器、便携 ZIP、校验值、测试步骤 `TESTING.txt`）
- 接入步骤、压缩模式和恢复机制：[Windows 压缩伴侣](../doc/WINDOWS_COMPRESSION_COMPANION.md)

**升级或卸载前，先在灵眸中解除 Codex 接入。**

## 开发与打包

### Linux

```bash
# 准备依赖（项目根目录）
uv sync --extra test --extra desktop
npm --prefix web install
npm --prefix desktop install

# 从源码运行
npm --prefix desktop start

# 打包 .deb 和 ZIP（含自包含 Python 后端）
npm --prefix desktop run make
```

产物：

```text
desktop/out/make/deb/x64/lingmou-agent-security_0.1.0_amd64.deb
desktop/out/make/zip/linux/x64/灵眸 Agent 安全中心-linux-x64-0.1.0.zip
```

只重建桌面壳用 `npm --prefix desktop run make:shell`，前提是 `desktop/dist/backend/lingmou-backend` 已存在。

### Windows

在 Windows 11 x64 的 PowerShell 中，从项目根目录运行：

```powershell
.\desktop\scripts\package-windows.ps1
```

- 构建机需预装 x64 Node.js、Python 3.11+ 和 uv；终端用户不需要。
- 脚本会安装锁定依赖、构建前端、准备字体/图标和 tokenizer 词表、冻结 Python 后端，
  生成 Squirrel `Lingmou-Setup.exe` 和 ZIP。它不运行测试，也不调用模型。
- 签名证书通过环境变量 `WINDOWS_CERTIFICATE_FILE` / `WINDOWS_CERTIFICATE_PASSWORD` 提供，不要写进仓库。

### 开发用环境变量

| 变量 | 用途 |
|---|---|
| `LINGMOU_CODEXSCOPE_BIN` | 指定 `codexscope` 可执行文件的绝对路径 |
| `LINGMOU_CODEX_BIN` | 指定 `codex` 可执行文件的绝对路径 |
| `LINGMOU_SERVICE_URL` + `LINGMOU_SERVICE_CERT_SHA256` | 由受保护的启动脚本直接连接现有服务，**必须同时提供**；应用读取后立即从自身环境中移除 |

```text
LINGMOU_SERVICE_URL=https://私网地址:端口/?access_token=本次令牌
LINGMOU_SERVICE_CERT_SHA256=本次服务证书的SHA-256指纹
```

## 进程与安全边界

```text
Electron 主进程
  ├─ lingmou-backend monitor（仅收尾自己启动的）
  ├─ lingmou-backend workbench（随机 loopback 端口）
  └─ 两个受限渲染页面
       ├─ 本地启动页：只能选择目录、开始、连接、退出
       └─ React 工作台：无 Node 或 Electron API
```

- 两个渲染页面都启用 `contextIsolation`、sandbox 和 `webSecurity`，禁用 Node 集成、新窗口、下载和权限申请；
- 启动页使用固定 CSP，只通过窄化的 preload bridge 调用主进程；本机模式的工作台只能导航到启动时分配的 loopback 地址；
- 远程模式只允许已校验的私网灵眸地址；自签名证书按 SHA-256 指纹精确放行，其他证书错误仍由 Chromium 拒绝；
- 内置 Python 后端只包含运行、策略和工作台所需模块，不含多模态或隐藏 Token 调研模块；
- 策略判断发生在真实执行前审批门，界面提示或风险预测不会显示为已阻断；
- 应用日志为 Electron 用户日志目录下的 `lingmou-desktop.log`，凭据按既有规则脱敏。

## 验证

```bash
cd web && npm test && npm run build
cd ../desktop && npm test
cd .. && .venv/bin/pytest -q \
  tests/test_workbench.py \
  tests/test_security_policy.py \
  tests/test_business_policy.py
```

冻结后的后端还需单独验证：运行 `lingmou-backend --help`，再用隔离的运行目录启动 monitor 和 workbench，
检查 `/api/v1/state` 和 `/api/v1/policies`。这只算本地集成验收；真实提交模型任务并验证动作、阻断和 OS 旁证后，
才算真实上游验收。

## 当前限制

- Codex CLI 及其登录不包含在安装包中；
- 本机单用户应用，不支持远程控制台、多用户权限或云端设备管理；
- `enforce` 只能拦截 Codex 发出了真实审批请求的操作；
- Windows 测试包未签名，真实安装与 Codex 链路待实测；macOS 未适配。
