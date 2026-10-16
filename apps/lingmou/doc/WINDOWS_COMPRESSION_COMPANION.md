# Windows 桌面端：接入用户自己的 Codex

## 0.1.5 补读工具兼容性修复

新版接入流程将灵眸来源工具的 namespace 加入
`features.code_mode.direct_only_tool_namespaces`，使 code mode 下的实际请求仍直接声明补读工具。
来源服务名也已缩短，完整 MCP 工具名不超过 64 字符，兼容旧版 Codex 的工具命名限制。
原有开关、其他直接调用工具及无关配置修改均保留，解除接入时恢复受管理字段。

从旧版升级时，先结束任务并关闭 Codex，在旧版灵眸中解除接入并退出；安装 0.1.5 后
重新接入，再打开 Codex。旧连接不会自动更换来源服务名，需要重新接入应用完整修复。
安装器与便携版见 [0.1.5 Release](https://github.com/chenshengyou170-wq/token_compress/releases/tag/lingmou-v0.1.5)。

## 2026-10-16 真实 Windows 压缩兼容性验证

在已安装的灵眸 0.1.3 与 Codex App 自带的 `0.162.0-alpha.17.2` 上确认：
原有 90 次请求全部未缩减。新版 Codex 将来源 MCP 工具延迟加载，代理在请求的工具定义中
看不到补读工具，因而从完整压缩回退到结构压缩；MCP 服务本身能正常返回原文。

将当前来源 namespace 加入 `features.code_mode.direct_only_tool_namespaces` 后，
真实上游对照问题的官方输入由 22,202 降至 16,268 token（减少 26.7%），两次答案均正确。
保存兼容配置后，不带临时命令行参数再次验证成功。本例是 29,906 字节的受控参考材料问答，
不能推导所有编程任务的节省比例。SSH 下的 PowerShell 读取测试未成功，不算完整编码任务验收。

源码的新接入已固定补读工具可见性，并缩短来源服务名，避免旧 Codex 将超过 64 字符的工具名
替换为哈希。配置恢复会保留原有 code mode 偏好和其他 namespace。源码回归 36 项通过，
Linux Codex 0.162.1 的模拟上游接入、补读工具声明和解除接入后恢复线程均通过。

上述排障测试使用 0.1.3，通过保存兼容配置修复当时的连接；0.1.5 已将该设置加入新接入流程。
已打开的 Codex 需要在任务结束后重新启动以加载配置。旧请求仍在累计中，应同时查看最近请求。
详细数字和测试边界见 [验证记录](../evidence/windows_compression_live_20261016/validation.json)。

## 0.1.2 配置恢复修复

下载与升级说明见 [桌面版发行说明](../desktop/RELEASE_NOTES.md)。新连接保留原 provider 身份：
内置 `openai` 通过 `openai_base_url` 设置本地路由；自定义 provider 只修改原条目的路由字段，
保留其鉴权。解除接入后，线程保存的 provider 名称仍有效。

旧版连接（包括已被旧版解除的连接）有恢复记录和配置备份时，新版会保留对应 provider 的直连
兼容项，使旧线程可以恢复。内置 OpenAI 的兼容项显式启用 OpenAI 鉴权；自定义供应商复用备份中的
鉴权设置。不读取登录文件，不修改 rollout 或线程数据库，也不凭 `openai_http` 之类的名字删除用户配置。

内置 OpenAI 的本地连接凭证放在 loopback 路径中，转发前移除；原有 Authorization 和账户头保持不变。
本地 URL 和配置备份应按敏感文件保管。WebSocket 握手返回 Codex 识别的 426，随后使用 HTTP/SSE。
需要使用支持 `openai_base_url` 的 Codex 版本。

后台收到父进程 EOF 时先恢复配置再退出。若整个后台被强制终止，仍需重启灵眸读取恢复记录。
锁文件由操作系统锁定，进程死亡后锁自动释放；残留文件本身不是锁，不能靠删除正在使用的锁文件
恢复连接，否则可能破坏并发互斥。

以下内容保留最初 0.1.0 构建与验收记录，其测试状态不是 0.1.2 的结果。

> **初版 0.1.0 历史记录：** 已生成未签名的 Windows x64 测试包，并在 Wine 中检查过后端能启动。
> **尚未**在真实 Windows 上安装、操作界面，也未经过真实 Codex 请求验证。详见文末[验证状态](#验证状态)。

## 它做什么

你照常使用 Codex Windows App 或 CLI。灵眸在本机启动一个代理，Codex 的模型请求经过它时被压缩，
同时统计 Token 用量：

```text
Codex App / CLI → 127.0.0.1 上的灵眸代理 → 原模型服务
                        ├─ 输入压缩与用量统计
                        └─ 原文库 ← Codex 通过 MCP 工具补读原文
```

须知：

- 这不是系统级 HTTPS 截获，只对灵眸改写过的那份 Codex 配置生效。App 和 CLI 可以共用这个连接，多个会话的用量合并展示；不同请求之间不共享压缩缓存（前缀、差量、候选）。
- 通过其他 profile、命令行参数或组织托管策略指定的 provider，**不一定**经过代理。
- 只有收到实际请求后才显示「已收到请求」；仅保存配置时显示「已配置 · 等待请求」。

## 安装

测试包位于 `desktop/out/windows-x64/`：

| 文件 | 用途 |
|---|---|
| [`Lingmou-0.1.0-win-x64-Setup.exe`](../desktop/out/windows-x64/Lingmou-0.1.0-win-x64-Setup.exe) | 安装器 |
| [`Lingmou-0.1.0-win-x64-portable.zip`](../desktop/out/windows-x64/Lingmou-0.1.0-win-x64-portable.zip) | 便携版，解压后运行 `Lingmou-win-x64\lingmou-agent-security.exe` |
| [`SHA256SUMS.txt`](../desktop/out/windows-x64/SHA256SUMS.txt) | 校验下载文件 |
| [`TESTING.txt`](../desktop/out/windows-x64/TESTING.txt) | 给测试者的简明步骤 |

推荐 Windows 11 x64。安装包已内含 Python 后端和依赖，无需另装 Python 或 Node.js，
但需要你自己安装并登录 Codex。测试包未签名，Windows 可能提示「未知发布者」。

## 接入 Codex

1. **先结束任务并关闭 Codex。**
2. 打开灵眸的「Token 压缩与应用接入」页（Windows 默认就是这一页）。
3. 读取 Codex 配置。默认是 `%USERPROFILE%\.codex\config.toml`，设置了 `CODEX_HOME` 时用该目录；
   也可以用文件选择器选择实际使用的 TOML。
4. 选择与 Codex 一致的登录方式：
   - ChatGPT 登录和 OpenAI API 登录使用不同的上游地址，务必与 Codex 实际登录方式一致；
   - 自定义 provider 选「保留现有自定义供应商」，沿用原 URL、鉴权和其他配置。
5. 压缩模式先选「结构压缩」（`structure`），点击「保存配置并接入」。
6. 重新打开 Codex，正常使用。在灵眸中查看接入状态和 Token 用量。

接入后关闭灵眸窗口会收到托盘，代理继续运行。安装版可在设置中开启登录时自启动。

## 解除接入

1. **先结束任务并关闭 Codex。**
2. 在灵眸中点击「解除接入」，恢复原配置。
3. 重新打开 Codex，它才会使用原来的连接。

**升级、移动便携版目录或卸载前，都要先解除接入**，否则 Codex 会保留失效的端口或 MCP 程序路径。

如果灵眸后台意外退出、被结束或系统关机，代理会中断，Codex 请求将无法转发。重新打开灵眸即可，
它会读取恢复记录并尝试使用原端口；也可以选择解除接入。

## 压缩模式

| 模式 | 行为 |
|---|---|
| `off` | 不压缩，只代理和统计用量 |
| `structure` | **推荐。** 仅对工具返回和显式参考材料做可还原的结构压缩 |
| `extract` | 按任务复制原文片段，有损；需要 Codex 请求中带有补读工具 |
| `auto` | 本地结构压缩加选段，有损；不会自动调用收费模型 |

- 系统 / 开发者指令、当前用户任务、工具参数、输出 schema 和未知的多模态内容保持原样；
- 压缩失败或没有收益时，原样转发；
- 选段前会检查请求的工具定义（含 Codex `additional_tools`）里是否有 `lingmou_source_read`，没有就退回结构压缩。
  只在配置里写了 MCP 条目不算具备补读能力；工具能否实际执行仍待客户端验收；
- 此入口**不提供** `full`、远程改写或模型权重下载。

## 压缩与用量页面怎么读

- 接入页直接显示累计节省 Token，点击「查看压缩效果」或侧栏「压缩与用量」进入明细；
- 顶部显示累计节省 Token、输入压缩率、压缩前和实际发送的压缩后输入，以及已统计 / 已缩短的请求次数；
- 节省量是完整请求压缩前后的本地估算之差，压缩率为节省量除以压缩前输入；它不代表官方计费或净费用节省。尚未取得估算显示「—」，已统计但没有缩减显示 0；
- 组件和最近请求均可查看压缩前、压缩后及节省量；组件独立计数，合计可能与完整请求不同，节省为负数表示内容增加；
- 官方输入、输出、总量、缓存命中（缓存属于输入）单独显示，远程改写与校验的额外消耗另列；
- 缺少官方 usage 时只显示已知部分，不用本地估算冒充官方数据，也不报告净节省费用；
- 请求还在进行时，官方用量尚未计入；
- 后台重启后重新累计；解除接入后仍可查看最近保存的记录；
- 不会额外请求 `/responses/input_tokens`。

## 隐私与凭据

- 灵眸**不读取** `auth.json`，也不要求你输入 API Key，登录、令牌更新和鉴权仍由 Codex 负责；
- 代理转发时会在内存中接触请求和鉴权头，但这些内容和后台原始 stderr 不写入桌面日志；
- 普通统计只保存数字、工具名和请求状态。只有选段模式会保存原文，用于补读；
- **原配置备份可能含有你写在 TOML 中的凭据，请当作敏感文件保管。**

## 兼容范围

- 只支持 Responses 类型的 provider，且必须使用 HTTP/SSE。WebSocket 升级请求会被拒绝，并提示改用 HTTP 流式传输；
- 服务端管理上下文的请求按现有引擎规则跳过；
- 不支持其他封闭 App、其他厂商协议或通用系统代理；
- Windows 上没有 Linux 的 `strace` / `inotify` 采集和审批拦截，也不会显示为已支持。需要安全工作台时，
  通过证书校验连接远端灵眸服务。

## 实现细节

### 配置修改与恢复

- 用 TOMLKit 修改配置，保留原有结构和注释；通过系统文件锁和原子替换写入；
- 备份、待应用配置和恢复阶段先写入灵眸用户数据目录，再切换 Codex 配置；
- 只新增这几项：独立命名的 provider、来源 MCP、默认 provider 选择、关闭 HTTP 请求编码压缩。恢复时只撤销这几项：
  - 配置没被改动过：恢复原始字节；
  - 你改了无关字段：保留你的修改；
  - 你改了灵眸添加的字段：停止恢复并说明冲突，不会用旧备份覆盖整个文件；
- 解除接入或重启时要求没有进行中的请求，修改配置期间拒绝新请求；
- 明确退出应用时先恢复原配置再停止后端；恢复失败则保持运行并提示。关窗口只是收到托盘；
- 后台意外退出时自动尝试 3 次恢复，失败后提供重启和解除接入入口。Windows 关机不保证触发正常退出流程，恢复记录会保留到下次启动。

### 原文库

按内容哈希存储，每次接入上限 64 MiB，满了就退回不选段。用户结束相关会话并解除接入后才允许清理；
配置备份和计量快照不随之删除。

### 本机安全

- 代理只监听 `127.0.0.1`，使用随机本地凭证头，检查 Host，拒绝浏览器 Origin 请求；本地凭证在转发前移除；
- 控制接口只走 Electron 与 Python 之间的 stdio，不在 HTTP 上开放配置操作；
- 渲染页面没有 Node 权限，preload 只暴露固定操作，主进程校验窗口、主 frame 和页面来源。

### 代码入口

| 文件 | 职责 |
|---|---|
| `desktop/src/main.cjs` | Windows 默认入口、托盘、单实例、应用生命周期、受限 IPC |
| `desktop/src/compression-companion.cjs` | Python 子进程和 JSONL 控制、有限重启、状态传递 |
| `desktop/src/compression-preload.cjs` | 压缩页面桥接 |
| `desktop/ui/compression.html` / `.css` / `.js` | 应用接入、用量、设置与原文页面 |
| `src/codexscope/desktop_companion.py` | 独立 sidecar、请求压缩和来源工具 |
| `src/codexscope/desktop_connection.py` | TOML 配置、备份、恢复与跨平台文件锁 |
| `src/codexscope/request_token_tap.py` | 复用的代理，新增端口、访问凭证、活动请求与暂停 |
| `desktop/backend_entry.py` | Windows 压缩入口分发，避免加载 Unix monitor |
| `desktop/lingmou-backend.spec` | 打包压缩依赖、MCP 和 tokenizer 数据；Windows 排除 Unix 工作台 |
| `desktop/scripts/package-windows.ps1` | Windows 原生构建入口 |

压缩引擎复用产品已有的 Responses / Chat Completions 实现。原 Linux monitor 和安全工作台路径不变。

## 构建

### 在 Windows 上原生构建（本轮未执行）

需要 Windows 11 x64、x64 Node.js、Python 3.11+ 和 uv。从项目根目录运行：

```powershell
.\desktop\scripts\package-windows.ps1
```

脚本安装锁定的 Python 和 npm 依赖，构建前端，准备字体/图标和公开 tokenizer 词表，再用 PyInstaller 冻结后端、
Electron Forge 生成安装器和 ZIP。词表下载只是构建资源准备，不调用模型，也不下载 LLMLingua 等模型权重。
脚本不运行测试。预期产物：

```text
desktop/out/make/squirrel.windows/x64/Lingmou-Setup.exe
desktop/out/make/zip/win32/x64/
```

签名证书从环境变量 `WINDOWS_CERTIFICATE_FILE` 和 `WINDOWS_CERTIFICATE_PASSWORD` 读取；不提供时生成未签名产物。
PyInstaller 必须在目标操作系统上构建。

### 现有测试包的构建方式

`desktop/out/windows-x64/` 中的测试包是在 Linux Docker 里用 Wine 11 构建的（Windows CPython 3.13.16、
PyInstaller 6.22.1、Electron 43.4.0），完整版本记录见
[`build-manifest.json`](../desktop/out/windows-x64/build-manifest.json)。几处特殊处理：

- Squirrel 的 Mono 工具需要旧文件名 `7z.exe` / `7z.dll`，构建脚本从依赖自带的 x64 文件建立副本；
- 安装器由 `make-windows-installer.cjs` 从已打包目录生成，重试时无需再次下载 Electron；
- 便携 ZIP 使用 ASCII 顶层目录并重写文件名编码，避免跨平台解压时目录名乱码。

源码开发可按 [desktop/README.md](../desktop/README.md) 安装依赖后运行 `npm --prefix desktop start`。
字体许可证位于 `desktop/ui/fonts/IBM-Plex-OFL.txt`。

## 验证状态

| 层次 | 状态 |
|---|---|
| 代码实现 | 界面、连接、压缩、补读、恢复、后台和构建入口已写入 |
| 静态核对 | 源文件阅读、Python AST / JavaScript 语法解析、依赖锁文件整理 |
| 构建检查 | 前端生产构建、Windows 后端冻结、Wine 中冻结入口 `--help`、PE 结构、包内资源与界面源码一致性均已完成 |
| 本地功能测试 | **未运行**（pytest、Node 测试、代理请求、浏览器交互） |
| Windows 安装包 | 未签名安装器和便携 ZIP 已生成，**未在真实 Windows 上验证** |
| 真实上游验收 | **未执行**，未调用模型，未改动本机实际 Codex 配置 |

后续需分别验证：配置往返与冲突保护、后台故障恢复、Windows 安装 / 退出 / 升级、中文路径、
真实 Codex HTTP/SSE 与来源 MCP，以及完整任务的正确性和官方 usage。

## 参考

[Codex Windows 网关配置](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway#configure-the-windows-app) ·
[ChatGPT 登录网关](https://learn.chatgpt.com/docs/enterprise/sign-in-with-chatgpt-through-a-gateway) ·
[Electron Forge Squirrel.Windows](https://www.electronforge.io/config/makers/squirrel.windows) ·
[PyInstaller 平台边界](https://pyinstaller.org/en/stable/operating-mode.html)
