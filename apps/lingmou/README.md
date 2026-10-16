# 灵眸 Windows 桌面端

[下载最新版本](https://github.com/chenshengyou170-wq/token_compress/releases/latest) · [升级说明](desktop/RELEASE_NOTES.md)

下载 `Lingmou-Setup.exe` 安装，或解压 `Lingmou-win-x64.zip` 使用便携版。支持 Windows 10/11 x64，
内置 Python 后端和 Electron；需要用户自己的 Codex 安装及登录。本包未签名。

灵眸在本机接入 Codex 模型请求，提供输入压缩、原文补读和用量展示。
0.1.5 修复补读工具被延迟加载或工具名过长，导致完整压缩一直回退的问题；保留 0.1.3 的压缩节省明细。
0.1.2 保持线程原来的 provider 身份，修复退出后无法恢复线程的问题；旧版本连接通过恢复记录保留直连兼容项。
升级前结束任务并关闭 Codex，在旧版灵眸中解除接入并退出；安装新版后重新接入，再打开 Codex。

本目录是灵眸产品的独立发行源码，与仓库根目录的压缩模块分别维护。未纳入独立多模态/隐藏 Token 调研、
历史运行日志或用户配置。`src/codexscope` 保留产品公共运行依赖；Windows 本地入口使用压缩伴侣，
不提供 Linux monitor 的系统审计功能。用户已修复的线程无需再修改。

## 构建与发布

在此目录安装 Node.js 24、Python 3.13 和 uv 后运行：

```powershell
uv sync --locked --extra desktop --extra test
npm ci --prefix web
npm ci --prefix desktop
.venv/Scripts/python.exe -m pytest tests -q
npm --prefix desktop test
npm --prefix web test
npm --prefix desktop run make:windows
.venv/Scripts/python.exe desktop/scripts/check-companion.py desktop/dist/backend/lingmou-backend/lingmou-backend.exe
.venv/Scripts/python.exe desktop/scripts/collect-release.py
```

更新 `desktop/package.json`、`desktop/package-lock.json` 的版本和 `desktop/RELEASE_NOTES.md` 后提交，
推送对应的 `lingmou-vX.Y.Z` 标签。GitHub Actions 会先在 Windows 上测试、构建、验证冻结后端，
全部通过才发布安装器、ZIP、SHA-256 和构建清单。主分支更新也会构建检查，但不创建 Release。
固定下载地址始终指向最新的已发布版本：

- [安装器](https://github.com/chenshengyou170-wq/token_compress/releases/latest/download/Lingmou-Setup.exe)
- [便携 ZIP](https://github.com/chenshengyou170-wq/token_compress/releases/latest/download/Lingmou-win-x64.zip)

自动检查使用隔离配置和本机模拟上游，包含实际 Codex CLI 的补读工具声明及线程恢复验证。
真实 Windows 材料问答对照曾测得官方输入减少 26.7%、答案正确；该单例不代表所有编程任务的收益，
也不等于完成整个桌面交互验收。详见[对照记录](evidence/windows_compression_live_20261016/validation.json)。
配置、旧版本恢复及使用边界见 [Windows 接入说明](doc/WINDOWS_COMPRESSION_COMPANION.md)。
