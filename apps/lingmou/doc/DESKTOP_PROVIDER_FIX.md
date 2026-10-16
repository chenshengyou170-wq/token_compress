# 桌面端 provider 生命周期修复 · 0.1.2

修复代码位于 `desktop_connection.py`、`desktop_companion.py` 与 `request_token_tap.py`。
新连接不再创建随机 provider。内置 `openai` 使用 `openai_base_url`，自定义供应商保留原名称和鉴权；
连接恢复只撤销所拥有的字段。后台收到父进程 EOF 时尝试恢复配置再退出。

旧连接的 `connection.json`、`original.toml`、`applied.toml` 可用时，升级会恢复默认连接，
并把旧随机 provider 保留为原供应商的直连兼容项。旧版本已删除该条目时也可恢复该兼容项，
同时保留用户当前的默认供应商。恢复中断后可重复执行；会话文件和线程数据库保持原样。
没有备份时不猜测其原鉴权。历史兼容项不是仍在运行的代理，不应在仍有线程引用时删除。

内置 provider 无法通过 `[model_providers.openai]` 覆盖，因此本机路由凭证放在随机路径中，
并在转发前去除。Authorization 与账户头不作替换。代理返回 426，使 Codex 的 WebSocket
连接回退为 HTTP/SSE。配置与本机 URL 应按敏感材料保存。

## 本地验证（2026-10-16）

- 47 项 Python 回归通过：配置往返、原名称和鉴权保留、无关编辑、冲突保护、重复接入拒绝、
  旧版升级、恢复中断、遗留锁文件、凭证转发、协议回退与父进程 EOF。
- 前端 47 项测试、桌面 Node 测试、前端生产构建通过。
- Codex CLI 0.162.1 对本机模拟上游：接入时创建线程，rollout 元数据保存 `openai`；
  解除接入后恢复同一线程成功。两次请求均使用模拟 API key，且上游未收到灵眸凭证。
  可用 `.venv/bin/python desktop/scripts/check-codex-routing.py` 重现；Windows 使用
  `.venv/Scripts/python.exe`。此检查没有使用真实账号或调用真实模型。
- GitHub Windows 原生构建、冻结后端检查与下载产物以对应 Actions / Release 的实际结果为准。
  真实 ChatGPT 桌面交互及真实 ChatGPT 上游不属于上述通过结果。

官方依据：[内置 provider URL 配置](https://learn.chatgpt.com/docs/config-file/config-advanced#azure-provider-and-per-provider-tuning)、
[自定义 provider 鉴权](https://learn.chatgpt.com/docs/auth#alternative-model-providers)。
自定义 provider 可以通过 `requires_openai_auth = true` 使用 OpenAI 登录，不能笼统地说只有内置 provider 会携带凭证。

GitHub 分发源位于 `chenshengyou170-wq/token_compress` 的 `apps/lingmou/`，与根目录原有压缩模块分别维护。
推送版本一致的 `lingmou-vX.Y.Z` 标签后，工作流先验证 Windows 安装产物，再发布 Release。
稳定入口：[最新版本](https://github.com/chenshengyou170-wq/token_compress/releases/latest)。
