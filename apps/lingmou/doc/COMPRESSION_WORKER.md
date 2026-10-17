# Windows 调用另一台主机的压缩模型

0.1.8 增加可选压缩服务。Windows 仍负责 Codex 连接、用量界面和原文补读；模型在另一台主机上常驻。
两端仅监听回环地址，通过 SSH 反向转发连接。Windows 发送请求正文，不发送上游 Authorization 头。

## 当前验证状态

- 代码已实现：压缩服务、Windows 客户端、原文哈希校验与同步、逐方法结果、缓存及额外调用用量。
- 本地测试：鉴权、原文同步失败时保留原请求、语义拒绝、缓存复用和桌面开关边界已覆盖。
- 真实模型预检：LLMLingua-2、Caveman NLP、Headroom、Kimi 与 Jev 已实际调用。
- 一个论文摘要样本没有有效缩减：三个候选未通过语义核对，额外服务用量合计 4,541 token，耗时约 20.4 秒。不同服务的 token 不能直接换算为同价费用。
- Windows 已验证 SSH 通道及服务状态查询；0.1.8 界面程序被测试机的应用控制策略阻止，错误码 `0x800711C7`。本版本尚未完成新 PPT 会话的真实 GUI 验收。
- 用户随后要求归档代码并清理测试机，本轮 PPT 测试不再继续。

这些记录不能解释为所有模型同时开启就会提高收益。

## 模型主机

从产品目录安装 `compression-full` 依赖，提前下载模型，并在服务进程环境中配置：

```text
KIMI_API_KEY 或 KIMI_API_KEY_FILE
TYPESAFE_API_KEY
LINGMOU_LLMLINGUA_MODEL
LINGMOU_CAVEMAN_PATH
LINGMOU_MLM_MODEL
LINGMOU_SPACY_MODEL
```

`LINGMOU_CAVEMAN_PATH` 指向 Caveman 参考实现；模型路径指向本地权重及 spaCy 模型。
配置文件保存在仓库外的私有目录，文件权限应仅允许当前用户读取。示例字段如下，示例令牌必须换成随机值：

```json
{
  "token": "REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS",
  "namespace": "my-windows-desktop",
  "state_dir": "/private/lingmou-worker/runtime",
  "port": 47831,
  "preload": true
}
```

```bash
.venv/bin/python -m codexscope.compression_worker --config /private/lingmou-worker/worker.json
ssh -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
  -R 127.0.0.1:47831:127.0.0.1:47831 administrator@WINDOWS_HOST
```

`GET /status` 和 `POST /compress` 均需要服务专用 Bearer 令牌。日志仅记录计数、来源哈希和阶段结果；
原文单独存入私有 `sources/`，默认配额 64 MiB。模型服务不需要 Codex 登录凭据。

## Windows 配置

在 `%APPDATA%\灵眸 Agent 安全中心\compression\worker.json` 写入：

```json
{
  "url": "http://127.0.0.1:47831",
  "token": "SAME_PRIVATE_TOKEN_AS_THE_WORKER",
  "namespace": "my-windows-desktop"
}
```

重启压缩后台，选择完整压缩并启用远程改写。只有当前请求声明了本连接的原文补读工具才会调用压缩服务。
Windows 在转发压缩请求前校验并保存服务返回的原文。连接失败或原文保存失败时保留原请求；已知的压缩服务消耗仍单独记录。

## 处理方式和限制

先执行整轮历史、旧工具输出归档、结构压缩、技能说明与原文选段，再比较适用的改写候选。
每个候选从同一原文产生，不把多个删词模型串联起来继续删词。

每个请求最多处理一个新的 256–1,200 token 文段；本地模型保持常驻。Caveman 规则、LLMLingua-2、
Caveman NLP、Headroom 和 Kimi 参与适用材料的候选生成。Caveman MLM 只处理不超过 400 字符的片段；
本次论文预检因长度限制未运行 MLM。指令与工具描述不交给删词模型；用户任务和可执行字段不改写。

候选先检查保护字面量，再由 Jev 从短到长核对。通过后缓存；已经否决的相同片段也缓存，避免重复付费。
每个服务进程有一次 6,000 token 的估算启动额度，之后以当前请求本地节省量的 25% 限制远程预算；
每请求最多 5 次远程调用、16,000 token 估算预算。预算是保护上限，不是服务商账单保证。

此次修复了两类误拒绝：数字替换破坏内部保护标记，以及删词后字面量与相邻单词粘连。
Kimi 输出预算也计入推理模型需要的余量，避免还未输出完整 JSON 就被截断。

停用时先停止 Codex 任务，解除灵眸接入，再停止 SSH 转发和模型服务。卸载前应先恢复 Codex 连接配置，
之后再删除应用、专用服务令牌和测试原文。
