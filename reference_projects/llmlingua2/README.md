# LLMLingua-2 接入与模型记录

本目录保存已使用模型的说明和[历史环境记录](environment.json)。本集合中的实际适配代码是
[llmlingua_compression.py](../../lingmou_compression/src/codexscope/llmlingua_compression.py)，
依赖 `llmlingua>=0.2.2,<0.3`；这里不冒充完整上游 Git 仓库。

历史实验使用：

- 模型：`microsoft/llmlingua-2-xlm-roberta-large-meetingbank`。
- revision：`ebaba9b0e874dadd3003ffcff828e4397e568089`。
- CPU，默认保留率 `0.6`，本地加载，`trust_remote_code=False`。
- 已有模型位置：`/home/abc/.cache/huggingface/hub/models--microsoft--llmlingua-2-xlm-roberta-large-meetingbank/snapshots/ebaba9b0e874dadd3003ffcff828e4397e568089`。

权重保留在原缓存，没有复制进项目目录。2026-10-10 盘点时，灵眸当前 `.venv` 未安装 `llmlingua`；
历史真实模型推理记录仍保留在 [v2 证据](../../lingmou_compression/evidence/context_compression_v2_20261009/REPORT.md)。
本次整理的本地测试只核对适配器保护、坏结果回退等逻辑，不重新执行模型推理。

在独立代码包环境中按需安装 `.[compression]`，再指定 `LINGMOU_LLMLINGUA_MODEL` 为已有模型目录。
程序不会自动下载权重。代码、数字、字面量和识别到的条件先用保护标记遮蔽；标记校验失败或没有预计收益时回退原文。

来源标识：Microsoft LLMLingua；上游地址 `https://github.com/microsoft/LLMLingua`。
