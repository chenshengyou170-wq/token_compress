#!/usr/bin/env python3
"""Render the audited Lingmou compression evidence as tables, without new API calls."""
import csv
import json
import statistics
from pathlib import Path
from compare_prompt_compression import read_object

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/input_compression_20261009'
NAMES = {'gpt-6-astra': 'GPT-6 Astra', 'gpt-5.6-sol': 'GPT-5.6 Sol',
         'kimi-for-coding': 'Kimi K2.8 Preview', 'k3': 'Kimi K3'}
CASES = {'english_api': '英文 API', 'chinese_bank': '中文银行演练', 'synthetic_diagnostics': '合成诊断长文'}
MODES = {'off': '关闭', 'hybrid': '本地规则/结构整理', 'kimi': 'Kimi 改写/结构整理'}


def read(path):
    return json.loads(path.read_text())


def pct(a, b):
    return round(100*(1-b/a), 2) if a else None


def table(headers, rows):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ') if value is not None else '未取得'
    return '\n'.join(['| '+' | '.join(headers)+' |', '| '+' | '.join(['---']*len(headers))+' |'] +
                     ['| '+' | '.join(map(cell, row))+' |' for row in rows])


def main():
    report = read(OUT/'final/results.json')
    rows = report['rows']; groups = report['groups']; aggregates = []
    for model in NAMES:
        for mode in ('hybrid', 'kimi'):
            baselines = [r for r in rows if r['model']==model and r['mode']=='off'
                         and r['case']!='synthetic_diagnostics' and r['status']=='completed']
            variants = [r for r in rows if r['model']==model and r['mode']==mode and r['case']!='synthetic_diagnostics']
            pairs = [(b, next((r for r in variants if r['case']==b['case'] and r['repeat']==b['repeat']
                              and r['status']=='completed'), None)) for b in baselines]
            pairs = [(b,r) for b,r in pairs if r is not None]
            if not pairs: continue
            sums = {key: (sum(b[key] for b,r in pairs), sum(r[key] for b,r in pairs))
                    for key in ('input_tokens','output_tokens','total_tokens','local_after')}
            aggregates.append({'model':model, 'mode':mode, 'paired_n':len(pairs),
                'local_before':sums['local_after'][0], 'local_after':sums['local_after'][1],
                'local_reduction_pct':pct(*sums['local_after']),
                'official_input_before':sums['input_tokens'][0], 'official_input_after':sums['input_tokens'][1],
                'official_input_reduction_pct':pct(*sums['input_tokens']),
                'official_output_before':sums['output_tokens'][0], 'official_output_after':sums['output_tokens'][1],
                'official_total_before':sums['total_tokens'][0], 'official_total_after':sums['total_tokens'][1],
                'official_total_reduction_pct':pct(*sums['total_tokens']),
                'quality_passes':sum(r['quality_passed'] for b,r in pairs),
                'median_latency_s':round(statistics.median(r['latency_s'] for b,r in pairs),2)})
    with (OUT/'aggregate.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(aggregates[0])); w.writeheader(); w.writerows(aggregates)
    (OUT/'aggregate.json').write_text(json.dumps(aggregates,ensure_ascii=False,indent=2)+'\n')
    md=['**灵眸输入压缩：仓库分析、实现与真实上游对照（2026-10-09）**',
        '这是灵眸产品的输入压缩实验，不是独立的多模态/隐藏 Token 调研验收。默认关闭；尚未提交或发布。',
        ('当前英文/中文材料中，没有一组同时达到官方输入减少 30% 且全部答案检查通过。'
         '建议先按任务验证本地 hybrid；Kimi 文本改写仍保留为实验选项，不能作为无损压缩上线。'
         if not any(a['official_input_reduction_pct']>=30 and a['quality_passes']==a['paired_n'] for a in aggregates)
         else '部分材料达到 30%，具体适用范围及质量检查见下表。'),
        '**两个仓库怎样节省 token**',
        'Caveman 对自然语言做简写。LLM 版把自然语言分句调用 GPT-4o-mini，默认还计算原文/改写的 embedding；'
        'NLP 版删除 spaCy 停用词，不能据此保证否定关系；MLM 版按 RoBERTa 的可预测性删词。'
        '源码里的 token 计数主要是字符数除以 4。其事实基准仅 2 篇、13 条事实，报告平均字符缩短 18.6%；'
        'README 的 40–58% 不代表任意真实请求均能达到。'
        '来源：[LLM 源码](https://github.com/wilpel/caveman-compression/blob/2a11efbf74863449e3392322ea0bf8d7ebe55357/caveman_compress.py)、'
        '[NLP 源码](https://github.com/wilpel/caveman-compression/blob/2a11efbf74863449e3392322ea0bf8d7ebe55357/caveman_compress_nlp.py)、'
        '[事实基准](https://github.com/wilpel/caveman-compression/blob/2a11efbf74863449e3392322ea0bf8d7ebe55357/benchmark/factual_preservation/README.md)。',
        '另用 o200k_base 对仓库现成示例重新分词：系统提示词 113→51（54.87%），'
        'API 文档 99→57（42.42%），简历 153→126（17.65%）；三项合计减少 35.89%。'
        '这只是现成文本的本地重计数，没有证明重写质量，也没有计入完整 Agent 请求开销。'
        '记录：[示例重计数](upstream_examples_recount.json)。',
        'GenericAgent 主要减少发送的上下文：压缩旧消息里的标签内容、限制工具结果长度，超阈值后淘汰旧历史，'
        '并用工作快照、key_info 和分层记忆按需恢复信息。默认标签保留最近 10 条，旧标签截取首尾合计约 800 字符；'
        '历史阈值按字符计算，常规目标保留 60%。它的整套 Agent 效率比较同时包含工具、轮数、记忆与调度差异，'
        '不能当成可单独移植的压缩模块效果。'
        '来源：[上下文实现](https://github.com/lsdefine/GenericAgent/blob/f308ee7eb079cc402edf5a934fa65f6d71a4c7ad/llmcore.py)、'
        '[项目评测说明](https://github.com/lsdefine/GenericAgent/blob/f308ee7eb079cc402edf5a934fa65f6d71a4c7ad/README.md#-evaluation)。',
        '**当前接入**',
        '在 RequestTokenTap 转发实际请求前处理文本。hybrid 使用本地简写、保护片段、相同工具结果引用、JSON 空白整理；'
        'kimi 在此基础上调用 Kimi 改写，优先处理任务材料。保护项必须完整且保持顺序，文本和本地估算都变短才采用；'
        '失败时回退原文。保留工具协议对象、代码等受保护材料，没有实现 GenericAgent 的长程历史淘汰与记忆架构。'
        '具体用法见 [README](../../README.md#codex-输入侧压缩实验功能)。',
        '每个请求记录压缩前/后本地估算及该请求返回的官方 usage。GPT 使用已有 ChatGPT 登录的 Codex，'
        '同时核对代理捕获的 SSE usage 与 Codex turn.completed；Kimi 使用官方 Kimi Code Chat Completions。'
        '两类接入的固定提示词开销不同，模型之间的绝对输入数不能直接比较。'
        '本地 o200k_base 替代计数不是 GPT-6/Kimi 官方计数，也不是预计算接口的精确值。',
        '**测试口径**',
        '四个下游模型 × 三个材料 × off/hybrid/kimi × 两次调用，计划 72 次。两次下游调用会复用已接受的 Kimi 改写缓存，'
        '不是两次独立压缩采样；失败改写有 5 分钟退避。英文 8 项、中文 16 项、合成长文 8 项，'
        '不同模型也可能遇到不同缓存/重试状态，所以这里比较的是实际接入流程，不能据此给模型能力排名。'
        '按固定 JSON 值、类型及字段集合检查；通过不等于普遍语义等价。顺序在第二次反转。'
        '本轮所有 LLM 压缩均使用 kimi-for-coding，按要求从节省比例分母和分子中排除；另存 compression_calls。'
        '超时压缩调用可能缺少官方 usage，不能据此计算完整净费用。',
        f'当前已记录 {len(rows)} 次，其中 {sum(r["status"]=="completed" for r in rows)} 次完成，'
        f'{sum(r["status"]!="completed" for r in rows)} 次调用失败。失败的质量检查也保留在表中，不因不通过而剔除。',
        '**英文与中文材料合计：每个模式 4 次下游调用**',
        table(['模型','方案','本地估算前→后','本地降幅','官方 input 前→后','官方 input 降幅','官方 total 降幅','答案通过'],
              [[NAMES[a['model']],MODES[a['mode']],f"{a['local_before']} → {a['local_after']}",f"{a['local_reduction_pct']}%",
                f"{a['official_input_before']} → {a['official_input_after']}",f"{a['official_input_reduction_pct']}%",
                f"{a['official_total_reduction_pct']}%",f"{a['quality_passes']}/{a['paired_n']}"] for a in aggregates]),
        '以上总量含缓存 input；output 包括服务商计入的 reasoning token。total 降幅可能为负，'
        '因为输入变短并不保证输出或推理量变少。不是费用节省比例。',
        '**逐场景结果：合成长文单列**',
        table(['模型','材料','方案','官方平均 input','官方平均 output','本地降幅','官方 input 降幅','通过','耗时中位数/秒'],
              [[NAMES[g['model']],CASES[g['case']],MODES[g['mode']],g['mean_input_tokens'],g['mean_output_tokens'],
                g['local_reduction_pct'],g['input_reduction_pct'],f"{g['quality_passes']}/{g['n']}",g['median_latency_s']] for g in groups]),
    ]
    failures=[]
    for p in sorted((OUT/'final').glob('call.*.json')):
        if p.name.endswith('.transport.json'): continue
        r=read(p)
        if not r.get('quality_passed'):
            problem=', '.join(k for k,v in r.get('checks',{}).items() if not v) or r.get('error_type','额外字段/格式')
            if r.get('response'):
                try: read_object(r['response'])
                except (ValueError, TypeError): problem='未满足固定 JSON 输出格式；各字段未计通过，不等于所有事实都丢失'
            transport=p.with_name(p.stem+'.transport.json')
            if r['status']!='completed' and transport.exists():
                t=read(transport)
                if t.get('observed_request_count')!=1:
                    problem=f"观察到 {t.get('observed_request_count')} 个请求；中断后重试，不满足单请求对照"
            failures.append([NAMES[r['model']],CASES[r['case']],r['repeat'],r['mode'],
                             problem])
    md.extend(['**未通过检查的记录**', table(['模型','材料','重复序号','模式','失败字段/错误'],failures) if failures else '本轮固定检查全部通过。'])
    md.append('GPT-5.6 合成长文的第二次 hybrid 调用发生中断后重试，最终答案正确，但首次请求未返回 usage；'
              '为避免把重试开销漏算为节省，将其排除在单请求配对统计之外。详情见 [异常请求审计](failed_request_audit.json)。')
    dup_file=OUT/'duplicate_tool_history/results.json'
    if dup_file.exists():
        ds=read(dup_file)['records']; dr=[]
        for model in NAMES:
            for repeat in (0,1):
                a=next((r for r in ds if r['model']==model and r['repeat']==repeat and r['mode']=='off'),None)
                b=next((r for r in ds if r['model']==model and r['repeat']==repeat and r['mode']=='hybrid'),None)
                if not a or not b:continue
                au=a.get('usage') or {};bu=b.get('usage') or {}
                al=(a.get('request_usage') or [{}])[0].get('input_tokens_after_estimate')
                bl=(b.get('request_usage') or [{}])[0].get('input_tokens_after_estimate')
                dr.append([NAMES[model],repeat,au.get('input_tokens'),bu.get('input_tokens'),
                           pct(au.get('input_tokens'),bu.get('input_tokens')) if au and bu else None,
                           f'{al} → {bl}' if al and bl else None, pct(al,bl) if al and bl else None,
                           a.get('quality_passed'),b.get('quality_passed')])
        md.extend(['**合成的重复工具历史，单独验证结构整理**',
            '两个完全相同的工具快照，各含 300 行 JSON。仅发送构造的历史消息，没有执行真实工具，也不代表真实长程任务。'
            '此处仅使用本地 hybrid，不调用压缩模型。缺少关闭模式的官方 usage 时，不报告官方节省比例。',
            table(['模型','重复序号','关闭 input','hybrid input','官方降幅/%','本地估算前→后','本地降幅/%','关闭通过','hybrid 通过'],dr)])
        with (OUT/'duplicate_tool_history/comparison.csv').open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.writer(f);w.writerow(['model','repeat','official_before','official_after','official_reduction_pct',
                                       'local_before_after','local_reduction_pct','baseline_quality_passed','compressed_quality_passed']);w.writerows(dr)
    old=read(ROOT/'evidence/token_compression_20261008/comparison/results.json')
    local=read(ROOT/'evidence/codex_input_compression_20261008/final/results.json')
    history=[]
    for case in old['cases']:
        base=case['variants']['original']['usage']['input_tokens']
        for mode in ('prompt_only','prompt_and_context'):
            r=case['variants'][mode]
            history.append([CASES[case['id']], '旧 LLM '+mode,base,r['usage']['input_tokens'],r['input_reduction_percent'],f"{r['passed']}/{r['total']}"])
    for case in local['cases']:
        r=case['variants']['caveman']; history.append([CASES[case['id']], '旧 caveman 全请求本地规则',case['variants']['off']['usage']['input_tokens'],r['usage']['input_tokens'],case['input_reduction_percent'],f"{r['passed']}/{r['total']}"])
    md.extend(['**前一轮实验，保持原口径**',
        '以下均为 2026-10-08 GPT-6 Astra 历史结果，Codex 版本、请求封装和压缩策略与本轮不同；'
        '旧 LLM 实验当时使用 GPT，不能标注成 Kimi 压缩。本轮遵循新要求，LLM 压缩仅使用 Kimi。',
        table(['材料','历史方案','原始 input','压缩 input','降幅/%','检查通过'],history),
        '[旧 LLM 完整证据](../token_compression_20261008/comparison/results.json)；'
        '[旧本地规则证据](../codex_input_compression_20261008/final/results.json)。旧 LLM 压缩开销分别为 16,431 / 20,802 token，'
        '本表同样未扣除此开销。',
        '**如何理解 30% 目标**',
        '输入缩短比例取决于可处理材料占整个请求的比例。Codex 的系统提示词、工具定义和协议开销较大，'
        '只缩短短任务文字难以使整个请求下降 30%。中文业务资料的数字、条件、表格和代码密集，'
        '删去这些内容会破坏事实或边界。LLM 改写还受超时、保护项检查、格式稳定性影响。'
        '重复的大型工具结果更适合结构整理，但其合成测试收益不能推广为日常 Agent 的平均收益。',
        '**验证和边界**',
        read(OUT/'validation.json')['result']+'。另完成真实 GPT-6 工具往返：关闭与 hybrid 均正确调用一次只读 printf 并返回标记；'
        '每种模式实际产生两个上游请求，账本的 input/output/total 之和与 Codex 官方 turn.completed 完全一致。'
        '来源：[工具往返](tool_roundtrip/results.json)。',
        '开发过程的失败保存在 pilot、guarded_pilot、bounded_pilot；bounded_pilot 有一次在途请求因修订策略被中断，'
        '未取得该次官方 usage。GPT-5.4 探测没有完成有效请求，正式 GPT-5 对照采用当前账号可用的 GPT-5.6 Sol。'
        '官方型号参考：[GPT-6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra)、'
        '[GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)、[Kimi Code](https://www.kimi.com/code/docs/en/)。',
        '复查入口：[每次请求 CSV](final/requests.csv)、[分组 CSV](final/summary.csv)、[英文中文合计 CSV](aggregate.csv)、'
        '[结构化结果](final/results.json)、[实现指纹](final/implementation_sha256.json)。原始记录保留官方 usage、'
        '压缩状态、检查明细和所用模型，密钥不在仓库或报告中。',
    ])
    (OUT/'REPORT.md').write_text('\n\n'.join(md)+'\n')
    print(str(OUT/'REPORT.md'))


if __name__=='__main__': main()
