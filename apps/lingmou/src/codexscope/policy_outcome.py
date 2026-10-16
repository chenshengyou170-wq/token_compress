"""User-facing outcomes for deterministic Lingmou policy blocks.

Detector reasons are intentionally technical and can contain several precursor
signals.  A final block needs a different contract: say what the Agent tried to
do, confirm what was stopped, and give one safe way to continue.  Keeping this
copy keyed by the actual blocking policy also makes recorded events replay with
the same explanation instead of falling back to one generic message.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

POLICY_BLOCK_OUTCOME_SCHEMA_VERSION = "lingmou.policy-block-outcome.v1"


_BLOCK_OUTCOMES: dict[str, dict[str, str]] = {
    "USER-FILESYSTEM-DENY": {
        "policy_name": "用户禁止访问目录",
        "headline": "已拒绝访问受保护目录",
        "summary": "Agent 已发起文件操作，文件系统拒绝了对用户指定目录的访问。",
        "reason": "目标处于用户禁止访问的目录内，系统调用返回权限错误。",
        "result_summary": "本次文件访问失败；具体路径、系统调用及错误码已记录。",
        "next_step": "请使用已授权的目录继续任务；目录边界只能由用户配置后重启 Agent 更新。",
    },
    "LING-EXFIL-004": {
        "policy_name": "敏感数据外泄",
        "headline": "已阻止敏感数据发送到外部",
        "summary": (
            "Agent 准备把凭据或其他敏感内容发送到工作区外。"
            "灵眸在传输进程启动前拒绝了命令，数据没有通过本次操作外发。"
        ),
        "reason": "待发送内容包含敏感数据，并且命令同时具备外部传输能力。",
        "result_summary": "传输命令未启动，敏感数据没有通过本次操作离开本机。",
        "next_step": "如确需共享，请先移除敏感字段，并使用已登记的接收目标。",
    },
    "LING-DESTRUCT-005": {
        "policy_name": "高破坏性操作",
        "headline": "已阻止不可逆的破坏性操作",
        "summary": (
            "Agent 准备执行可能批量删除文件、破坏磁盘或关闭系统的操作。"
            "这类结果难以恢复，因此灵眸在命令启动前完成了阻断。"
        ),
        "reason": "命令包含高破坏性动作，执行结果可能无法可靠恢复。",
        "result_summary": "命令未启动，目标没有因本次操作发生改变。",
        "next_step": "请先缩小到明确的文件或资源范围，并用只读命令核对影响。",
    },
    "LING-SCAN-007": {
        "policy_name": "网络扫描行为",
        "headline": "已阻止批量网络扫描",
        "summary": (
            "Agent 准备连续探测一组主机或端口，可能越过当前任务的网络边界。"
            "灵眸在扫描进程启动前拒绝了操作。"
        ),
        "reason": "命令具有批量主机或端口探测特征，目标范围没有得到明确授权。",
        "result_summary": "扫描进程未启动，本次操作没有发出探测连接。",
        "next_step": "请把目标收敛到一个已授权的主机和必要端口后再试。",
    },
    "LING-EVASION-016": {
        "policy_name": "审计与安全证据清除",
        "headline": "已阻止删除审计与安全证据",
        "summary": (
            "Agent 准备删除或篡改日志、审计记录或诊断证据。"
            "这会让后续行为无法核对，因此灵眸在执行前保留了现有证据。"
        ),
        "reason": "命令会削弱或清除用于追踪本次运行的安全证据。",
        "result_summary": "清除命令未启动，现有审计与诊断证据仍被保留。",
        "next_step": "如需控制磁盘占用，请改为归档副本，并保留原始审计链。",
    },
    "LING-REMOTEEXEC-017": {
        "policy_name": "下载脚本直连解释器执行",
        "headline": "已阻止下载内容直接执行",
        "summary": (
            "Agent 准备从网络取得脚本并立即交给 Shell 或解释器。"
            "因为执行前无法审阅真实内容，灵眸在下载与执行链启动前拒绝了命令。"
        ),
        "reason": "远程内容未经落盘和审阅就会直接进入解释器。",
        "result_summary": "下载与解释器进程均未启动，远程内容没有被执行。",
        "next_step": "请先下载到文件，核对来源、内容和哈希后再单独执行。",
    },
    "LING-REVSHELL-018": {
        "policy_name": "反向或交互式 Shell 通道",
        "headline": "已阻止建立远程 Shell 通道",
        "summary": (
            "Agent 准备把交互式 Shell 接到远程端点，可能让外部获得命令执行能力。"
            "灵眸在连接和 Shell 进程启动前完成了阻断。"
        ),
        "reason": "命令会把本机 Shell 的输入输出连接到远程端点。",
        "result_summary": "远程连接和 Shell 进程均未启动。",
        "next_step": "请改用有身份认证、命令范围受限且可审计的远程管理方式。",
    },
    "LING-METADATA-019": {
        "policy_name": "云实例元数据凭证访问",
        "headline": "已阻止读取云实例临时凭据",
        "summary": (
            "Agent 准备访问云实例元数据服务，响应可能包含临时身份凭据。"
            "灵眸在请求发出前拒绝了操作，避免凭据进入后续执行链。"
        ),
        "reason": "目标属于云实例元数据地址，可能返回可用于云 API 的临时凭据。",
        "result_summary": "元数据请求未发出，本次操作没有取得云实例凭据。",
        "next_step": "请使用为当前任务明确授权的测试身份或本地模拟数据。",
    },
    "LING-CONTAINER-020": {
        "policy_name": "容器逃逸与宿主控制面访问",
        "headline": "已阻止触达容器外的宿主控制面",
        "summary": (
            "Agent 准备访问 Docker Socket、宿主命名空间或特权设备。"
            "该操作可能把容器内权限扩大到宿主机，因此灵眸在执行前拒绝了命令。"
        ),
        "reason": "命令具备从容器触达宿主控制面或特权资源的能力。",
        "result_summary": "命令未启动，宿主控制面没有因本次操作被访问。",
        "next_step": "请改用权限最小化的容器接口，并明确登记所需的宿主资源。",
    },
    "LING-GIT-021": {
        "policy_name": "Git 工作区或历史破坏",
        "headline": "已阻止破坏 Git 工作区或提交历史",
        "summary": (
            "Agent 准备丢弃未提交修改、清理未跟踪文件或重写提交历史。"
            "为避免代码和历史不可恢复地丢失，灵眸在执行前拒绝了命令。"
        ),
        "reason": "命令会破坏当前 Git 工作区状态或改写已有提交历史。",
        "result_summary": "Git 命令未启动，工作区和提交历史未被本次操作改变。",
        "next_step": "请先查看 git status 和 diff，并为需要保留的内容创建备份或提交。",
    },
    "LING-SECDISABLE-022": {
        "policy_name": "主机安全控制停用",
        "headline": "已阻止停用主机安全控制",
        "summary": (
            "Agent 准备关闭防火墙、审计或其他安全服务。"
            "这会降低后续操作的防护和可见性，因此灵眸在执行前完成了阻断。"
        ),
        "reason": "命令会停用正在提供防护或审计能力的主机安全控制。",
        "result_summary": "停用命令未启动，相关安全控制保持原状态。",
        "next_step": "如为故障排查，请只调整必要规则，并设置明确的恢复步骤。",
    },
    "LING-OBFEXEC-026": {
        "policy_name": "解码与混淆载荷执行",
        "headline": "已阻止解码内容直接进入 Shell",
        "summary": (
            "Agent 准备把 Base64 等解码结果直接通过管道交给 Shell 或动态执行函数。"
            "由于执行前无法核对真实指令，灵眸在解释器启动前拒绝了这条命令。"
        ),
        "reason": "解码结果未经审阅便直接进入解释器，属于高置信度动态执行链。",
        "result_summary": "命令未启动，没有产生由本次操作触发的子进程、文件修改或网络访问。",
        "next_step": "请先把解码结果写入文件并审阅；只解码、不执行的检查不会命中本阻断。",
    },
    "LING-LINEAGE-030": {
        "policy_name": "敏感派生文件跨步骤外发",
        "headline": "已阻止敏感派生文件外发",
        "summary": (
            "Agent 准备上传一个名称普通的文件，但运行血缘显示它由敏感源文件生成。"
            "灵眸在上传进程启动前拒绝了操作，阻止派生内容绕过文件名检查。"
        ),
        "reason": "待上传文件可追溯到敏感源文件，跨步骤变换没有消除其敏感性。",
        "result_summary": "上传进程未启动，派生内容没有通过本次操作外发。",
        "next_step": "请回到源数据完成脱敏，并重新生成可共享的派生文件。",
    },
    "PAY-EXFIL-004": {
        "policy_name": "支付密钥外泄阻断",
        "headline": "已阻止支付密钥外发",
        "summary": (
            "Agent 准备读取支付密钥，并通过同一条命令把内容发送到外部目标。"
            "灵眸在传输进程启动前拒绝了操作。"
        ),
        "reason": "同一待执行命令同时命中支付密钥资产和外部上传通道。",
        "result_summary": "传输命令未启动，支付密钥没有通过本次操作离开本机。",
        "next_step": "请改为发送不含密钥的诊断摘要，或使用专门的密钥管理流程。",
    },
    "LIFE-ORDER-002": {
        "policy_name": "重复下单保护",
        "headline": "已阻止超出授权数量的重复下单",
        "summary": (
            "Agent 准备再次提交相同订单，预计数量已经超过用户明确授权。"
            "灵眸在新订单和下一笔扣款产生前拒绝了操作。"
        ),
        "reason": "相同商家、商品、金额和地址的订单数量将超过用户授权。",
        "result_summary": "没有生成新的模拟订单，也没有产生下一笔模拟扣款。",
        "next_step": "请先核对现有订单状态，再由用户明确决定是否追加一单。",
    },
    "WORK-MAIL-002": {
        "policy_name": "重复邮件投递阻断",
        "headline": "已阻止重复发送同一封邮件",
        "summary": (
            "相同收件人、主题和附件的邮件已经在业务沙箱中投递。"
            "灵眸在第二个发送执行器启动前拒绝了重试，避免收件人重复收到邮件。"
        ),
        "reason": "提交时重新读取到一封内容与目标均相同的已投递邮件。",
        "result_summary": "第二个发送执行器未启动，已投递邮件保持一封。",
        "next_step": "请用 action_status 核对首封状态；不要仅因回执超时再次发送。",
    },
    "WORK-PROCURE-007": {
        "policy_name": "重复采购阻断",
        "headline": "已阻止创建重复采购单",
        "summary": (
            "库存已经达到目标数量，或相同物料已有一张有效采购单。"
            "灵眸在第二个采购执行器启动前拒绝了重试，避免重复补货和再次计费。"
        ),
        "reason": "提交时重新读取到目标库存已满足或同物料有效采购单已存在。",
        "result_summary": "第二个采购执行器未启动，库存和有效采购单数量没有再次增加。",
        "next_step": "请查询库存与首张采购单状态；确需追加时先取得新的明确授权。",
    },
}

# The directory guard is configured per workspace, outside the default catalog.
BLOCK_OUTCOME_POLICY_IDS = frozenset(k for k in _BLOCK_OUTCOMES if k != "USER-FILESYSTEM-DENY")


def _amount_label(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "未知金额"
    amount = float(value)
    return f"{amount:.2f}".rstrip("0").rstrip(".")


def policy_block_outcome(
    policy_id: object,
    *,
    policy_name: object = None,
    business_summary: object = None,
    business_impact: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Return stable, display-safe copy for one actual blocking policy."""

    normalized_id = str(policy_id or "UNKNOWN-POLICY")[:128]
    profile = dict(_BLOCK_OUTCOMES.get(normalized_id, {}))
    normalized_name = str(
        policy_name or profile.get("policy_name") or normalized_id
    )[:160]
    if not profile:
        profile = {
            "headline": f"已按「{normalized_name}」阻止操作",
            "summary": (
                f"这条命令命中「{normalized_name}」，灵眸在进程启动前拒绝了执行。"
                "本次命令没有进入运行阶段。"
            ),
            "reason": f"「{normalized_name}」作出了执行前拒绝决定。",
            "result_summary": "命令未启动，没有产生由本次操作触发的进程级副作用。",
            "next_step": "请查看策略证据，缩小操作范围或改用可审阅的安全步骤后再试。",
        }

    if normalized_id == "LIFE-ORDER-002":
        impact = business_impact if isinstance(business_impact, Mapping) else {}
        projected = impact.get("projected_order_count")
        amount = impact.get("amount_per_order_yuan")
        if isinstance(projected, int) and not isinstance(projected, bool):
            profile["headline"] = (
                f"已阻止第 {projected} 次下单：避免再扣 ¥{_amount_label(amount)}"
            )
        if str(business_summary or "").strip():
            profile["summary"] = str(business_summary).strip()[:600]

    return {
        "schema_version": POLICY_BLOCK_OUTCOME_SCHEMA_VERSION,
        "policy_id": normalized_id,
        "policy_name": normalized_name,
        "headline": profile["headline"],
        "summary": profile["summary"],
        "reason": profile["reason"],
        "result_summary": profile["result_summary"],
        "next_step": profile["next_step"],
    }


__all__ = [
    "BLOCK_OUTCOME_POLICY_IDS",
    "POLICY_BLOCK_OUTCOME_SCHEMA_VERSION",
    "policy_block_outcome",
]
