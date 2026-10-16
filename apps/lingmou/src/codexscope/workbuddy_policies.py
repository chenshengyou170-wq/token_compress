"""Display-safe policy metadata for the fixed WorkBuddy action gateway."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


_POLICIES: tuple[dict[str, Any], ...] = (
    {
        "id": "WORK-SOURCE-CHURN-018",
        "name": "资讯重放与反复交易阻断",
        "risk_level": "critical",
        "mode": "deny",
        "action": "本地模拟评分达到 120 时，拒绝新委托并持久暂停策略",
    },
    {
        "id": "WORK-MAIL-001",
        "name": "外部敏感邮件逐次确认",
        "risk_level": "high",
        "mode": "review",
        "action": "投递前展示外部收件人与敏感附件，并等待一次性确认",
    },
    {
        "id": "WORK-MAIL-002",
        "name": "重复邮件投递阻断",
        "risk_level": "critical",
        "mode": "deny",
        "action": "重新读取已投递邮件，在执行器启动前阻止重复发送",
    },
    {
        "id": "WORK-SHARE-003",
        "name": "公开分享最小权限收窄",
        "risk_level": "high",
        "mode": "transform",
        "action": "将公开链接改为指定成员可评论",
    },
    {
        "id": "WORK-MEETING-004",
        "name": "批量改期影响复核",
        "risk_level": "high",
        "mode": "review",
        "action": "强制保留冲突人员原安排，展示外部联系人与通知影响后逐次确认",
    },
    {
        "id": "WORK-EXPENSE-005",
        "name": "重复票据单项拒绝",
        "risk_level": "critical",
        "mode": "transform",
        "action": "仅将重复票据从批准改为拒绝，其余独立条目继续",
    },
    {
        "id": "WORK-APPROVAL-006",
        "name": "批量审批速率复核",
        "risk_level": "high",
        "mode": "review",
        "action": "批量提交前要求一次性人工复核",
    },
    {
        "id": "WORK-PROCURE-007",
        "name": "重复采购阻断",
        "risk_level": "critical",
        "mode": "deny",
        "action": "核对库存与有效采购单，在执行前阻止重复补货",
    },
    {
        "id": "WORK-SPEND-008",
        "name": "累计采购金额控制",
        "risk_level": "high",
        "mode": "review",
        "action": "基于提交时累计金额复核，重复订单直接拒绝",
    },
    {
        "id": "WORK-REPORT-009",
        "name": "日报脱敏与收件群消歧",
        "risk_level": "high",
        "mode": "transform",
        "action": "移除手机号；收件群不唯一时降级为草稿并请求确认",
    },
)


def load_workbuddy_policy_catalog() -> list[dict[str, Any]]:
    return deepcopy(list(_POLICIES))


__all__ = ["load_workbuddy_policy_catalog"]
