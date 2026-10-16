"""Deterministic signals for the payment-key leakage showcase."""

from __future__ import annotations

import re
from typing import Any

PAYMENT_POLICY_ID = "codexscope.payment-key-egress.v1"

PAYMENT_POLICY_RULES: tuple[dict[str, str], ...] = (
    {
        "id": "PAY-KEY-001",
        "label": "支付密钥资产",
        "condition": (
            "命令引用 payment/**/secrets、支付凭据文件或已知支付密钥变量"
        ),
        "effect": "track",
    },
    {
        "id": "PAY-ENCODE-002",
        "label": "密钥编码前兆",
        "condition": "支付密钥资产被 base64、openssl enc 或 tar 编码打包",
        "effect": "warn",
    },
    {
        "id": "PAY-EGRESS-003",
        "label": "外部上传通道",
        "condition": "curl、wget、scp、rsync、nc 等命令携带上传语义",
        "effect": "detect",
    },
    {
        "id": "PAY-EXFIL-004",
        "label": "支付密钥外泄阻断",
        "condition": "PAY-KEY-001 与 PAY-EGRESS-003 在同一待执行命令中同时命中",
        "effect": "decline",
    },
)

_PAYMENT_SECRET_PATH = re.compile(
    r"(?:payments?[/\\][^\s'\";&|]*"
    r"(?:\.env|secrets?|credentials?|private[_-]?keys?|api[_-]?keys?)"
    r"[^\s'\";&|]*|secrets?[/\\]\.env\.production\.demo)",
    re.IGNORECASE,
)
_PAYMENT_SECRET_NAME = re.compile(
    r"\b(?:PAYMENT_GATEWAY_SECRET|PAYMENT_WEBHOOK_SECRET|STRIPE_SECRET_KEY|"
    r"ALIPAY_PRIVATE_KEY|WECHAT_PAY_API_V3_KEY)\b",
    re.IGNORECASE,
)
_ENCODING = re.compile(
    r"(?:^|[;&|]\s*|\s)[\"']?(?:base64|openssl\s+(?:enc|base64)|"
    r"tar\s+[^\n]*[cz])\b",
    re.IGNORECASE,
)
_EGRESS_TOOL = re.compile(
    r"(?:^|[;&|]\s*|\s)[\"']?(?:curl|wget|scp|sftp|rsync|nc|ncat|socat)\b",
    re.IGNORECASE,
)
_EXTERNAL_TARGET = re.compile(
    r"(?:https?|ftp)://|(?:[\w.-]+@)?[\w.-]+:(?:/|~)|\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b",
    re.IGNORECASE,
)
_UPLOAD_SEMANTICS = re.compile(
    r"(?:--data(?:-ascii|-binary|-raw|-urlencode)?(?:=|\s+)|"
    r"(?:^|\s)-d(?:=|\s+)|--upload-file(?:=|\s+)|"
    r"(?:^|\s)(?:-F|--form)(?:=|\s+)|--post-file(?:=|\s+)|"
    r"\b(?:scp|sftp|rsync|nc|ncat|socat)\b|<\s*[^\s]+)",
    re.IGNORECASE,
)


def references_payment_secret(text: str) -> bool:
    """Return whether text identifies a protected payment credential."""

    return bool(_PAYMENT_SECRET_PATH.search(text) or _PAYMENT_SECRET_NAME.search(text))


def assess_payment_command(command: str) -> dict[str, Any]:
    """Return explainable payment-leak signals and matching rule IDs."""

    protected = references_payment_secret(command)
    encoding = protected and bool(_ENCODING.search(command))
    egress_tool = bool(_EGRESS_TOOL.search(command))
    upload = bool(_UPLOAD_SEMANTICS.search(command))
    external_target = bool(_EXTERNAL_TARGET.search(command))
    outbound_upload = egress_tool and upload and external_target

    matched_rules: list[str] = []
    if protected:
        matched_rules.append("PAY-KEY-001")
    if encoding:
        matched_rules.append("PAY-ENCODE-002")
    if outbound_upload:
        matched_rules.append("PAY-EGRESS-003")
    if protected and outbound_upload:
        matched_rules.append("PAY-EXFIL-004")

    return {
        "signals": {
            "protected_payment_secret": protected,
            "encoding": encoding,
            "external_egress_tool": egress_tool,
            "external_target": external_target,
            "upload": upload,
            "outbound_upload": outbound_upload,
        },
        "matched_rules": matched_rules,
        "blocking_rule": (
            "PAY-EXFIL-004" if "PAY-EXFIL-004" in matched_rules else None
        ),
    }


__all__ = [
    "PAYMENT_POLICY_ID",
    "PAYMENT_POLICY_RULES",
    "assess_payment_command",
    "references_payment_secret",
]
