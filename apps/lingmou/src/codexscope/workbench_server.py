"""HTTP and WebSocket API for the local Lingmou interactive workbench."""

from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .agent_adapter import AgentAdapter
from .atomic_policy import (
    FIELDS,
    OPS,
    PolicyConfigError,
    PolicyConflict,
    config_path,
    default_document,
    effective_rules,
    evaluate,
    load_document,
    save_document,
    validate_document,
)
from .business_policy import load_business_policy_catalog
from .filesystem_guard import guard_status, resolve_denied
from .harness_monitor import HarnessMonitor
from .token_panel import token_panel_snapshot
from .storage import atomic_json_dump
from .investigation import HistoryUnavailable
from .local_policies import load_local_policies
from .payment_security import PAYMENT_POLICY_RULES
from .policy_outcome import policy_block_outcome
from .policy_intent import interpret_policy
from .policy_primitives import meta_catalog
from .redaction import redact_text
from .security_policy import assess_approval_policies
from .syscall_index import MAX_PAGE_SIZE, SyscallIndex, SyscallIndexError
from .workbench_controller import WorkbenchController, WorkbenchError
from .workbench_store import WorkbenchEventStore
from .workbuddy_policies import load_workbuddy_policy_catalog
from .workbuddy_scenarios import scenario_catalog


class TextBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=128_000)
    scenario_id: str | None = Field(
        default=None, min_length=1, max_length=20, pattern=r"^(?:WB|LIFE)-\d{2}$"
    )


class PolicySaveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]
    revision: str = Field(min_length=1, max_length=64)


class PolicyIntentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=4000)


class PolicyActivateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: str = Field(min_length=1, max_length=64)


class PolicyPreviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]
    command: str | None = Field(default=None, min_length=1, max_length=32_000)
    event: Literal["command.approval", "work.action"] = "command.approval"
    facts: dict[str, Any] = Field(default_factory=dict)


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str


class UserInputBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answers: dict[str, list[str]]


_ACCESS_COOKIE = "lingmou_access"


def _block_copy_fields(policy_id: str, policy_name: str, mode: str) -> dict[str, Any]:
    if mode != "deny":
        return {
            "block_headline": None,
            "block_summary": None,
            "safe_next_step": None,
        }
    outcome = policy_block_outcome(policy_id, policy_name=policy_name)
    return {
        "block_headline": outcome["headline"],
        "block_summary": outcome["summary"],
        "safe_next_step": outcome["next_step"],
    }


def _workbench_policy_catalog() -> dict[str, Any]:
    """Return display-safe policy metadata without detector match internals."""

    runtime = [
        {
            "id": policy["id"],
            "name": policy["name"],
            "risk_level": policy["risk_level"],
            "action": policy["action"],
            "mode": policy["mode"],
            "stage": policy["stage"],
            "evidence_source": policy["evidence_source"],
            "enforceable_now": policy["enforceable_now"],
            "stateful": policy["stateful"],
            "tested": policy["tested"],
            "enabled": True,
            **_block_copy_fields(
                str(policy["id"]),
                str(policy["name"]),
                str(policy["mode"]),
            ),
        }
        for policy in load_local_policies()
    ]
    payment_risk = {
        "track": "notice",
        "warn": "warning",
        "detect": "high",
        "block": "critical",
        "decline": "critical",
    }
    payment_action = {
        "track": "持续跟踪关联操作",
        "warn": "告警并跟踪派生内容",
        "detect": "进入执行前审批",
        "block": "执行前阻断并保全证据",
        "decline": "执行前阻断并保全证据",
    }
    payment = [
        {
            "id": rule["id"],
            "name": rule["label"],
            "risk_level": payment_risk.get(rule["effect"], "warning"),
            "action": payment_action.get(rule["effect"], "记录并告警"),
            "mode": (
                "deny"
                if rule["effect"] in {"block", "decline"}
                else "review"
                if rule["effect"] == "detect"
                else "observe"
            ),
            "stage": "pre_execution_approval",
            "evidence_source": "deterministic_command_analysis",
            "enforceable_now": rule["effect"] in {"block", "decline"},
            "stateful": False,
            "tested": "real_upstream" if rule["id"] == "PAY-EXFIL-004" else "local",
            "enabled": True,
            **_block_copy_fields(
                str(rule["id"]),
                str(rule["label"]),
                (
                    "deny"
                    if rule["effect"] in {"block", "decline"}
                    else "review"
                    if rule["effect"] == "detect"
                    else "observe"
                ),
            ),
        }
        for rule in PAYMENT_POLICY_RULES
    ]
    business_risk = {
        "LIFE-RETRY-001": "warning",
        "LIFE-ORDER-002": "critical",
        "LIFE-SPEND-003": "high",
    }
    business = [
        {
            "id": policy["id"],
            "name": policy["name"],
            "risk_level": business_risk.get(policy["id"], "warning"),
            "action": policy["action"],
            "mode": "deny" if policy["id"] == "LIFE-ORDER-002" else "review",
            "stage": "pre_execution_approval",
            "evidence_source": "deterministic_business_state",
            "enforceable_now": policy["id"] == "LIFE-ORDER-002",
            "stateful": True,
            "tested": "local",
            "enabled": True,
            **_block_copy_fields(
                str(policy["id"]),
                str(policy["name"]),
                "deny" if policy["id"] == "LIFE-ORDER-002" else "review",
            ),
        }
        for policy in load_business_policy_catalog().values()
    ]
    workbuddy = [
        {
            **policy,
            "stage": "transactional_commit",
            "evidence_source": "workbuddy_sqlite_state",
            "enforceable_now": True,
            "stateful": True,
            "tested": "local",
            "enabled": True,
            **_block_copy_fields(
                str(policy["id"]), str(policy["name"]), str(policy["mode"])
            ),
        }
        for policy in load_workbuddy_policy_catalog()
    ]
    groups = [
        {
            "id": "runtime",
            "name": "Agent 行为防护",
            "description": "覆盖凭据、外联、破坏、持久化和主机控制等运行风险。",
            "policies": runtime,
        },
        {
            "id": "payment",
            "name": "支付密钥保护",
            "description": "关联密钥读取、编码派生和外发通道，在执行前阻断组合风险。",
            "policies": payment,
        },
        {
            "id": "business",
            "name": "生活业务保护",
            "description": "把重复提交和超额消费转换为用户能直接判断的业务后果。",
            "policies": business,
        },
        {
            "id": "workbuddy",
            "name": "WorkBuddy 办公动作保护",
            "description": "在本地事务沙箱中执行准备、复核、转换、阻断与一次性批准。",
            "policies": workbuddy,
        },
    ]
    return {
        "schema_version": "lingmou.workbench-policy-catalog.v1",
        "total": sum(len(group["policies"]) for group in groups),
        "groups": groups,
    }


def _same_origin(origin: str | None, host: str | None) -> bool:
    if not origin:
        return True
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(host)
        and parsed.netloc.casefold() == str(host).casefold()
    )


def _token_matches(candidate: str | None, expected: str | None) -> bool:
    return bool(
        candidate
        and expected
        and secrets.compare_digest(candidate, expected)
    )


class CompressionSettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["off", "structure", "extract", "auto", "full"]


def create_workbench_app(
    controller: AgentAdapter,
    store: WorkbenchEventStore,
    *,
    syscall_index: SyscallIndex | None = None,
    harness_monitor: HarnessMonitor | None = None,
    static_dir: Path | None = None,
    manage_controller: bool = True,
    allowed_hosts: list[str] | None = None,
    access_token: str | None = None,
    secure_cookie: bool = False,
    scenario_launch_urls: dict[str, str] | None = None,
    token_tap: Any = None,
) -> FastAPI:
    """Create the protected API and serve the compiled React client."""

    controller_run_dir = getattr(controller, "run_dir", None)
    index_run_dir = Path(controller_run_dir) if controller_run_dir else store.path.parent
    if syscall_index is None:
        try:
            syscall_index = SyscallIndex(index_run_dir, event_store=store)
        except (OSError, ValueError, SyscallIndexError):
            syscall_index = None
    if harness_monitor is None:
        try:
            harness_monitor = HarnessMonitor(index_run_dir)
        except (OSError, ValueError):
            harness_monitor = None

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if manage_controller:
            await controller.start_background()
        try:
            yield
        finally:
            if manage_controller:
                await controller.stop()
            if syscall_index is not None:
                await asyncio.to_thread(syscall_index.close)

    app = FastAPI(
        title="Lingmou Workbench",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.syscall_index = syscall_index
    app.state.harness_monitor = harness_monitor
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "127.0.0.1",
            "localhost",
            "[::1]",
            "testserver",
            *(allowed_hosts or []),
        ],
    )

    @app.middleware("http")
    async def require_access_token(request: Request, call_next: Any):
        if not access_token:
            return await call_next(request)

        supplied = request.query_params.get("access_token")
        authenticated = _token_matches(
            request.cookies.get(_ACCESS_COOKIE), access_token
        )
        if _token_matches(supplied, access_token):
            response = RedirectResponse(request.url.path or "/", status_code=303)
            response.set_cookie(
                _ACCESS_COOKIE,
                access_token,
                httponly=True,
                secure=secure_cookie,
                samesite="strict",
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response
        if not authenticated:
            return JSONResponse(
                {"detail": "valid Lingmou access token required"},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)

    @app.middleware("http")
    async def reject_cross_origin_mutations(request: Request, call_next: Any):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not _same_origin(
            request.headers.get("origin"), request.headers.get("host")
        ):
            return JSONResponse({"detail": "cross-origin mutation refused"}, status_code=403)
        return await call_next(request)

    @app.exception_handler(WorkbenchError)
    async def workbench_error(_request: Request, exc: WorkbenchError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/api/v1/state")
    async def state() -> dict[str, Any]:
        return controller.snapshot()

    def token_snapshot() -> dict:
        current = {**token_tap.stats_dict(), 'configurable': True} if token_tap is not None else None
        return token_panel_snapshot(index_run_dir, provider_snapshot=current)

    @app.get("/api/v1/tokens")
    async def tokens() -> dict:
        return await asyncio.to_thread(token_snapshot)

    @app.put("/api/v1/tokens/compression")
    async def compression_settings(body: CompressionSettingsBody) -> dict:
        snapshot = await asyncio.to_thread(token_snapshot)
        if not snapshot['configurable'] or not snapshot['relay_enabled']:
            raise HTTPException(409, '本次运行未接入可配置的请求代理，请重新启动并启用 Token 压缩。')
        await asyncio.to_thread(atomic_json_dump, index_run_dir / 'compression_settings.json', {'mode': body.mode})
        return await asyncio.to_thread(token_snapshot)

    @app.get("/api/v1/events")
    async def events(
        after_seq: int = Query(0, ge=0),
        limit: int = Query(1_000, ge=1, le=5_000),
    ) -> dict[str, Any]:
        rows = store.events(after_seq=after_seq, limit=limit)
        return {
            "events": rows,
            "last_seq": rows[-1]["seq"] if rows else store.last_seq,
        }

    def policy_workspace() -> Path:
        # Runtime workspace is authoritative; never accept a client-supplied path.
        repo = getattr(controller, "repo", None) or controller.snapshot().get("workspace")
        if not repo:
            raise HTTPException(409, "当前 Agent 未提供策略工作区")
        return Path(repo)

    def configuration_payload(
        document: dict[str, Any], revision: str
    ) -> dict[str, Any]:
        return {
            "document": document,
            "revision": revision,
            "path": str(config_path(policy_workspace())),
            "defaults": default_document()["rules"],
            "fields": sorted(FIELDS),
            "operators": sorted(OPS),
            "meta_policies": meta_catalog(),
            "filesystem_guard": guard_status(getattr(controller, "run_dir", None), document),
        }

    @app.exception_handler(PolicyConfigError)
    async def policy_config_error(_request: Request, exc: PolicyConfigError):
        return JSONResponse(
            {"detail": str(exc)},
            status_code=409 if isinstance(exc, PolicyConflict) else 422,
        )

    @app.get("/api/v1/policy-config")
    async def policy_configuration() -> dict[str, Any]:
        return configuration_payload(*load_document(policy_workspace()))

    policy_proposals: dict[str, dict[str, Any]] = {}
    interpretation_slots = asyncio.Semaphore(2)

    @app.post("/api/v1/policy-intent/interpret")
    async def interpret_policy_requirement(body: PolicyIntentBody) -> dict[str, Any]:
        document, revision = load_document(policy_workspace())
        async with interpretation_slots:
            proposal = await interpret_policy(body.text.strip(), policy_workspace(), document)
        # Interpretation can take seconds; recheck saved and running state before
        # reporting an idempotent success. A saved-but-inactive rule is not active.
        current, current_revision = load_document(policy_workspace())
        if current_revision != revision:
            raise PolicyConflict("策略已被修改，请重新生成")
        configuration = configuration_payload(current, current_revision)
        guard = configuration["filesystem_guard"]
        if (proposal["document"] == current
                and not guard["restart_required"]
                and guard["status"] in {"active", "disabled"}
                and not controller.snapshot().get("policy_transition")
                and not controller.snapshot().get("policy_error")):
            return {"status": "already_active", "summary": proposal["summary"],
                    "message": "该规则已生效，无需重复启用，可直接到工作台提交任务。",
                    "configuration": configuration, "parser": proposal["parser"]}
        proposal_id = secrets.token_urlsafe(24)
        now = time.monotonic()
        for key in list(policy_proposals):
            if policy_proposals[key]["expires_at"] < now:
                del policy_proposals[key]
        if len(policy_proposals) >= 64:
            del policy_proposals[next(iter(policy_proposals))]
        policy_proposals[proposal_id] = {**proposal, "revision": revision, "expires_at": now + 900}
        return {"proposal_id": proposal_id, "summary": proposal["summary"],
                "changes": proposal["changes"], "source_text": body.text,
                "status": "ready", "parser": proposal["parser"]}

    @app.post("/api/v1/policy-intent/activate")
    async def activate_policy_requirement(body: PolicyActivateBody) -> dict[str, Any]:
        proposal = policy_proposals.get(body.proposal_id)
        if not proposal or proposal["expires_at"] < time.monotonic():
            raise HTTPException(409, "策略预览已过期，请重新生成")
        activate = getattr(controller, "activate_policy", None)
        if activate is None:
            raise HTTPException(409, "当前 Agent 不支持自动启用策略")
        result = await activate(proposal["document"], proposal["revision"], proposal["summary"])
        policy_proposals.pop(body.proposal_id, None)
        return {"status": "active", "summary": proposal["summary"],
                "configuration": configuration_payload(result["document"], result["revision"])}

    @app.put("/api/v1/policy-config")
    async def save_policy_configuration(body: PolicySaveBody) -> dict[str, Any]:
        resolve_denied(policy_workspace(), validate_document(body.document))
        document, revision = save_document(
            policy_workspace(), body.document, body.revision
        )
        store.append(
            "policy_config_updated",
            title="策略配置已更新",
            summary="审批规则即时更新；目录边界变更须重启 Agent 后生效",
            source="lingmou_workbench",
            payload={
                "revision": revision,
                "rule_count": len(document["rules"]),
                "override_count": len(document["overrides"]),
            },
        )
        return configuration_payload(document, revision)

    @app.post("/api/v1/policy-config/preview")
    async def preview_policy_configuration(body: PolicyPreviewBody) -> dict[str, Any]:
        document = validate_document(body.document)
        if body.event == "work.action":
            traces: list[dict[str, Any]] = []
            decisions = await asyncio.to_thread(evaluate, document, body.event, body.facts, traces=traces)
            return {
                "decisions": decisions,
                "traces": traces,
                "blocking_rule": next(
                    (d["policy_id"] for d in decisions if d["blocking"]), None
                ),
                "scope": "仅按提供的办公事实试算，不读取真实业务状态，不执行动作",
            }
        if not body.command:
            raise HTTPException(422, "命令试算需要 command")
        result = await asyncio.to_thread(
            assess_approval_policies, body.command, workspace=policy_workspace(), document=document
        )
        return {
            "decisions": result["policy_decisions"],
            "traces": result["policy_traces"],
            "blocking_rule": next(
                (d["policy_id"] for d in result["policy_decisions"] if d["blocking"]),
                None,
            ),
            "scope": "单命令试算，不执行命令，不包含当前会话派生链",
            "facts": {key: result["policy_facts"][key] for key in ("network", "file", "process")},
            "parse_complete": result["policy_facts"]["command"]["parse_complete"],
            "parse_warnings": result["parse_warnings"],
        }

    @app.get("/api/v1/policies")
    async def policies() -> dict[str, Any]:
        catalog = _workbench_policy_catalog()
        try:
            document, revision = load_document(policy_workspace())
        except HTTPException:
            return catalog
        configured = {r["id"]: r for r in effective_rules(document)}
        for group in catalog["groups"]:
            for policy in group["policies"]:
                rule = configured.get(policy["id"])
                if rule and policy["id"] in document["overrides"]:
                    policy.update(
                        mode=rule["mode"],
                        enabled=rule.get("enabled", True),
                        stage="pre_execution_approval"
                        if rule["event"] == "command.approval"
                        else "tool_before",
                        enforceable_now=rule.get("enabled", True),
                    )
                    policy["action"] = (
                        "已停用（执行前检查）"
                        if not rule.get("enabled", True)
                        else {
                            "deny": "执行前阻断",
                            "review": "人工复核",
                            "observe": "记录",
                            "transform": "按配置条件处理内容",
                        }[rule["mode"]]
                    )
        custom = [
            {
                "id": r["id"],
                "name": r["name"],
                "risk_level": r.get("risk_level", "warning"),
                "mode": r["mode"],
                "action": "已停用"
                if not r.get("enabled", True)
                else {"deny": "执行前阻断", "review": "人工复核", "observe": "记录"}[
                    r["mode"]
                ],
                "stage": "pre_execution_approval"
                if r["event"] == "command.approval"
                else "tool_before",
                "evidence_source": "atomic_policy",
                "enforceable_now": True,
                "stateful": False,
                "tested": "unverified",
            }
            for r in document["rules"]
        ]
        fs = guard_status(getattr(controller, "run_dir", None), document)
        if document.get("filesystem", {}).get("deny") or fs.get("denied_paths"):
            custom.append({
                "id": "USER-FILESYSTEM-DENY", "name": "用户禁止访问目录",
                "risk_level": "high", "mode": "deny", "stage": "kernel_filesystem",
                "action": "目录访问拒绝" if fs.get("status") == "active" else "待重启 Agent",
                "evidence_source": "linux_strace", "enforceable_now": fs.get("status") == "active",
                "enabled": True, "stateful": False, "tested": "unverified",
            })
        if custom:
            catalog["groups"].append(
                {
                    "id": "custom",
                    "name": "自定义策略",
                    "description": "按用户配置组合事实条件",
                    "policies": custom,
                }
            )
        catalog["total"] = sum(len(g["policies"]) for g in catalog["groups"])
        catalog["revision"] = revision
        return catalog

    @app.get("/api/v1/scenarios")
    async def scenarios() -> dict[str, Any]:
        snapshot = controller.snapshot()
        backend = str(snapshot.get("agent_backend") or "codex")
        active = snapshot.get("active_scenario")
        active_id = (
            str(active.get("id"))
            if isinstance(active, dict) and active.get("id")
            else None
        )
        result = scenario_catalog(agent_available=True)
        launched = 0
        for item in result["scenarios"]:
            if not item["runnable"]:
                continue
            launch_url = (scenario_launch_urls or {}).get(str(item["id"]))
            if launch_url:
                item["launch_url"] = launch_url
                launched += 1
            if active_id and item["id"] == active_id:
                item["availability"] = "available"
                item["availability_reason"] = None
            elif launch_url:
                item["availability"] = "available"
                item["availability_reason"] = "独立策略沙箱已启动。"
            elif active_id:
                item["availability"] = "restart_required"
                item["availability_reason"] = (
                    f"当前沙箱属于 {active_id}；请用干净重启脚本选择此场景。"
                )
            else:
                item["availability"] = "workbuddy_start_required"
                item["availability_reason"] = "请先通过 codexscope workbuddy 创建独立沙箱。"
        result["agent_backend"] = backend
        result["launched"] = launched
        if launched:
            result["launch_hint"] = (
                f"已接入 {launched} 个独立 WorkBuddy 沙箱；点击场景进入对应策略工作台。"
            )
        elif active_id:
            result["launch_hint"] = None
        else:
            result["launch_hint"] = (
                "用 `codexscope workbuddy --scenario WB-05` 启动重复采购故障注入；"
                "默认沿用当前 Codex 登录与模型。"
            )
        return result

    @app.get("/api/v1/harness")
    async def harness_status() -> dict[str, Any]:
        if harness_monitor is None:
            raise HTTPException(
                status_code=503,
                detail="当前 Run 的 Harness 监控数据不可用",
            )
        try:
            return await asyncio.to_thread(harness_monitor.snapshot)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    def require_syscall_index() -> SyscallIndex:
        if syscall_index is None:
            raise HTTPException(
                status_code=503,
                detail="当前 Run 的系统调用索引不可用",
            )
        return syscall_index

    @app.get("/api/v1/syscalls/status")
    async def syscall_status() -> dict[str, Any]:
        service = require_syscall_index()
        try:
            return await asyncio.to_thread(service.status)
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/syscalls")
    async def syscalls(
        after_seq: int | None = Query(None, ge=0),
        before_seq: int | None = Query(None, ge=1),
        limit: int = Query(200, ge=1, le=MAX_PAGE_SIZE),
        order: str = Query("desc", pattern="^(asc|desc)$"),
        pid: int | None = Query(None, ge=1),
        tid: int | None = Query(None, ge=1),
        syscall: list[str] | None = Query(None),
        category: str | None = Query(None, max_length=64),
        access: str | None = Query(None, max_length=64),
        path: str | None = Query(None, max_length=512),
        endpoint: str | None = Query(None, max_length=512),
        success: bool | None = Query(None),
        q: str | None = Query(None, max_length=256),
        from_ns: int | None = Query(None, ge=0),
        to_ns: int | None = Query(None, ge=0),
        key_only: bool = Query(False),
        behavior_only: bool = Query(False),
        item_id: str | None = Query(None, max_length=256),
    ) -> dict[str, Any]:
        service = require_syscall_index()
        try:
            return await asyncio.to_thread(
                service.query,
                after_seq=after_seq,
                before_seq=before_seq,
                limit=limit,
                order=order,
                pid=pid,
                tid=tid,
                syscalls=syscall or (),
                category=category,
                access=access,
                path=path,
                endpoint=endpoint,
                success=success,
                query=q,
                from_ns=from_ns,
                to_ns=to_ns,
                key_only=key_only,
                behavior_only=behavior_only,
                item_id=item_id,
            )
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/syscalls/processes")
    async def syscall_processes(
        limit: int = Query(5_000, ge=1, le=20_000),
    ) -> dict[str, Any]:
        service = require_syscall_index()
        try:
            return await asyncio.to_thread(service.processes, limit=limit)
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/syscalls/density")
    async def syscall_density(
        buckets: int = Query(96, ge=1, le=240),
        from_ns: int | None = Query(None, ge=0),
        to_ns: int | None = Query(None, ge=0),
        key_only: bool = Query(False),
        behavior_only: bool = Query(False),
        pid: int | None = Query(None, ge=1),
        category: str | None = Query(None, max_length=64),
    ) -> dict[str, Any]:
        service = require_syscall_index()
        try:
            return await asyncio.to_thread(
                service.density,
                buckets=buckets,
                from_ns=from_ns,
                to_ns=to_ns,
                key_only=key_only,
                behavior_only=behavior_only,
                pid=pid,
                category=category,
            )
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/api/v1/syscalls/rebuild")
    async def rebuild_syscalls() -> dict[str, Any]:
        service = require_syscall_index()
        try:
            return await asyncio.to_thread(service.rebuild)
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/syscalls/{seq}")
    async def syscall_detail(seq: int) -> dict[str, Any]:
        service = require_syscall_index()
        try:
            result = await asyncio.to_thread(service.detail, seq)
        except (OSError, ValueError, SyscallIndexError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="syscall not found")
        return result

    @app.get("/api/v1/history")
    async def history(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
        try:
            result = store.history_runs(limit=limit)
        except HistoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        result["status"] = store.history_status()
        return result

    @app.post("/api/v1/history/rebuild")
    async def rebuild_history() -> dict[str, Any]:
        try:
            return await asyncio.to_thread(store.rebuild_history)
        except HistoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/investigations")
    async def investigations(
        limit: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        try:
            return store.investigations(limit=limit)
        except HistoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/investigations/{investigation_id}")
    async def investigation(investigation_id: str) -> dict[str, Any]:
        try:
            result = store.investigation(investigation_id)
        except HistoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="investigation not found")
        return result

    @app.get("/api/v1/context-capsule")
    async def context_capsule(
        run_id: str = Query(min_length=1, max_length=256),
        thread_id: str = Query(min_length=1, max_length=256),
        turn_id: str = Query(min_length=1, max_length=256),
        include_forensic: bool = Query(False),
    ) -> dict[str, Any]:
        try:
            result = store.context_capsule(
                run_id,
                thread_id,
                turn_id,
                include_forensic=include_forensic,
            )
        except HistoryUnavailable as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="context capsule not found")
        return result

    @app.post("/api/v1/turns", status_code=202)
    async def start_turn(body: TextBody) -> dict[str, Any]:
        if body.scenario_id is None:
            return await controller.send_prompt(body.text)
        return await controller.send_prompt(body.text, scenario_id=body.scenario_id)

    @app.post("/api/v1/turns/steer", status_code=202)
    async def steer_turn(body: TextBody) -> dict[str, Any]:
        return await controller.steer(body.text)

    @app.post("/api/v1/turns/interrupt", status_code=202)
    async def interrupt_turn() -> dict[str, Any]:
        return await controller.interrupt()

    @app.post("/api/v1/approvals/{interaction_id:path}")
    async def decide_approval(
        interaction_id: str, body: ApprovalBody
    ) -> dict[str, Any]:
        return await controller.respond_approval(interaction_id, body.decision)

    @app.post("/api/v1/user-input/{interaction_id:path}")
    async def answer_user_input(
        interaction_id: str, body: UserInputBody
    ) -> dict[str, Any]:
        return await controller.respond_user_input(interaction_id, body.answers)

    @app.websocket("/api/v1/events/ws")
    async def event_socket(
        websocket: WebSocket, after_seq: int = Query(0, ge=0)
    ) -> None:
        if access_token and not _token_matches(
            websocket.cookies.get(_ACCESS_COOKIE), access_token
        ):
            await websocket.close(code=1008, reason="valid access token required")
            return
        if not _same_origin(
            websocket.headers.get("origin"), websocket.headers.get("host")
        ):
            await websocket.close(code=1008, reason="cross-origin connection refused")
            return
        await websocket.accept()
        queue = store.subscribe(maxsize=5_000)
        cursor = after_seq
        try:
            await websocket.send_json({"type": "state", "state": controller.snapshot()})
            while True:
                replay = store.events(after_seq=cursor, limit=5_000)
                for event in replay:
                    await websocket.send_json({"type": "event", "event": event})
                    cursor = max(cursor, int(event["seq"]))
                if len(replay) < 5_000:
                    break
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except TimeoutError:
                    await websocket.send_json(
                        {"type": "heartbeat", "last_seq": cursor}
                    )
                    continue
                if int(event["seq"]) <= cursor:
                    continue
                await websocket.send_json({"type": "event", "event": event})
                cursor = int(event["seq"])
        except (WebSocketDisconnect, RuntimeError):
            return
        finally:
            store.unsubscribe(queue)

    @app.websocket("/api/v1/syscalls/ws")
    async def syscall_socket(
        websocket: WebSocket,
        after_seq: int = Query(0, ge=0),
        behavior_only: bool = Query(False),
    ) -> None:
        if access_token and not _token_matches(
            websocket.cookies.get(_ACCESS_COOKIE), access_token
        ):
            await websocket.close(code=1008, reason="valid access token required")
            return
        if not _same_origin(
            websocket.headers.get("origin"), websocket.headers.get("host")
        ):
            await websocket.close(code=1008, reason="cross-origin connection refused")
            return
        service = syscall_index
        if service is None:
            await websocket.close(code=1013, reason="syscall index unavailable")
            return
        await websocket.accept()
        cursor = after_seq
        last_heartbeat = 0.0
        try:
            status_payload = await asyncio.to_thread(service.status)
            latest = int(status_payload.get("index", {}).get("last_seq") or 0)
            if cursor > latest:
                cursor = 0
                await websocket.send_json(
                    {"type": "reset", "reason": "source_rebuilt", "last_seq": latest}
                )
            await websocket.send_json({"type": "status", "status": status_payload})
            while True:
                page = await asyncio.to_thread(
                    service.query,
                    after_seq=cursor,
                    limit=500,
                    order="asc",
                    behavior_only=behavior_only,
                    include_total=False,
                )
                rows = page.get("items") or []
                if rows:
                    cursor = int(rows[-1]["seq"])
                    await websocket.send_json(
                        {
                            "type": "batch",
                            "events": rows,
                            "first_seq": rows[0]["seq"],
                            "last_seq": cursor,
                            "has_more": bool(page.get("page", {}).get("has_more")),
                        }
                    )
                    continue
                latest = int(page.get("index", {}).get("last_seq") or cursor)
                if behavior_only and cursor <= latest:
                    # Intentionally filtered rows still advance the raw index.
                    # Fast-forward the stream cursor so an idle behavior view
                    # does not rescan the same noise four times per second.
                    cursor = latest
                now = asyncio.get_running_loop().time()
                if now - last_heartbeat >= 10:
                    if cursor > latest:
                        cursor = 0
                        await websocket.send_json(
                            {"type": "reset", "reason": "source_rebuilt", "last_seq": latest}
                        )
                    else:
                        await websocket.send_json(
                            {"type": "heartbeat", "last_seq": cursor}
                        )
                    last_heartbeat = now
                await asyncio.sleep(0.25)
        except (WebSocketDisconnect, RuntimeError):
            return
        except (OSError, ValueError, SyscallIndexError) as exc:
            try:
                await websocket.send_json(
                    {"type": "error", "detail": redact_text(str(exc))[:512]}
                )
            except (WebSocketDisconnect, RuntimeError):
                pass

    root = static_dir or Path(__file__).with_name("workbench_dist")
    assets = root / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="workbench-assets")

    @app.get("/", include_in_schema=False)
    async def index() -> Any:
        path = root / "index.html"
        if not path.is_file():
            raise HTTPException(
                status_code=503,
                detail="workbench frontend is not built; run `npm run build` in web/",
            )
        return FileResponse(path)

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> Any:
        if path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = (root / path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            raise HTTPException(status_code=404) from None
        if candidate.is_file():
            return FileResponse(candidate)
        index_path = root / "index.html"
        if index_path.is_file():
            return FileResponse(index_path)
        raise HTTPException(status_code=404)

    return app


__all__ = ["create_workbench_app"]
