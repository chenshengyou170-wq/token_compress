"""CodeBuddy HTTP ACP v1 adapter for the Lingmou WorkBuddy workbench.

The adapter deliberately uses only the documented ``/api/v1/health`` and
``/api/v1/acp*`` surface.  It records semantic ACP updates and the controlled
WorkBuddy executor evidence, but never stores agent thought text.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx

from . import __version__
from .redaction import redact_event, redact_text
from .workbench_controller import WorkbenchError, WorkbenchRpcError
from .workbench_store import WorkbenchEventStore
from .workbuddy_actions import WorkBuddyActionError, WorkBuddyRuntime
from .workbuddy_events import record_workbuddy_runtime_event
from .workbuddy_scenarios import scenario_instruction


ACP_PROTOCOL_VERSION = 1
_PUBLIC_ACP_PATH = "/api/v1/acp"


async def parse_sse_lines(lines: AsyncIterator[str]) -> AsyncIterator[dict[str, str]]:
    """Parse SSE fields, including multiline data and resume identifiers."""

    event: dict[str, str] = {}
    data: list[str] = []
    async for raw_line in lines:
        line = raw_line.rstrip("\r")
        if not line:
            if data:
                event["data"] = "\n".join(data)
            if event:
                yield event
            event = {}
            data = []
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if not separator:
            value = ""
        elif value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
        elif field in {"event", "id", "retry"}:
            event[field] = value
    if data:
        event["data"] = "\n".join(data)
    if event:
        yield event


def _content_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if value.get("type") == "text" and isinstance(value.get("text"), str):
            return str(value["text"])
        for key in ("content", "message", "delta"):
            nested = value.get(key)
            result = _content_text(nested)
            if result:
                return result
    if isinstance(value, list):
        return "".join(_content_text(item) for item in value)
    return ""


class CodeBuddyACPAdapter:
    """Translate CodeBuddy's public HTTP ACP transport into workbench events."""

    def __init__(
        self,
        *,
        base_url: str,
        password: str,
        repo: Path | str,
        run_dir: Path | str,
        store: WorkbenchEventStore,
        runtime: WorkBuddyRuntime,
        mcp_server: Mapping[str, Any],
        os_audit: Mapping[str, Any] | None = None,
        client: httpx.AsyncClient | None = None,
        reconnect_delay: float = 0.25,
        rpc_timeout: float = 1_800.0,
    ) -> None:
        normalized_url = base_url.rstrip("/")
        if not normalized_url.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise ValueError("CodeBuddy ACP endpoint must be loopback HTTP")
        self.base_url = normalized_url
        self.password = password
        self.repo = Path(repo).expanduser().resolve()
        self.run_dir = Path(run_dir).expanduser().resolve()
        self.store = store
        self.runtime = runtime
        self.mcp_server = dict(mcp_server)
        self.os_audit = dict(os_audit or {})
        self.reconnect_delay = max(0.02, float(reconnect_delay))
        self.rpc_timeout = max(1.0, float(rpc_timeout))
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(None, connect=10.0), follow_redirects=False
        )
        self._owns_client = client is None

        self.connected = False
        self.connection_error: str | None = None
        self.thread_id: str | None = None
        self.active_turn_id: str | None = None
        self.turn_status = "idle"
        self.model: str | None = None
        self._connection_id: str | None = None
        self._session_token: str | None = None
        self._last_event_id: str | None = None
        self._next_rpc_id = 1
        self._rpc_pending: dict[int | str, asyncio.Future[Any]] = {}
        self._acp_interactions: dict[str, dict[str, Any]] = {}
        self._runner_task: asyncio.Task[None] | None = None
        self._sse_task: asyncio.Task[None] | None = None
        self._outbox_task: asyncio.Task[None] | None = None
        self._prompt_task: asyncio.Task[None] | None = None
        self._closing = False
        self._ready = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._outbox_cursor = 0
        self._plan_steps: list[dict[str, Any]] = []
        self._active_tool: dict[str, Any] | None = None
        self._task_goal: str | None = None

    def snapshot(self) -> dict[str, Any]:
        pending = [*self.runtime.pending_interactions(), *self._acp_interactions.values()]
        return {
            "agent_backend": "codebuddy",
            "active_scenario": self.runtime.scenario,
            "mcp_gateway_status": self.runtime.gateway_status(),
            "connected": self.connected,
            "connection_error": self.connection_error,
            "workspace": os.fspath(self.repo),
            "run_dir": os.fspath(self.run_dir),
            "thread_id": self.thread_id,
            "active_turn_id": self.active_turn_id,
            "turn_status": self.turn_status,
            "model": self.model,
            "approval_policy": "one_shot_only",
            "sandbox": "workbuddy_sqlite",
            "security_mode": "enforce",
            "privacy": {
                "credentials": "always_redacted",
                "conversation_persisted": self.store.persist_conversation,
                "forensic_context_encrypted": self.store.forensic_mode,
                "hidden_reasoning_content": "never_collected",
            },
            "history": self.store.history_status(),
            "pending_interactions": sorted(
                pending, key=lambda item: float(item.get("created_at") or 0)
            ),
            "live_security": self.store.get_state("live_security", {}),
            "task": {
                "goal": self._task_goal,
                "started_at": self.store.get_state("workbuddy_turn_started_at"),
                "current_step": next(
                    (item for item in self._plan_steps if item["status"] == "in_progress"),
                    self._plan_steps[0] if self._plan_steps else None,
                ),
                "steps": self._plan_steps,
                "active_command": self._active_tool,
            },
            "last_seq": self.store.last_seq,
        }

    async def start_background(self) -> None:
        if self._runner_task is not None and not self._runner_task.done():
            return
        self._closing = False
        self._outbox_task = asyncio.create_task(
            self._outbox_loop(), name="lingmou-workbuddy-outbox"
        )
        self._runner_task = asyncio.create_task(
            self._connection_loop(), name="lingmou-codebuddy-acp"
        )

    async def wait_until_ready(self, timeout: float = 15.0) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    async def stop(self) -> None:
        self._closing = True
        if self.active_turn_id and self.thread_id and self.connected:
            try:
                await self._notify("session/cancel", {"sessionId": self.thread_id})
            except Exception:
                pass
        for interaction in tuple(self._acp_interactions.values()):
            try:
                await self._answer_server_request(
                    interaction["rpc_id"], {"outcome": {"outcome": "cancelled"}}
                )
            except Exception:
                pass
        self._acp_interactions.clear()
        if self._connection_id:
            try:
                await self._client.delete(
                    f"{self.base_url}{_PUBLIC_ACP_PATH}", headers=self._acp_headers()
                )
            except Exception:
                pass
        tasks = [
            task
            for task in (self._prompt_task, self._sse_task, self._runner_task, self._outbox_task)
            if task is not None and not task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._fail_pending(WorkbenchError("CodeBuddy ACP connection closed"))
        self.connected = False
        self._ready.clear()
        if self._owns_client:
            await self._client.aclose()

    def _base_headers(self) -> dict[str, str]:
        return {
            "X-CodeBuddy-Request": "1",
            "Authorization": f"Bearer {self.password}",
            "Accept": "application/json",
        }

    def _acp_headers(self, *, stream: bool = False) -> dict[str, str]:
        headers = self._base_headers()
        if self._connection_id:
            headers["acp-connection-id"] = self._connection_id
        if self._session_token:
            headers["acp-session-token"] = self._session_token
        if self._last_event_id and stream:
            headers["Last-Event-ID"] = self._last_event_id
        if stream:
            headers["Accept"] = "text/event-stream"
        return headers

    async def _connection_loop(self) -> None:
        while not self._closing:
            try:
                await self._connect_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                message = redact_text(str(exc)) or type(exc).__name__
                self.connection_error = message
                self.store.append(
                    "connection",
                    title="CodeBuddy ACP 连接中断",
                    summary=message,
                    source="codebuddy_acp",
                    status="failed",
                )
            finally:
                self.connected = False
                self._ready.clear()
                self._fail_pending(WorkbenchError("CodeBuddy ACP connection closed"))
                if self._sse_task and not self._sse_task.done():
                    self._sse_task.cancel()
                    await asyncio.gather(self._sse_task, return_exceptions=True)
                self._sse_task = None
                self._connection_id = None
                self._session_token = None
            if not self._closing:
                await asyncio.sleep(self.reconnect_delay)

    async def _connect_once(self) -> None:
        health = await self._client.get(
            f"{self.base_url}/api/v1/health", headers=self._base_headers()
        )
        health.raise_for_status()
        response = await self._client.post(
            f"{self.base_url}{_PUBLIC_ACP_PATH}/connect",
            headers=self._base_headers(),
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", payload) if isinstance(payload, Mapping) else {}
        self._connection_id = str(data.get("connectionId") or "")
        self._session_token = str(data.get("sessionToken") or "")
        if not self._connection_id or not self._session_token:
            raise WorkbenchError("CodeBuddy ACP connect response is missing credentials")

        self._sse_task = asyncio.create_task(
            self._sse_loop(), name="lingmou-codebuddy-acp-sse"
        )
        await asyncio.sleep(0)
        initialized = await self._rpc(
            "initialize",
            {
                "protocolVersion": ACP_PROTOCOL_VERSION,
                "clientCapabilities": {},
                "clientInfo": {
                    "name": "lingmou-workbench",
                    "title": "灵眸 WorkBuddy",
                    "version": __version__,
                },
            },
            timeout=20.0,
        )
        negotiated = initialized if isinstance(initialized, Mapping) else {}
        if negotiated.get("protocolVersion") != ACP_PROTOCOL_VERSION:
            raise WorkbenchError(
                "CodeBuddy ACP protocol incompatible: Lingmou requires stable v1"
            )
        capabilities = negotiated.get("agentCapabilities")
        capabilities = capabilities if isinstance(capabilities, Mapping) else {}
        mcp = capabilities.get("mcpCapabilities")
        mcp = mcp if isinstance(mcp, Mapping) else {}
        if mcp.get("http") is not True:
            raise WorkbenchError(
                "CodeBuddy ACP does not advertise required MCP HTTP capability"
            )
        info = negotiated.get("agentInfo")
        if isinstance(info, Mapping):
            self.model = str(info.get("title") or info.get("name") or "CodeBuddy")
        self.connected = True
        self.connection_error = None
        self._ready.set()
        self.store.append(
            "connection",
            title="已连接 CodeBuddy ACP",
            summary="公开 ACP v1 · MCP HTTP",
            payload={"protocol_version": 1, "transport": "http+sse"},
            source="codebuddy_acp",
            status="connected",
        )
        await self._sse_task

    async def _sse_loop(self) -> None:
        while not self._closing and self._connection_id:
            try:
                async with self._client.stream(
                    "GET",
                    f"{self.base_url}{_PUBLIC_ACP_PATH}",
                    headers=self._acp_headers(stream=True),
                ) as response:
                    response.raise_for_status()
                    async for event in parse_sse_lines(response.aiter_lines()):
                        if event.get("id"):
                            self._last_event_id = event["id"]
                        raw = event.get("data")
                        if not raw:
                            continue
                        try:
                            frame = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        await self._handle_frame(frame)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.connection_error = f"ACP SSE reconnecting: {redact_text(str(exc))}"
                if not self._closing:
                    await asyncio.sleep(self.reconnect_delay)
                continue
            if not self._closing:
                await asyncio.sleep(self.reconnect_delay)

    async def _post_frame(self, frame: Mapping[str, Any]) -> None:
        async with self._send_lock:
            response = await self._client.post(
                f"{self.base_url}{_PUBLIC_ACP_PATH}",
                headers=self._acp_headers(),
                json=dict(frame),
            )
        response.raise_for_status()
        if not response.content:
            return
        try:
            payload = response.json()
        except json.JSONDecodeError:
            return
        if isinstance(payload, Mapping) and "data" in payload and "jsonrpc" not in payload:
            payload = payload["data"]
        await self._handle_frame(payload)

    async def _rpc(
        self, method: str, params: Mapping[str, Any], *, timeout: float | None = None
    ) -> Any:
        rpc_id = self._next_rpc_id
        self._next_rpc_id += 1
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._rpc_pending[rpc_id] = future
        try:
            await self._post_frame(
                {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": dict(params)}
            )
            return await asyncio.wait_for(
                future, timeout=self.rpc_timeout if timeout is None else timeout
            )
        finally:
            self._rpc_pending.pop(rpc_id, None)

    async def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        await self._post_frame(
            {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        )

    async def _handle_frame(self, raw: object) -> None:
        if isinstance(raw, list):
            for item in raw:
                await self._handle_frame(item)
            return
        if not isinstance(raw, Mapping):
            return
        frame: Mapping[str, Any] = raw
        if "data" in frame and "jsonrpc" not in frame and isinstance(frame["data"], Mapping):
            frame = frame["data"]
        rpc_id = frame.get("id")
        method = frame.get("method")
        if rpc_id is not None and method is None and ("result" in frame or "error" in frame):
            future = self._rpc_pending.get(rpc_id)
            if future is not None and not future.done():
                if "error" in frame:
                    future.set_exception(WorkbenchRpcError("ACP", frame["error"]))
                else:
                    future.set_result(frame.get("result"))
            return
        if not isinstance(method, str):
            return
        params = frame.get("params")
        params = params if isinstance(params, Mapping) else {}
        if method == "session/update":
            self._handle_session_update(params)
            return
        if rpc_id is not None and method == "session/request_permission":
            self._handle_permission_request(rpc_id, params)
            return
        if rpc_id is not None and method in {
            "_codebuddy.ai/question",
            "session/request_input",
            "elicitation/create",
        }:
            self._handle_user_input_request(rpc_id, method, params)
            return
        if rpc_id is not None:
            await self._answer_server_error(rpc_id, -32601, "client method not supported")

    def _handle_session_update(self, params: Mapping[str, Any]) -> None:
        update = params.get("update")
        if not isinstance(update, Mapping):
            return
        update_type = str(update.get("sessionUpdate") or "")
        session_id = str(params.get("sessionId") or self.thread_id or "") or None
        item_id = str(update.get("messageId") or update.get("toolCallId") or "") or None
        common = {
            "source": "codebuddy_acp",
            "thread_id": session_id,
            "turn_id": self.active_turn_id,
            "item_id": item_id,
        }
        if update_type == "agent_message_chunk":
            text = _content_text(update.get("content"))
            if text:
                self.store.append(
                    "agent_delta",
                    title="CodeBuddy 正在回复",
                    summary=text,
                    payload={"delta": text},
                    status="streaming",
                    **common,
                )
            return
        if update_type in {"agent_thought_chunk", "agent_thought"}:
            text = _content_text(update.get("content"))
            self.store.append(
                "reasoning_summary",
                title="CodeBuddy 正在推理",
                summary="已接收推理进度；隐藏推理内容不采集、不保存。",
                payload={
                    "content_collected": False,
                    "observed_characters": len(text),
                    "status": "streaming",
                },
                status="streaming",
                **common,
            )
            return
        if update_type == "plan":
            entries = update.get("entries")
            entries = entries if isinstance(entries, list) else []
            self._plan_steps = [
                {
                    "id": f"{self.active_turn_id or 'turn'}:step:{index}",
                    "index": index,
                    "title": redact_text(str(item.get("content") or f"步骤 {index}")),
                    "status": str(item.get("status") or "pending"),
                    "source": "agent_plan",
                }
                for index, item in enumerate(entries, 1)
                if isinstance(item, Mapping)
            ]
            self.store.append(
                "plan",
                title="CodeBuddy 更新了执行计划",
                summary="执行计划已更新",
                payload={"plan": self._plan_steps},
                status="updated",
                **common,
            )
            return
        if update_type in {"tool_call", "tool_call_update"}:
            status = str(update.get("status") or "pending")
            title = str(update.get("title") or update.get("name") or "调用办公工具")
            tool_id = str(update.get("toolCallId") or item_id or uuid.uuid4().hex)
            self._active_tool = (
                None
                if status in {"completed", "failed", "cancelled"}
                else {"item_id": tool_id, "title": redact_text(title), "status": status}
            )
            self.store.append(
                "tool",
                title=redact_text(title),
                summary=f"工具状态：{status}",
                payload={
                    "tool_call_id": tool_id,
                    "status": status,
                    "kind": update.get("kind"),
                    "locations": update.get("locations") or [],
                    "raw_input": update.get("rawInput"),
                    "content": update.get("content") or [],
                },
                status=status,
                **{**common, "item_id": tool_id},
            )
            return
        if update_type == "usage_update":
            self.store.append(
                "usage",
                title="CodeBuddy 更新上下文用量",
                summary=f"{update.get('used', 0)} / {update.get('size', 0)} tokens",
                payload={
                    "used": update.get("used"),
                    "size": update.get("size"),
                    "cost": update.get("cost"),
                    "source": "agent_reported_acp",
                },
                status="observed",
                **common,
            )
            return
        if update_type in {"current_model_update", "session_info_update"}:
            model = update.get("modelId") or update.get("model")
            if model:
                self.model = str(model)
            return
        # Preserve only the semantic update name. Unknown vendor payloads may
        # contain private reasoning and are intentionally not journaled.
        if update_type and update_type != "user_message_chunk":
            self.store.append(
                "agent_event",
                title="CodeBuddy 状态更新",
                summary=update_type,
                payload={"session_update": update_type, "raw_payload_collected": False},
                status="observed",
                **common,
            )

    def _handle_permission_request(
        self, rpc_id: int | str, params: Mapping[str, Any]
    ) -> None:
        options = params.get("options")
        options = options if isinstance(options, list) else []
        allowed = [
            dict(item)
            for item in options
            if isinstance(item, Mapping)
            and item.get("kind") in {"allow_once", "reject_once"}
        ]
        interaction_id = f"acp:{rpc_id}"
        tool_call = params.get("toolCall")
        tool_call = tool_call if isinstance(tool_call, Mapping) else {}
        public = {
            "id": interaction_id,
            "rpc_id": rpc_id,
            "kind": "approval",
            "method": "session/request_permission",
            "created_at": time.time(),
            "thread_id": params.get("sessionId"),
            "turn_id": self.active_turn_id,
            "item_id": tool_call.get("toolCallId"),
            "reason": tool_call.get("title") or "CodeBuddy 请求执行一次工具调用",
            "risk": {
                "level": "warning",
                "basis": "acp_permission_request",
                "matched_rules": [],
            },
            "explanation": {
                "headline": "CodeBuddy 请求一次性工具许可",
                "description": "灵眸不会提供永久允许选项。办公副作用仍需通过 MCP 两阶段网关。",
            },
            "evidence": {"availability": "agent_semantic_event"},
            "choices": ["accept", "decline", "cancel"],
            "options": allowed,
        }
        self._acp_interactions[interaction_id] = public
        self.store.append(
            "approval",
            title="CodeBuddy 等待一次性许可",
            summary=public["reason"],
            payload={"interaction_id": interaction_id, "options": allowed},
            source="codebuddy_acp",
            status="pending",
            thread_id=str(params.get("sessionId") or "") or None,
            turn_id=self.active_turn_id,
            item_id=str(tool_call.get("toolCallId") or "") or None,
        )

    def _handle_user_input_request(
        self, rpc_id: int | str, method: str, params: Mapping[str, Any]
    ) -> None:
        interaction_id = f"acp-input:{rpc_id}"
        self._acp_interactions[interaction_id] = {
            "id": interaction_id,
            "rpc_id": rpc_id,
            "kind": "user_input",
            "method": method,
            "created_at": time.time(),
            "thread_id": params.get("sessionId"),
            "turn_id": self.active_turn_id,
            "item_id": None,
            "reason": "CodeBuddy 需要补充信息",
            "questions": redact_event(params.get("questions") or params.get("message") or []),
            "risk": {"level": "normal", "basis": "acp_elicitation"},
            "explanation": {"headline": "Agent 等待你的补充"},
            "evidence": {"availability": "agent_semantic_event"},
            "choices": [],
        }

    async def _answer_server_request(self, rpc_id: int | str, result: Mapping[str, Any]) -> None:
        await self._post_frame({"jsonrpc": "2.0", "id": rpc_id, "result": dict(result)})

    async def _answer_server_error(
        self, rpc_id: int | str, code: int, message: str
    ) -> None:
        await self._post_frame(
            {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
        )

    async def _ensure_session(self) -> str:
        if self.thread_id:
            return self.thread_id
        result = await self._rpc(
            "session/new",
            {"cwd": os.fspath(self.repo), "mcpServers": [self.mcp_server]},
            timeout=60.0,
        )
        value = result if isinstance(result, Mapping) else {}
        session_id = str(value.get("sessionId") or "")
        if not session_id:
            raise WorkbenchError("CodeBuddy ACP session/new did not return sessionId")
        self.thread_id = session_id
        self.store.set_state("thread_id", session_id)
        self.store.append(
            "thread",
            title="已创建 CodeBuddy 会话",
            summary=session_id,
            source="codebuddy_acp",
            status="created",
            thread_id=session_id,
        )
        return session_id

    async def send_prompt(
        self, text: str, *, scenario_id: str | None = None
    ) -> dict[str, Any]:
        prompt = text.strip()
        if not prompt:
            raise WorkbenchError("提示词不能为空")
        if len(prompt.encode("utf-8")) > 128_000:
            raise WorkbenchError("提示词超过 128 KB 限制")
        requested = (scenario_id or self.runtime.scenario_id).upper()
        if requested != self.runtime.scenario_id:
            raise WorkbenchError(
                f"当前干净沙箱属于 {self.runtime.scenario_id}；切换场景请重新启动"
            )
        async with self._operation_lock:
            if not self.connected:
                raise WorkbenchError("CodeBuddy ACP 尚未连接")
            if self.active_turn_id:
                raise WorkbenchError("当前回合仍在运行")
            session_id = await self._ensure_session()
            turn_id = f"turn-{uuid.uuid4().hex}"
            self.active_turn_id = turn_id
            self.turn_status = "running"
            self._task_goal = prompt
            started_at = time.time()
            self.store.set_state("workbuddy_turn_started_at", started_at)
            self.store.append(
                "user_prompt",
                title="你提交了 WorkBuddy 任务",
                summary=prompt,
                payload={"text": prompt, "scenario_id": requested},
                source="user",
                status="submitted",
                thread_id=session_id,
                turn_id=turn_id,
            )
            self._prompt_task = asyncio.create_task(
                self._run_prompt(session_id, turn_id, prompt, requested),
                name=f"lingmou-codebuddy-prompt-{turn_id}",
            )
            return {"thread_id": session_id, "turn_id": turn_id, "scenario_id": requested}

    async def _run_prompt(
        self, session_id: str, turn_id: str, prompt: str, scenario_id: str
    ) -> None:
        status = "completed"
        stop_reason = "end_turn"
        try:
            response = await self._rpc(
                "session/prompt",
                {
                    "sessionId": session_id,
                    "prompt": [
                        {"type": "text", "text": prompt},
                        {"type": "text", "text": scenario_instruction(scenario_id)},
                    ],
                    "requestId": turn_id,
                },
            )
            value = response if isinstance(response, Mapping) else {}
            stop_reason = str(value.get("stopReason") or "end_turn")
            status = "interrupted" if stop_reason == "cancelled" else "completed"
        except asyncio.CancelledError:
            status = "interrupted"
            stop_reason = "cancelled"
            raise
        except Exception as exc:
            status = "failed"
            stop_reason = redact_text(str(exc))
        finally:
            await self._drain_outbox_once()
            self.store.append(
                "turn",
                title=("WorkBuddy 回合已完成" if status == "completed" else "WorkBuddy 回合已结束"),
                summary=stop_reason,
                payload={"stop_reason": stop_reason, "scenario_id": scenario_id},
                source="codebuddy_acp",
                status=status,
                thread_id=session_id,
                turn_id=turn_id,
            )
            self.store.append(
                "scenario_summary",
                title="本次业务结果",
                summary=self.runtime.scenario_result_summary(),
                payload={
                    "scenario_id": scenario_id,
                    "summary": self.runtime.scenario_result_summary(),
                },
                source="lingmou_workbuddy",
                status="completed" if status == "completed" else status,
                thread_id=session_id,
                turn_id=turn_id,
            )
            self.active_turn_id = None
            self.turn_status = status
            self._active_tool = None

    async def steer(self, text: str) -> dict[str, Any]:
        if not text.strip():
            raise WorkbenchError("steer 内容不能为空")
        raise WorkbenchError("CodeBuddy ACP v1 不支持运行中 steer；可停止后重新提交")

    async def interrupt(self) -> dict[str, Any]:
        if not self.connected or not self.thread_id or not self.active_turn_id:
            raise WorkbenchError("没有可停止的运行中回合")
        turn_id = self.active_turn_id
        await self._notify("session/cancel", {"sessionId": self.thread_id})
        self.turn_status = "interrupting"
        for interaction_id, interaction in list(self._acp_interactions.items()):
            if interaction.get("kind") == "approval":
                await self._answer_server_request(
                    interaction["rpc_id"], {"outcome": {"outcome": "cancelled"}}
                )
                self._acp_interactions.pop(interaction_id, None)
        return {"thread_id": self.thread_id, "turn_id": turn_id}

    async def respond_approval(self, interaction_id: str, decision: str) -> dict[str, Any]:
        if interaction_id.startswith("wb-"):
            try:
                result = await asyncio.to_thread(
                    self.runtime.decide, interaction_id, decision
                )
            except WorkBuddyActionError as exc:
                raise WorkbenchError(str(exc)) from exc
            await self._drain_outbox_once()
            return result
        interaction = self._acp_interactions.get(interaction_id)
        if interaction is None or interaction.get("kind") != "approval":
            raise WorkbenchError("审批请求不存在或已经处理")
        if decision == "acceptForSession":
            raise WorkbenchError("WorkBuddy 只允许逐次批准")
        if decision not in {"accept", "decline", "cancel"}:
            raise WorkbenchError("不支持的审批决定")
        if decision == "cancel":
            outcome: dict[str, Any] = {"outcome": "cancelled"}
        else:
            wanted = "allow_once" if decision == "accept" else "reject_once"
            option = next(
                (item for item in interaction.get("options", []) if item.get("kind") == wanted),
                None,
            )
            if option is None:
                raise WorkbenchError(f"CodeBuddy 没有提供 {wanted} 选项")
            outcome = {"outcome": "selected", "optionId": option["optionId"]}
        await self._answer_server_request(
            interaction["rpc_id"], {"outcome": outcome}
        )
        self._acp_interactions.pop(interaction_id, None)
        return {"id": interaction_id, "decision": decision}

    async def respond_user_input(
        self, interaction_id: str, answers: Mapping[str, list[str]]
    ) -> dict[str, Any]:
        interaction = self._acp_interactions.get(interaction_id)
        if interaction is None or interaction.get("kind") != "user_input":
            raise WorkbenchError("补充信息请求不存在或已经处理")
        await self._answer_server_request(
            interaction["rpc_id"], {"answers": redact_event(dict(answers))}
        )
        self._acp_interactions.pop(interaction_id, None)
        return {"id": interaction_id, "answered": True}

    async def _outbox_loop(self) -> None:
        while not self._closing:
            await self._drain_outbox_once()
            await asyncio.sleep(0.1)

    async def _drain_outbox_once(self) -> None:
        page = await asyncio.to_thread(
            self.runtime.drain_events, after_id=self._outbox_cursor, limit=500
        )
        for event in page["events"]:
            self._record_runtime_event(event)
            self._outbox_cursor = max(self._outbox_cursor, int(event["id"]))

    def _record_runtime_event(self, event: Mapping[str, Any]) -> None:
        record_workbuddy_runtime_event(
            store=self.store,
            runtime=self.runtime,
            event=event,
            os_audit=self.os_audit,
            thread_id=self.thread_id,
            turn_id=self.active_turn_id,
        )

    def _fail_pending(self, exc: BaseException) -> None:
        for future in tuple(self._rpc_pending.values()):
            if not future.done():
                future.set_exception(exc)


__all__ = [
    "ACP_PROTOCOL_VERSION",
    "CodeBuddyACPAdapter",
    "parse_sse_lines",
]
