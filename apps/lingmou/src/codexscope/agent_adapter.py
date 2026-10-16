"""Shared contract for Agent backends exposed by the Lingmou workbench."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable


@runtime_checkable
class AgentAdapter(Protocol):
    """Minimal lifecycle and interaction surface used by the HTTP workbench."""

    def snapshot(self) -> dict[str, Any]: ...

    async def start_background(self) -> None: ...

    async def stop(self) -> None: ...

    async def send_prompt(
        self, text: str, *, scenario_id: str | None = None
    ) -> dict[str, Any]: ...

    async def steer(self, text: str) -> dict[str, Any]: ...

    async def interrupt(self) -> dict[str, Any]: ...

    async def respond_approval(
        self, interaction_id: str, decision: str
    ) -> dict[str, Any]: ...

    async def respond_user_input(
        self, interaction_id: str, answers: Mapping[str, list[str]]
    ) -> dict[str, Any]: ...


__all__ = ["AgentAdapter"]
