"""Reversible, comment-preserving Codex configuration for the desktop relay.

No login file is read. Provider credentials stay in Codex's existing provider
configuration. Original/applied snapshots are private recovery material and are
never sent to the renderer. Only the fields owned by this connection are undone.
"""
from __future__ import annotations

import copy
import hashlib
import os
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .storage import atomic_json_dump, json_load


MODES = ("off", "structure", "extract", "auto", "full")
CHATGPT_UPSTREAM = "https://chatgpt.com/backend-api/codex"
API_UPSTREAM = "https://api.openai.com/v1"
MAX_CONFIG_BYTES = 2 * 1024 * 1024
RELAY_PATH = "/lingmou-relay/"


class ConnectionError(ValueError):
    """An actionable message safe to show without configuration contents."""


@contextmanager
def file_lock(path: Path):
    """An OS-owned lock releases on process death, including on Windows."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ConnectionError("配置或后台服务正在被另一进程使用，请稍后重试。") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def default_codex_config() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return (Path(configured).expanduser() if configured else Path.home() / ".codex") / "config.toml"


def config_path(value: str | None = None) -> Path:
    path = Path(value).expanduser() if value else default_codex_config()
    if not path.is_absolute() or path.suffix.lower() != ".toml":
        raise ConnectionError("请选择 Codex 使用的 TOML 配置文件的绝对路径。")
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ConnectionError("配置文件必须是普通文件；请直接选择实际文件。")
    return path


def _read(path: Path) -> bytes:
    if not path.exists():
        return b""
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConnectionError("Codex 配置文件超过 2 MB，请先检查文件。")
    return path.read_bytes()


def _parse(raw: bytes):
    try:
        import tomlkit
    except ImportError as exc:
        raise ConnectionError("后台缺少 tomlkit。源码运行请安装项目的 desktop 可选依赖。") from exc
    try:
        return tomlkit.parse(raw.decode("utf-8-sig"))
    except Exception as exc:
        # Parser errors may include a credential-bearing source line.
        raise ConnectionError("Codex 配置不是有效的 UTF-8 TOML，请先在编辑器中修复。") from exc


def validate_upstream(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise ConnectionError("请输入有效的模型服务地址。")
    try:
        url = urlsplit(value.strip())
        url.port
    except ValueError as exc:
        raise ConnectionError("模型服务地址格式不正确。") from exc
    if (not url.hostname or url.username is not None or url.password is not None
            or url.query or url.fragment or url.scheme not in {"http", "https"}
            or url.scheme == "http" and url.hostname not in {"127.0.0.1", "localhost", "::1"}
            or "\\" in value):
        raise ConnectionError("上游需使用 HTTPS；仅本机地址允许 HTTP。地址中不能包含凭据、查询或片段。")
    return value.strip().rstrip("/")


def inspect_codex(value: str | None = None) -> dict:
    path = config_path(value)
    document = _parse(_read(path))
    selected = document.get("model_provider", "openai")
    if not isinstance(selected, str):
        raise ConnectionError("model_provider 必须是字符串。")
    providers = document.get("model_providers", {})
    if not hasattr(providers, "get"):
        raise ConnectionError("model_providers 必须是 TOML 表。")
    provider = providers.get(selected, {})
    upstream = (document.get("openai_base_url") if selected == "openai"
                else provider.get("base_url") if hasattr(provider, "get") else None)
    if not isinstance(upstream, str):
        upstream = ""
    if upstream:
        upstream = validate_upstream(upstream)
    if selected.startswith("lingmou_desktop_") or RELAY_PATH in upstream:
        raise ConnectionError("此配置已接入灵眸。请使用原来的灵眸数据目录恢复连接，避免重复覆盖。")
    return {
        "config_path": str(path), "exists": path.exists(), "provider": selected,
        "upstream": upstream, "custom_provider": selected != "openai",
        "model": str(document.get("model", "使用 Codex 当前模型"))[:160],
        "notice": "仅调整此配置中的默认连接；命令行参数、其他 profile 和组织托管配置可能覆盖它。接入后以收到请求为准。",
    }


def _lookup(document, parts):
    value = document
    for part in parts:
        if not hasattr(value, "get") or part not in value:
            return False, None
        value = value[part]
    return True, value.unwrap() if hasattr(value, "unwrap") else value


def _set(document, parts, value):
    import tomlkit
    node = document
    for part in parts[:-1]:
        if part not in node:
            node[part] = tomlkit.table()
        node = node[part]
    node[parts[-1]] = copy.deepcopy(value)


def _remove(document, parts):
    node = document
    for part in parts[:-1]:
        if part not in node:
            return
        node = node[part]
    node.pop(parts[-1], None)


class CodexConnection:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / "connection.json"
        self.record = json_load(self.path) if self.path.exists() else None
        if self.record is not None and not isinstance(self.record, dict):
            raise ConnectionError("连接恢复记录损坏；请保留数据目录并检查备份。")

    @property
    def enabled(self):
        return bool(self.record and self.record.get("phase") in {"prepared", "connected", "restoring"})

    @property
    def directory(self):
        return self.root / "connections" / self.record["id"]

    def _save(self):
        atomic_json_dump(self.path, self.record)

    def paths(self):
        if self.record.get("version", 1) >= 2:
            return [tuple(parts) for parts in self.record["owned_paths"]]
        if self.record.get("legacy_alias_only"):
            return [("model_providers", self.record["provider"])]
        return [("model_provider",), ("model_providers", self.record["provider"]),
                ("mcp_servers", self.record["source_server"]), ("features", "enable_request_compression")]

    def prepare(self, *, path: str, auth_kind: str, upstream: str, mode: str,
                source_command: str, source_args: list[str], remote_enabled: bool = False) -> dict:
        if self.enabled:
            raise ConnectionError("请先解除当前接入，再连接其他配置。")
        if mode not in MODES or auth_kind not in {"chatgpt", "api", "existing"}:
            raise ConnectionError("不支持的压缩模式或登录方式。")
        if type(remote_enabled) is not bool:
            raise ConnectionError("远程改写开关必须为布尔值。")
        target = config_path(path)
        raw = _read(target)
        original = _parse(raw)
        selected = original.get("model_provider", "openai")
        if not isinstance(selected, str) or selected.startswith("lingmou_desktop_"):
            raise ConnectionError("配置已经接入灵眸或 provider 无效，请先恢复原连接。")
        providers = original.get("model_providers", {})
        if not hasattr(providers, "get"):
            raise ConnectionError("model_providers 必须是 TOML 表。")
        if selected == "openai":
            # Built-in provider IDs cannot be overridden by model_providers.
            # Keep the identity saved in thread metadata; only route its URL.
            existing_url = original.get("openai_base_url", "")
            if not isinstance(existing_url, str):
                raise ConnectionError("openai_base_url 必须是字符串。")
            if auth_kind == "existing" and not existing_url:
                raise ConnectionError("当前没有自定义上游，请选择与 Codex 登录一致的方式。")
            upstream = upstream or existing_url or (CHATGPT_UPSTREAM if auth_kind == "chatgpt" else API_UPSTREAM)
            owned_paths = [("openai_base_url",)]
        elif auth_kind == "existing":
            existing = providers.get(selected)
            if not hasattr(existing, "get") or not existing.get("base_url"):
                raise ConnectionError("当前 provider 没有可复用的 base_url，请选择与 Codex 登录一致的方式。")
            if existing.get("wire_api", "responses") != "responses":
                raise ConnectionError("此 Codex 接入器只支持 Responses provider。")
            upstream = str(existing["base_url"])
            provider = copy.deepcopy(existing)
            headers = provider.get("http_headers", {})
            environment_headers = provider.get("env_http_headers", {})
            if (not hasattr(headers, "get") or not hasattr(environment_headers, "get")
                    or any(key.lower() == "x-lingmou-relay-token" for key in (*headers, *environment_headers))):
                raise ConnectionError("原 provider 已使用灵眸连接标识或请求头配置无效，请先恢复原连接。")
            if (urlsplit(upstream).hostname == "chatgpt.com"
                    and provider.get("requires_openai_auth") is not True):
                raise ConnectionError("ChatGPT 上游需要 requires_openai_auth = true。请先修复原 provider 的登录配置，避免 401。")
            owned_paths = [("model_providers", selected, field)
                           for field in ("base_url", "supports_websockets")]
            owned_paths.append(("model_providers", selected, "http_headers", "X-Lingmou-Relay-Token"))
        else:
            raise ConnectionError("当前使用自定义 provider，请选择“保留现有供应商”以保留鉴权设置。")
        upstream = validate_upstream(upstream)
        if RELAY_PATH in upstream:
            raise ConnectionError("此配置已接入灵眸，请使用原来的数据目录解除接入，避免重复代理。")
        identifier = secrets.token_hex(12)
        source_server = f"lingmou_desktop_sources_{identifier}"
        owned_paths += [("mcp_servers", source_server), ("features", "enable_request_compression")]
        self.record = {
            "version": 2, "id": identifier, "phase": "prepared", "config_path": str(target),
            "config_existed": target.exists(), "original_digest": hashlib.sha256(raw).hexdigest(),
            "original_provider": selected, "auth_kind": auth_kind, "upstream": upstream,
            "provider": selected, "source_server": source_server, "owned_paths": owned_paths,
            "path_auth": selected == "openai",
            "access_token": secrets.token_urlsafe(32), "port": 0, "mode": mode,
            "remote_enabled": remote_enabled,
            "source_command": source_command, "source_args": source_args,
        }
        atomic_bytes(self.directory / "original.toml", raw)
        self._save()
        return self.record

    def apply(self, port: int) -> None:
        import tomlkit
        target = config_path(self.record["config_path"])
        with file_lock(target.with_name(f".{target.name}.lingmou.lock")):
            raw = _read(target)
            if hashlib.sha256(raw).hexdigest() != self.record["original_digest"]:
                raise ConnectionError("Codex 配置在接入期间被其他程序修改，请重新读取后再接入。")
            document = _parse(raw)
            local_url = f"http://127.0.0.1:{port}"
            if self.record["path_auth"]:
                # OpenAI's built-in provider has no configurable relay header.
                # The local capability is stripped before forwarding upstream.
                local_url += RELAY_PATH + self.record["access_token"]
            local_url += urlsplit(self.record["upstream"]).path
            if self.record["provider"] == "openai":
                _set(document, ("openai_base_url",), local_url)
            else:
                prefix = ("model_providers", self.record["provider"])
                _set(document, (*prefix, "base_url"), local_url)
                _set(document, (*prefix, "supports_websockets"), False)
                _set(document, (*prefix, "http_headers", "X-Lingmou-Relay-Token"), self.record["access_token"])
            _set(document, ("features", "enable_request_compression"), False)
            _set(document, ("mcp_servers", self.record["source_server"]), {
                "command": self.record["source_command"],
                "args": [*self.record["source_args"], "--store", str(self.directory / "sources")],
                "startup_timeout_sec": 20,
            })
            applied = tomlkit.dumps(document).encode("utf-8")
            # Persist the recovery journal before switching the user's config.
            atomic_bytes(self.directory / "applied.toml", applied)
            self.record["port"] = port
            self._save()
            atomic_bytes(target, applied)
            self.record["phase"] = "connected"
            self._save()

    def recover(self) -> None:
        if (self.record and self.record.get("version", 1) < 2
                and not self.record.get("legacy_provider_preserved")
                and (self.directory / "applied.toml").exists()):
            self.restore()
            return
        if not self.enabled:
            return
        if self.record.get("version", 1) < 2:
            # Upgrade old journals without resuming the temporary provider.
            # Its direct upstream alias keeps already-created threads usable.
            self.restore()
            return
        target = config_path(self.record["config_path"])
        current = _parse(_read(target))
        original = _parse((self.directory / "original.toml").read_bytes())
        if all(_lookup(current, parts) == _lookup(original, parts) for parts in self.paths()):
            self.record["phase"] = "disconnected"
            self._save()
        elif not (self.directory / "applied.toml").exists():
            raise ConnectionError("接入尚未完成且配置已变化，请先检查配置与恢复备份。")
        else:
            # An interrupted apply/restore is recoverable using the same port.
            self.record["phase"] = "connected"
            self._save()

    def restore(self) -> None:
        import tomlkit
        if not self.enabled:
            if (not self.record or self.record.get("version", 1) >= 2
                    or self.record.get("legacy_provider_preserved")
                    or not (self.directory / "applied.toml").exists()):
                return
            # Old versions already removed their provider on exit. Repair only
            # that known alias from our journal, leaving current preferences as
            # they are. Never scan or rewrite user rollouts or the thread DB.
            self.record["legacy_alias_only"] = True
        target = config_path(self.record["config_path"])
        with file_lock(target.with_name(f".{target.name}.lingmou.lock")):
            raw = _read(target)
            current = _parse(raw)
            original_raw = (self.directory / "original.toml").read_bytes()
            original = _parse(original_raw)
            applied_path = self.directory / "applied.toml"
            applied = _parse(applied_path.read_bytes()) if applied_path.exists() else original
            desired = copy.deepcopy(original)
            legacy = self.record.get("version", 1) < 2 and applied_path.exists()
            if legacy:
                selected = self.record["original_provider"]
                if selected == "openai":
                    alias = {"name": "OpenAI", "requires_openai_auth": True, "wire_api": "responses",
                             "base_url": original.get("openai_base_url") or self.record["upstream"]}
                else:
                    alias = original.get("model_providers", {}).get(selected)
                    if not hasattr(alias, "get") or not alias.get("base_url"):
                        raise ConnectionError("旧版连接缺少原供应商备份，请保留数据目录并检查 original.toml。")
                _set(desired, ("model_providers", self.record["provider"]), alias)
            conflicts = [".".join(parts) for parts in self.paths()
                         if _lookup(current, parts) not in (_lookup(applied, parts), _lookup(original, parts),
                                                           _lookup(desired, parts))]
            if conflicts:
                raise ConnectionError("这些接入字段已被修改，未覆盖你的修改：" + "、".join(conflicts)
                                      + "。请查看配置备份，恢复这些字段后再解除接入。")
            self.record["phase"] = "restoring"
            self._save()
            if not legacy and applied_path.exists() and raw == applied_path.read_bytes():
                restored = original_raw
            else:
                for parts in self.paths():
                    exists, _ = _lookup(desired, parts)
                    if exists:
                        value = desired
                        for part in parts:
                            value = value[part]
                        _set(current, parts, value)
                    else:
                        _remove(current, parts)
                        # Prune only containers introduced by this connection.
                        for length in range(len(parts) - 1, 0, -1):
                            parent = parts[:length]
                            present, value = _lookup(current, parent)
                            if present and not value and not _lookup(original, parent)[0]:
                                _remove(current, parent)
                for parent in ("model_providers", "mcp_servers", "features"):
                    if parent not in original and parent in current and not current[parent]:
                        del current[parent]
                restored = tomlkit.dumps(current).encode("utf-8")
            atomic_bytes(target, restored)
            if legacy:
                self.record["legacy_provider_preserved"] = True
            self.record["phase"] = "disconnected"
            self._save()

    def public(self):
        record = self.record
        if record is None:
            return None
        return {key: record[key] for key in ("id", "phase", "config_path", "original_provider", "auth_kind", "upstream", "port", "mode")} | {
            "remote_enabled": record.get("remote_enabled", False) is True,
            "legacy_provider_preserved": record.get("legacy_provider_preserved", False) is True,
            "backup_path": str(self.directory / "original.toml"),
            "sources_path": str(self.directory / "sources"),
        }
