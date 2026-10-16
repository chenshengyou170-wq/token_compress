"""Self-contained CPython frame profiler used by the sitecustomize shim.

Keep this module stdlib-only and conservative: it may be imported by a Python
interpreter different from the one running CodexScope.
"""

import atexit
import errno
import json
import os
import socket
import sys
import threading
import time


_SCHEMA = "codexscope.function_trace.v1"
_EXCLUDED_PARTS = frozenset(
    (".git", ".venv", "venv", "node_modules", "__pycache__")
)
_MAX_TEXT = 1000
_MAX_DEPTH = 512
_MAX_CODE_CACHE = 16384
_BOOTSTRAP_ROOT = os.path.realpath(os.path.dirname(__file__))
_SUPPRESS_ENV = "CODEXSCOPE_FUNCTION_TRACE_SUPPRESS"

_active = False
_accept_new = True
_transport_dead = False
_owner_pid = None
_process_instance_id = None
_root = None
_startup_cwd = None
_socket_path = None
_socket = None
_max_calls = 100000
_call_counter = 0
_process_sequence = 0
_record_counter = 0
_dropped = 0
_open_activations = 0
_limit_sent = False
_code_cache = {}
_state = threading.local()
_session_open = False
_shutdown_done = False
_shutdown_in_progress = False
_atexit_registered = False
_atfork_registered = False


def _bounded(value):
    if not isinstance(value, str):
        return None
    return value[:_MAX_TEXT]


def _native_thread_id():
    getter = getattr(threading, "get_native_id", None)
    if getter is not None:
        return int(getter())
    return int(threading.current_thread().ident or 0)


def _process_start_marker(pid):
    try:
        with open("/proc/%d/stat" % pid, "r") as stream:
            value = stream.read()
        fields = value[value.rfind(")") + 2 :].split()
        return fields[19]
    except BaseException:
        return str(time.monotonic_ns())


def _new_process_identity():
    global _owner_pid, _process_instance_id
    pid = os.getpid()
    _owner_pid = pid
    try:
        generation = os.urandom(12).hex()
    except BaseException:
        generation = "%x-%x" % (time.monotonic_ns(), id(object()))
    _process_instance_id = "%d:%s:%s" % (
        pid,
        _process_start_marker(pid),
        generation,
    )


def _new_socket():
    global _socket, _transport_dead
    if _socket is not None:
        try:
            _socket.close()
        except BaseException:
            pass
    _socket = None
    _transport_dead = False
    sender = None
    try:
        sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sender.setblocking(False)
        sender.connect(_socket_path)
        _socket = sender
    except BaseException:
        if sender is not None:
            try:
                sender.close()
            except BaseException:
                pass
        _transport_dead = True


def _close_socket():
    global _socket, _transport_dead
    sender = _socket
    _socket = None
    _transport_dead = True
    if sender is not None:
        try:
            sender.close()
        except BaseException:
            pass


def _send(kind, fields=None, force=False):
    global _process_sequence, _record_counter, _dropped, _transport_dead
    if (_transport_dead or _socket is None) and not force:
        _dropped += 1
        return False
    _process_sequence += 1
    row = {
        "schema": _SCHEMA,
        "kind": kind,
        "backend": "python_profile",
        "language": "python",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "process_instance_id": _process_instance_id,
        "runtime_thread_id": _native_thread_id(),
        "process_seq": _process_sequence,
        "monotonic_ns": time.monotonic_ns(),
        "wall_time_ns": time.time_ns(),
        "dropped_before": _dropped,
    }
    if fields:
        row.update(fields)
    try:
        encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(encoded) > 16000:
            raise ValueError("runtime record exceeds datagram bound")
        _socket.send(encoded)
    except BaseException:
        _dropped += 1
        error = getattr(sys, "exc_info")()[1]
        if isinstance(error, OSError) and error.errno in (
            errno.ENOENT,
            errno.ECONNREFUSED,
            errno.EACCES,
            errno.EBADF,
        ):
            _transport_dead = True
        return False
    _record_counter += 1
    return True


def _relative_code(code):
    cached = _code_cache.get(code, ...)
    if cached is not ...:
        return cached
    filename = getattr(code, "co_filename", None)
    result = None
    if isinstance(filename, str) and filename and not filename.startswith("<"):
        try:
            absolute = os.path.realpath(
                filename
                if os.path.isabs(filename)
                else os.path.join(_startup_cwd, filename)
            )
            common = os.path.commonpath((_root, absolute))
            bootstrap_common = os.path.commonpath((_BOOTSTRAP_ROOT, absolute))
            if common == _root and bootstrap_common != _BOOTSTRAP_ROOT:
                relative = os.path.relpath(absolute, _root)
                if not any(part in _EXCLUDED_PARTS for part in relative.split(os.sep)):
                    result = relative.replace(os.sep, "/")
        except (OSError, ValueError):
            pass
    if len(_code_cache) >= _MAX_CODE_CACHE:
        _code_cache.clear()
    _code_cache[code] = result
    return result


def _code_kind(code):
    flags = int(getattr(code, "co_flags", 0))
    if flags & 0x200:
        return "async_generator"
    if flags & 0x80:
        return "coroutine"
    if flags & 0x20:
        return "generator"
    return "function"


def _thread_state():
    value = getattr(_state, "value", None)
    if value is None:
        value = {"stack": [], "suppressed": set(), "busy": False}
        _state.value = value
    return value


def _profile(frame, event, arg):
    del arg
    global _active, _accept_new, _call_counter, _open_activations, _limit_sent
    if not _active or event not in ("call", "return"):
        return
    state = _thread_state()
    if state["busy"]:
        return
    state["busy"] = True
    try:
        # A Python ``after_in_child`` handler produces a profile call event
        # before its body runs.  Filter our bootstrap frame first; otherwise
        # PID fallback would reset the child here and the handler would reset it
        # a second time immediately afterwards.
        relative = _relative_code(frame.f_code)
        if relative is None:
            return
        if os.getpid() != _owner_pid:
            _after_fork_child()
            state = _thread_state()
            state["busy"] = True
        frame_id = id(frame)
        if event == "call":
            if not _accept_new or len(state["stack"]) >= _MAX_DEPTH:
                state["suppressed"].add(frame_id)
                return
            if _call_counter >= _max_calls:
                _accept_new = False
                state["suppressed"].add(frame_id)
                if not _limit_sent:
                    _limit_sent = True
                    _send("limit_reached", {"max_calls": _max_calls})
                return
            _call_counter += 1
            native_thread = _native_thread_id()
            activation = "%s:t%d:a%d" % (
                _process_instance_id,
                native_thread,
                _call_counter,
            )
            parent = state["stack"][-1][1] if state["stack"] else None
            state["stack"].append((frame_id, activation))
            _open_activations += 1
            code = frame.f_code
            module = frame.f_globals.get("__name__")
            _send(
                "frame_enter",
                {
                    "activation_id": activation,
                    "caller_activation_id": parent,
                    "path": relative,
                    "qualname": _bounded(
                        getattr(code, "co_qualname", None)
                        or getattr(code, "co_name", "<unknown>")
                    ),
                    "first_line": int(getattr(code, "co_firstlineno", 0) or 0),
                    "module": _bounded(module),
                    "code_kind": _code_kind(code),
                },
            )
            return

        if frame_id in state["suppressed"]:
            state["suppressed"].discard(frame_id)
            return
        match = None
        for index in range(len(state["stack"]) - 1, -1, -1):
            if state["stack"][index][0] == frame_id:
                match = index
                break
        if match is None:
            return
        if match != len(state["stack"]) - 1:
            orphaned = len(state["stack"]) - match - 1
            del state["stack"][match + 1 :]
            _open_activations = max(0, _open_activations - orphaned)
            _send("stack_resync", {"orphaned_activations": orphaned})
        _frame_id, activation = state["stack"].pop()
        _open_activations = max(0, _open_activations - 1)
        _send(
            "frame_exit",
            {
                "activation_id": activation,
                "path": relative,
                "qualname": _bounded(
                    getattr(frame.f_code, "co_qualname", None)
                    or getattr(frame.f_code, "co_name", "<unknown>")
                ),
                "first_line": int(
                    getattr(frame.f_code, "co_firstlineno", 0) or 0
                ),
                "current_line": int(getattr(frame, "f_lineno", 0) or 0),
            },
        )
    except BaseException as error:
        # Keep diagnostics fail-open for the target, but do not leave an
        # inactive callback installed on every subsequent Python frame.
        _finish_session("profile_callback_failed", error)
    finally:
        try:
            state["busy"] = False
        except BaseException:
            pass


def _after_fork_child():
    global _state, _call_counter, _process_sequence, _record_counter, _dropped
    global _open_activations, _accept_new, _limit_sent, _code_cache
    global _session_open, _shutdown_done, _shutdown_in_progress
    if not _active:
        return
    _state = threading.local()
    _call_counter = 0
    _process_sequence = 0
    _record_counter = 0
    _dropped = 0
    _open_activations = 0
    _accept_new = True
    _limit_sent = False
    _code_cache = {}
    _session_open = False
    _shutdown_done = False
    _shutdown_in_progress = False
    _new_process_identity()
    _new_socket()
    _session_open = not _transport_dead and _socket is not None
    _send(
        "process_start",
        {
            "python_version": "%d.%d.%d" % sys.version_info[:3],
            "implementation": getattr(sys.implementation, "name", "unknown"),
            "fork_child": True,
        },
        force=True,
    )


def _remove_our_profiles():
    try:
        if sys.getprofile() is _profile:
            sys.setprofile(None)
    except BaseException:
        pass
    try:
        get_thread_profile = getattr(threading, "getprofile", None)
        if get_thread_profile is not None and get_thread_profile() is _profile:
            threading.setprofile(None)
    except BaseException:
        pass


def _finish_session(reason, error=None):
    global _active, _accept_new, _session_open
    global _shutdown_done, _shutdown_in_progress
    if _shutdown_done or _shutdown_in_progress:
        return
    _shutdown_in_progress = True
    _active = False
    _accept_new = False
    try:
        _remove_our_profiles()
        if error is not None:
            _send(
                "backend_error",
                {
                    "stage": reason,
                    "error_type": _bounded(type(error).__name__),
                },
                force=True,
            )
        if _session_open or _socket is not None:
            _send(
                "process_end",
                {
                    "reason": reason,
                    "calls_started": _call_counter,
                    "open_activations": _open_activations,
                    "records_sent": _record_counter,
                    "records_dropped": _dropped,
                },
                force=True,
            )
    except BaseException:
        pass
    finally:
        _close_socket()
        _session_open = False
        _shutdown_done = True
        _shutdown_in_progress = False


def _shutdown():
    _finish_session("interpreter_shutdown")


def _profiles_are_available():
    try:
        if sys.getprofile() is not None:
            return False
        get_thread_profile = getattr(threading, "getprofile", None)
        if get_thread_profile is None or get_thread_profile() is not None:
            return False
    except BaseException:
        return False
    return True


def _suppressed_by_environment():
    try:
        return os.environ.get(_SUPPRESS_ENV, "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    except BaseException:
        return True


def _register_lifecycle_handlers():
    global _atexit_registered, _atfork_registered
    if not _atexit_registered:
        try:
            atexit.register(_shutdown)
            _atexit_registered = True
        except BaseException:
            pass
    if not _atfork_registered and hasattr(os, "register_at_fork"):
        try:
            os.register_at_fork(after_in_child=_after_fork_child)
            _atfork_registered = True
        except BaseException:
            pass


def activate():
    global _active, _accept_new, _root, _startup_cwd, _socket_path, _max_calls
    global _session_open, _shutdown_done, _shutdown_in_progress
    if _active or getattr(sys.implementation, "name", "") != "cpython":
        return
    if _suppressed_by_environment():
        return
    languages = os.environ.get("CODEXSCOPE_FUNCTION_TRACE", "")
    if "python" not in [part.strip() for part in languages.split(",")]:
        return
    root = os.environ.get("CODEXSCOPE_FUNCTION_ROOT")
    socket_path = os.environ.get("CODEXSCOPE_FUNCTION_SOCKET")
    if not root or not socket_path:
        return
    if not _profiles_are_available():
        return
    _root = os.path.realpath(root)
    try:
        _startup_cwd = os.path.realpath(os.getcwd())
    except BaseException:
        _startup_cwd = _root
    _socket_path = socket_path
    try:
        _max_calls = max(
            1,
            min(
                10000000,
                int(os.environ.get("CODEXSCOPE_FUNCTION_MAX_CALLS", "100000")),
            ),
        )
    except (TypeError, ValueError):
        _max_calls = 100000
    _accept_new = True
    _session_open = False
    _shutdown_done = False
    _shutdown_in_progress = False
    _new_process_identity()
    _new_socket()
    if _transport_dead:
        return
    _session_open = True
    _send(
        "process_start",
        {
            "python_version": "%d.%d.%d" % sys.version_info[:3],
            "implementation": getattr(sys.implementation, "name", "unknown"),
            "run_id": _bounded(os.environ.get("CODEXSCOPE_FUNCTION_RUN_ID")),
        },
    )
    _active = True
    try:
        threading.setprofile(_profile)
        sys.setprofile(_profile)
    except BaseException as error:
        # Roll back both callback slots if either installation was partial.
        _finish_session("profile_install_failed", error)
        return
    _register_lifecycle_handlers()
