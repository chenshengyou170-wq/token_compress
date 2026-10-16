"""Opt-in CodexScope Python runtime bootstrap.

This module is visible only when ``codexscope run --function-trace`` prepends
this directory to ``PYTHONPATH``. Tracer failures must never make a target
interpreter fail; errors from the target's own later ``sitecustomize`` retain
their normal CPython behavior.
"""


def _chain_existing_sitecustomize():
    # Prepending our bootstrap would otherwise silently mask a sitecustomize in
    # a later sys.path entry. Preserve its real module name/spec and leave it in
    # sys.modules, matching what a normal ``import sitecustomize`` would expose.
    import importlib.machinery
    import importlib.util
    import os
    import sys

    here = os.path.realpath(os.path.dirname(__file__))
    search = [
        entry for entry in sys.path if os.path.realpath(entry or os.curdir) != here
    ]
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", search)
    if spec is None:
        return
    same_origin = isinstance(spec.origin, str) and os.path.realpath(
        spec.origin
    ) == os.path.realpath(__file__)
    if same_origin:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules["sitecustomize"] = module
    try:
        if spec.loader is not None:
            spec.loader.exec_module(module)
    except BaseException:
        if sys.modules.get("sitecustomize") is module:
            del sys.modules["sitecustomize"]
        raise


def _activate_tracer():
    try:
        from _codexscope_function_trace_runtime import activate

        activate()
    except BaseException:
        # Only CodexScope instrumentation is fail-open. The target's own
        # sitecustomize exceptions are deliberately not swallowed here.
        pass


try:
    _chain_existing_sitecustomize()
except BaseException:
    _activate_tracer()
    raise
else:
    _activate_tracer()
