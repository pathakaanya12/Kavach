"""Kavach Tool Decorator.

Wraps any Python function tool with Kavach pre-execution inspection.
Usage:
    # Production mode (server-anchored session):
    @protect(client, session_id_getter=lambda: current_session_id)
    def my_tool(arg1, arg2):
        ...

    # Dev/testing mode (deprecated client-supplied task):
    @protect(client, get_task=lambda: current_user_task)
    def my_tool(arg1, arg2):
        ...
"""

import functools
import inspect
import warnings
from typing import Callable, Any, Optional
from sdk.kavach_client import KavachClient, KavachBlockedException

def protect(
    client: KavachClient,
    session_id_getter: Optional[Callable[[], str]] = None,
    get_task: Optional[Callable[[], str]] = None,
    run_id_getter: Optional[Callable[[], str]] = None
):
    """Decorator to protect any Python tool with Kavach task-alignment and policy checking."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            tool_args = bound.arguments

            tool_name = func.__name__
            session_id = session_id_getter() if session_id_getter else None
            run_id = run_id_getter() if run_id_getter else (session_id or "sdk-run")

            user_task = None
            if get_task and not session_id:
                warnings.warn(
                    "Passing get_task to @protect is deprecated in production. "
                    "Use server-anchored sessions via client.start_session() and session_id_getter.",
                    DeprecationWarning,
                    stacklevel=2
                )
                user_task = get_task()

            verdict = client.check(
                session_id=session_id,
                run_id=run_id,
                user_task=user_task,
                tool=tool_name,
                args=tool_args
            )

            decision = verdict.get("decision", "allow")
            if decision == "block":
                raise KavachBlockedException(f"Kavach Blocked '{tool_name}': {verdict.get('reason')}")
            elif decision == "ask":
                raise KavachBlockedException(f"Kavach Pending Approval for '{tool_name}': {verdict.get('reason')}")

            return func(*args, **kwargs)
        return wrapper
    return decorator
