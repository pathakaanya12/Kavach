"""V2: destructive-action guard + kill switch (offline / scripted)."""
import asyncio
import os

os.environ["KAVACH_OFFLINE"] = "1"
os.environ["AGENT_PLANNER"] = "scripted"
os.environ["DEMO_ATTACK_PERSISTS"] = "1"

from kavach_engine.policy import evaluate_policy, is_destructive
from kavach_engine.audit import reset_audit_log
from agent.guard import KavachGuard
import agent.tools as fake_tools


def test_delete_file_is_destructive():
    assert is_destructive("delete_file", {"file": "project_report.pdf"}) is True
    assert is_destructive("drop_table", {"table": "customers"}) is True
    assert is_destructive("pay_bill", {"payee": "Delhi Power Board", "amount": 3420}) is False
    assert is_destructive("send_email", {"to": "karan.mehta@brightpath.example"}) is False


def test_destructive_call_always_asks():
    # Even when the user task itself mentions deleting, a human must approve.
    decision, reason, hits = evaluate_policy(
        "delete_file", {"file": "project_report.pdf"}, [], ["email:1"])
    assert decision == "ask"
    assert "destructive_action" in hits


def test_destructive_sql_in_args_asks():
    decision, _, hits = evaluate_policy(
        "sql_query", {"query": "DROP TABLE customers"}, [], [])
    assert decision == "ask"
    assert "destructive_action" in hits


def test_guard_blocks_destructive_without_approval():
    async def _run():
        reset_audit_log(keep_disk=False)
        events = []

        async def deny(*_a, **_k):
            return "block"

        fake_tools.set_tool_callbacks(emitter=lambda e: events.append(e))
        guard = KavachGuard(run_id="destr-1", user_task="Delete the old report",
                            is_active=True, event_emitter=lambda e: events.append(e),
                            approval_handler=deny)
        res = await guard.call("delete_file", {"file": "project_report.pdf"})
        assert res.get("status") == "blocked"
        # The fake tool never ran: no tool_execution event for delete_file.
        assert not any(e.get("data", {}).get("tool") == "delete_file"
                       for e in events if e.get("type") == "tool_execution")
        reset_audit_log(keep_disk=False)

    asyncio.run(_run())


def test_kill_switch_stops_tool_calls():
    async def _run():
        reset_audit_log(keep_disk=False)
        events = []
        fake_tools.set_tool_callbacks(emitter=lambda e: events.append(e))
        guard = KavachGuard(run_id="kill-1", user_task="Pay the bill",
                            is_active=True, event_emitter=lambda e: events.append(e),
                            kill_check=lambda: True)
        res = await guard.call("pay_bill", {"payee": "Delhi Power Board",
                                            "amount": 3420, "reference": "4471 2290 18"})
        assert res.get("status") == "killed"
        assert not any(e.get("data", {}).get("tool") == "pay_bill"
                       for e in events if e.get("type") == "tool_execution")
        reset_audit_log(keep_disk=False)

    asyncio.run(_run())


def test_kill_switch_off_allows_tool():
    async def _run():
        reset_audit_log(keep_disk=False)
        events = []
        fake_tools.set_tool_callbacks(emitter=lambda e: events.append(e))
        guard = KavachGuard(run_id="kill-0", user_task="Pay the bill",
                            is_active=True, event_emitter=lambda e: events.append(e),
                            kill_check=lambda: False)
        res = await guard.call("pay_bill", {"payee": "Delhi Power Board",
                                            "amount": 3420, "reference": "4471 2290 18"})
        assert res.get("status") == "paid"
        reset_audit_log(keep_disk=False)

    asyncio.run(_run())
