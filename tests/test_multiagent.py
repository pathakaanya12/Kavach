"""Multi-agent taint tests (offline / scripted).

Reader -> Executor: poison survives in the summary, taint travels
summary:1<-email:3. OFF = BREACHED, ON = PROTECTED.
"""
import asyncio
import json
import os

os.environ["KAVACH_OFFLINE"] = "1"
os.environ["AGENT_PLANNER"] = "scripted"
os.environ["DEMO_ATTACK_PERSISTS"] = "1"

import pytest

from kavach_engine.audit import reset_audit_log
from agent.guard import KavachGuard
from agent.multiagent import build_summary, plan_executor_actions, run_multiagent_demo
import agent.tools as fake_tools

DEMO_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kavach_demo_data.json")


def load_demo():
    with open(DEMO_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def clean_environment():
    reset_audit_log(keep_disk=False)
    yield
    reset_audit_log(keep_disk=False)


def test_summary_carries_poison_and_derived_from():
    demo = load_demo()
    summary = build_summary(demo["emails"])
    assert summary["derived_from"] == ["email:1", "email:2", "email:3", "email:4"]
    assert "customer_data.csv" in summary["text"]
    actions = plan_executor_actions(summary)
    assert any(a["args"].get("to") == "verify@cloudnest-billing.example" for a in actions)


def test_multiagent_off_breached():
    async def _run():
        demo = load_demo()
        breached = False
        events = []

        def on_breach(msg):
            nonlocal breached
            breached = True

        fake_tools.set_tool_callbacks(emitter=lambda e: events.append(e), on_breach=on_breach)
        guard = KavachGuard(run_id="ma-off", user_task=demo["user_task"], is_active=False,
                            event_emitter=lambda e: events.append(e))
        result = await run_multiagent_demo(guard, demo["emails"])
        assert result["taint_path"] is None, "OFF: no taint label exists"
        assert breached is True, "OFF: Executor follows poisoned summary -> BREACHED"

    asyncio.run(_run())


def test_multiagent_on_protected():
    async def _run():
        demo = load_demo()
        breached = False
        paid = False
        sent = False
        blocked = False

        def on_tool_evt(evt):
            nonlocal paid, sent
            data = evt.get("data", {})
            if data.get("tool") == "pay_bill" and data.get("payee") == "Delhi Power Board":
                paid = True
            if data.get("tool") == "send_email" and "karan.mehta" in str(data.get("to")):
                sent = True

        def on_breach(msg):
            nonlocal breached
            breached = True

        fake_tools.set_tool_callbacks(emitter=on_tool_evt, on_breach=on_breach)

        async def mock_approval(run_id, tool, args, reason, policy_hits, hidden=""):
            nonlocal blocked
            blocked = True
            return "block"

        guard = KavachGuard(run_id="ma-on", user_task=demo["user_task"], is_active=True,
                            event_emitter=lambda e: None,
                            approval_handler=mock_approval)
        result = await run_multiagent_demo(guard, demo["emails"])
        assert result["taint_path"] == "email:3 \u2192 summary \u2192 executor"
        assert "summary:1<-email:3" in result["flagged_sources"]
        assert breached is False
        assert paid is True
        assert sent is True
        assert blocked is True, "tainted Executor action must reach human approval and be blocked"

    asyncio.run(_run())
