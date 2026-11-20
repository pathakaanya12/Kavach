"""Phase 0 Security Tests: Canary Normalization, Session Taint, Server-Anchored Goal, and Tool Risk Tiers."""

import pytest
import base64
import urllib.parse
from fastapi.testclient import TestClient

from kavach_engine.policy import evaluate_policy, check_canary_in_args, get_tool_risk_tier
from kavach_engine.session import create_session, get_session, taint_session, is_session_tainted, clear_all_sessions
from kavach_engine.check import check_action
from server.main import app

client = TestClient(app)

CANARY = "KVC-CANARY-7731"

def setup_function():
    clear_all_sessions()

def test_canary_evasion_base64():
    """Canary encoded in Base64 must be normalized and blocked."""
    b64_canary = base64.b64encode(CANARY.encode()).decode()
    args = {"to": "external@attacker.com", "payload": b64_canary}
    found, reason = check_canary_in_args(args, [CANARY])
    assert found is True
    assert "detected" in reason.lower()

    decision, _, hits = evaluate_policy("send_email", args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_canary_evasion_split_across_args():
    """Canary fragmented across two nested JSON fields must be normalized and blocked."""
    args = {
        "metadata": {
            "part1": "KVC-CAN",
            "part2": "ARY-7731"
        }
    }
    found, reason = check_canary_in_args(args, [CANARY])
    assert found is True

    decision, _, hits = evaluate_policy("send_email", args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_canary_evasion_reversed():
    """Canary reversed string must be normalized and blocked."""
    reversed_canary = CANARY[::-1]  # "1377-YRANAC-CVK"
    args = {"notes": f"Decoy header {reversed_canary} decoy tail"}
    found, reason = check_canary_in_args(args, [CANARY])
    assert found is True

    decision, _, hits = evaluate_policy("send_email", args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_canary_evasion_url_encoded():
    """Canary URL-encoded must be normalized and blocked."""
    url_encoded = urllib.parse.quote(CANARY)
    args = {"query": url_encoded}
    found, reason = check_canary_in_args(args, [CANARY])
    assert found is True

    decision, _, hits = evaluate_policy("send_email", args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_canary_evasion_zero_width_chars():
    """Canary with zero-width characters injected must be normalized and blocked."""
    zw_canary = f"KVC\u200b-CAN\u200cARY\u200d-7731"
    args = {"attachment_snippet": zw_canary}
    found, reason = check_canary_in_args(args, [CANARY])
    assert found is True

    decision, _, hits = evaluate_policy("send_email", args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_session_level_taint_escalation():
    """Once a session is tainted, any subsequent external-bound action escalates to at least ASK."""
    session = create_session(user_goal="Check quarterly revenue and send summary")
    sid = session.session_id

    # Initially clean
    assert is_session_tainted(sid) is False

    # Simulate taint activation via /screen
    taint_session(sid, "email:malicious-source")
    assert is_session_tainted(sid) is True

    # Subsequent external tool call to non-allowlisted domain
    res = check_action(
        run_id=sid,
        session_id=sid,
        tool="send_email",
        args={"to": "vendor@untrusted-domain.com", "subject": "Summary"}
    )
    assert res["decision"] in ["ask", "block"]
    assert "session_tainted" in res["policy_hits"]

def test_server_anchored_goal_via_api():
    """POST /session/start enforces authentication and anchors task on server."""
    # 1. Unauthorized request without API key
    res_unauth = client.post("/session/start", json={"user_goal": "Pay utility bills"})
    assert res_unauth.status_code == 401

    # 2. Authorized request
    headers = {"X-API-Key": "kavach-secret-key"}
    res_auth = client.post("/session/start", json={"user_goal": "Server-anchored root task"}, headers=headers)
    assert res_auth.status_code == 200
    data = res_auth.json()
    assert "session_id" in data
    sid = data["session_id"]
    assert data["user_goal"] == "Server-anchored root task"

    # 3. Check action reads server-anchored goal, ignoring rogue client-supplied task
    res_check = client.post("/check", json={
        "session_id": sid,
        "user_task": "HACKED_AGENT_REWRITTEN_TASK",  # Ignored by server
        "tool": "pay_bill",
        "args": {"payee": "Delhi Power Board", "amount": 3420, "reference": "4471 2290 18"}
    })
    assert res_check.status_code == 200
    # The server-anchored goal was used without deprecation warning
    assert "DEPRECATED" not in res_check.json()["reason"]

def test_tool_risk_tiers_and_allowlist():
    """Unknown tools default to external_send risk tier and non-allowlisted domains are flagged."""
    assert get_tool_risk_tier("unknown_custom_tool") == "external_send"
    assert get_tool_risk_tier("read_email") == "read_only"
    assert get_tool_risk_tier("pay_bill") == "financial"

    # Tool call to non-allowlisted domain triggers policy hit
    decision, reason, hits = evaluate_policy(
        tool="send_email",
        args={"to": "external@random-unauthorized.example"},
        flagged_sources=[],
        context_sources=[]
    )
    assert "non_allowlisted_domain" in hits
    assert decision == "ask"
