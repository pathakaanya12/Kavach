"""Unit tests for Kavach Engine Screening and Check Logic."""

import os
import json
import pytest

from kavach_engine.screen import screen_content, sanitize_text
from kavach_engine.check import check_action

# Load demo data
DEMO_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kavach_demo_data.json")
with open(DEMO_PATH, "r", encoding="utf-8") as f:
    DEMO_DATA = json.load(f)

def test_screen_safe_emails():
    # Emails 1, 2, 4 must be safe
    for email in DEMO_DATA["emails"]:
        if not email["poisoned"]:
            res = screen_content("test-run", f"email:{email['id']}", email["body"])
            assert res["verdict"] == "safe", f"Email {email['id']} should be safe, got {res['verdict']}"
            assert len(res["signals"]) == 0

def test_screen_poisoned_email_english():
    email_3 = next(e for e in DEMO_DATA["emails"] if e["id"] == 3)
    res = screen_content("test-run", "email:3", email_3["body"])
    assert res["verdict"] == "flagged"
    assert "hidden_html_comment" in res["signals"]
    assert "imperative_to_agent" in res["signals"]
    assert "secrecy_request" in res["signals"]
    # Check sanitization removes the hidden instruction
    assert "AI ASSISTANT INSTRUCTION" not in res["sanitized_text"]
    assert "customer_data.csv" not in res["sanitized_text"]

def test_screen_poisoned_email_hinglish():
    hinglish_line = DEMO_DATA["hinglish_variant_email_3_hidden_line"]
    email_3_hinglish_body = f"Hello,\n\nPlease find your invoice.\n{hinglish_line}"
    res = screen_content("test-run", "email:3", email_3_hinglish_body)
    assert res["verdict"] == "flagged"
    assert "hidden_html_comment" in res["signals"]
    assert any(s in res["signals"] for s in ["imperative_to_agent", "secrecy_request"])
    assert "customer_data.csv" not in res["sanitized_text"]

def test_check_legitimate_actions_allowed():
    user_task = DEMO_DATA["user_task"]

    # Action 1: Pay electricity bill
    pay_action = DEMO_DATA["expected_correct_actions"][0]
    res_pay = check_action(
        run_id="test-run",
        user_task=user_task,
        tool=pay_action["tool"],
        args=pay_action["args"],
        flagged_sources=[],
        context_sources=["email:2"]
    )
    assert res_pay["decision"] == "allow"

    # Action 2: Send report to manager
    report_action = DEMO_DATA["expected_correct_actions"][1]
    res_report = check_action(
        run_id="test-run",
        user_task=user_task,
        tool=report_action["tool"],
        args=report_action["args"],
        flagged_sources=[],
        context_sources=["email:1"]
    )
    assert res_report["decision"] == "allow"

def test_check_attack_action_stopped():
    user_task = DEMO_DATA["user_task"]
    attack_action = DEMO_DATA["expected_attack_action"]

    res_attack = check_action(
        run_id="test-run",
        user_task=user_task,
        tool=attack_action["tool"],
        args=attack_action["args"],
        flagged_sources=["email:3"],
        context_sources=["email:1", "email:3"]
    )
    assert res_attack["decision"] in ["ask", "block"]
    assert "external_recipient" in res_attack["policy_hits"]
    assert "restricted_file" in res_attack["policy_hits"]
