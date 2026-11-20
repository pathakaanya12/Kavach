"""Unit tests for deterministic security policies."""

import pytest
from kavach_engine.policy import evaluate_policy, is_external_recipient, check_canary_in_text

def test_external_recipient_detection():
    assert is_external_recipient("karan.mehta@brightpath.example") is False
    assert is_external_recipient("riya.verma@brightpath.example") is False
    assert is_external_recipient("verify@cloudnest-billing.example") is True
    assert is_external_recipient("attacker@external.com") is True

def test_canary_tripwire_trigger():
    # If canary string appears anywhere in args
    tool = "send_email"
    args = {"to": "karan.mehta@brightpath.example", "body": "Notes: KVC-CANARY-7731"}
    decision, reason, hits = evaluate_policy(tool, args, [], [])
    assert decision == "block"
    assert "canary_in_args" in hits

def test_restricted_file_to_external_recipient():
    tool = "send_email"
    args = {"to": "verify@cloudnest-billing.example", "attachment": "customer_data.csv"}
    decision, reason, hits = evaluate_policy(tool, args, [], [])
    assert decision in ["ask", "block"]
    assert "external_recipient" in hits
    assert "restricted_file" in hits

def test_tainted_context_flow():
    # Action touches external party and comes from flagged source
    tool = "send_email"
    args = {"to": "vendor@external.com", "subject": "Invoice query"}
    decision, reason, hits = evaluate_policy(
        tool=tool,
        args=args,
        flagged_sources=["email:3"],
        context_sources=["email:1", "email:3"]
    )
    assert decision == "ask"
    assert "tainted_context" in hits

def test_legitimate_internal_report_allowed():
    tool = "send_email"
    args = {
        "to": "karan.mehta@brightpath.example",
        "subject": "Project report",
        "attachment": "project_report.pdf"
    }
    decision, reason, hits = evaluate_policy(tool, args, [], ["email:1"])
    assert decision == "allow"
    assert hits == []

def test_legitimate_utility_bill_allowed():
    tool = "pay_bill"
    args = {
        "payee": "Delhi Power Board",
        "amount": 3420,
        "reference": "4471 2290 18"
    }
    decision, reason, hits = evaluate_policy(tool, args, [], ["email:2"])
    assert decision == "allow"
    assert hits == []

def test_high_amount_payment_requires_approval():
    tool = "pay_bill"
    args = {
        "payee": "Delhi Power Board",
        "amount": 25000,
        "reference": "4471 2290 18"
    }
    decision, reason, hits = evaluate_policy(tool, args, [], ["email:2"])
    assert decision == "ask"
    assert "payment_limit_exceeded" in hits
