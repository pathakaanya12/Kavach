"""V2: secret-leak guard (offline). All test values are synthetic /
public documentation examples — no real credentials anywhere."""
import os

os.environ["KAVACH_OFFLINE"] = "1"

from kavach_engine.policy import evaluate_policy, detect_secret_leak
from kavach_engine.screen import screen_content

FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # public AWS documentation example
FAKE_GH = "ghp_" + "A" * 36
FAKE_SK = "sk-" + "B" * 36
FAKE_SLACK = "xoxb-123456789012-ABCDEFGHIJ"


def test_aws_key_blocked():
    found, kind = detect_secret_leak({"body": f"key is {FAKE_AWS}"})
    assert found and kind == "aws_access_key"
    d, _, hits = evaluate_policy("send_email",
        {"to": "vendor@external.com", "body": f"here is {FAKE_AWS}"}, [], [])
    assert d == "block" and "secret_leak" in hits


def test_github_and_api_keys_blocked():
    for value in (FAKE_GH, "github_pat_" + "C" * 30, FAKE_SK, "sk_live_" + "D" * 24):
        d, _, hits = evaluate_policy("send_email",
            {"to": "vendor@external.com", "body": value}, [], [])
        assert d == "block", value
        assert "secret_leak" in hits


def test_private_key_and_slack_blocked():
    d, _, hits = evaluate_policy("share_file",
        {"file": "notes.txt", "with_email": "vendor@external.com",
         "body": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"},
        [], [])
    assert d == "block" and "secret_leak" in hits
    d, _, hits = evaluate_policy("http_post",
        {"url": "https://example.com/hook", "body": FAKE_SLACK}, [], [])
    assert d == "block" and "secret_leak" in hits


def test_credential_filename_blocked():
    d, _, hits = evaluate_policy("send_email",
        {"to": "vendor@external.com", "attachment": ".env"}, [], [])
    assert d == "block" and "secret_leak" in hits
    d, _, hits = evaluate_policy("send_email",
        {"to": "vendor@external.com", "attachment": "id_rsa"}, [], [])
    assert d == "block" and "secret_leak" in hits


def test_legitimate_calls_still_allowed():
    d, _, hits = evaluate_policy("pay_bill",
        {"payee": "Delhi Power Board", "amount": 3420, "reference": "4471 2290 18"}, [], ["email:2"])
    assert d == "allow" and hits == []
    # customer_data.csv is data, not a secret — the canary handles it separately.
    d, _, hits = evaluate_policy("send_email",
        {"to": "karan.mehta@brightpath.example", "subject": "Project report",
         "attachment": "customer_data.csv"}, [], ["email:1"])
    assert "secret_leak" not in hits


def test_screen_flags_secret_in_text():
    res = screen_content("run-secret", "email:9", f"My key is {FAKE_AWS}, please use it.")
    assert res["verdict"] == "flagged"
    assert "secret_leak" in res["signals"]
