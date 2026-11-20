"""Unit tests for SHA-256 Hash-Chained Audit Log."""

import pytest
from kavach_engine.audit import (
    record_entry,
    get_audit_entries,
    verify_audit_chain,
    reset_audit_log,
    calculate_entry_hash,
    GENESIS_HASH
)

def setup_function():
    reset_audit_log(keep_disk=False)

def test_empty_chain_is_valid():
    res = verify_audit_chain()
    assert res["ok"] is True
    assert res["length"] == 0

def test_hash_chain_creation_and_verification():
    e1 = record_entry("run-1", "screen", "email:1", "SAFE", "clean")
    e2 = record_entry("run-1", "screen", "email:3", "FLAGGED", "hidden instruction")
    e3 = record_entry("run-1", "check", "pay_bill", "ALLOW", "task match")

    assert e1["seq"] == 1
    assert e1["prev_hash"] == GENESIS_HASH
    assert e2["seq"] == 2
    assert e2["prev_hash"] == e1["hash"]
    assert e3["seq"] == 3
    assert e3["prev_hash"] == e2["hash"]

    # Verify chain passes
    res = verify_audit_chain()
    assert res["ok"] is True
    assert res["length"] == 3

def test_tampering_fails_verification():
    record_entry("run-1", "screen", "email:1", "SAFE", "clean")
    record_entry("run-1", "check", "pay_bill", "ALLOW", "legit")
    record_entry("run-1", "check", "send_email", "BLOCK", "exfiltration")

    entries = get_audit_entries()
    assert verify_audit_chain(entries)["ok"] is True

    # Tamper with entry #2 (e.g., change ALLOW to BLOCK or detail)
    tampered_entries = [dict(e) for e in entries]
    tampered_entries[1]["result"] = "TAMPERED_RESULT"

    res = verify_audit_chain(tampered_entries)
    assert res["ok"] is False
    assert res["broken_seq"] == 2
    assert "Tampering detected" in res["reason"]
