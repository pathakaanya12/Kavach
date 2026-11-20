"""Hash-chained Audit Log for Kavach.

Ensures tamper-evidence using SHA-256 hash chaining:
hash = sha256(prev_hash + canonical_json(entry_without_hash))
"""

import os
import json
import hashlib
import hmac as hmac_mod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Mediator-signed receipts (v4): HMAC-SHA256 over the audit entry hash.
# Key comes from env KAVACH_AUDIT_KEY; without one a clearly-marked
# DEV-ONLY fallback is used so receipts still work offline in the demo.
# Never put a real key in the repo; rotate the env key in production.
# Ed25519 signatures stay on the roadmap.
DEV_AUDIT_KEY = "kavach-dev-audit-key-NOT-FOR-PRODUCTION"


def _audit_key() -> bytes:
    return os.getenv("KAVACH_AUDIT_KEY", "").strip().encode("utf-8") or DEV_AUDIT_KEY.encode("utf-8")


def sign_receipt(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Signs one audit entry: {seq, run_id, hash, signature, key_hint}.
    The signature covers the entry's hash, so any tampering with the
    entry breaks both the hash chain and the receipt."""
    payload = canonical_json({
        "seq": entry.get("seq"), "run_id": entry.get("run_id"),
        "hash": entry.get("hash"),
    })
    sig = hmac_mod.new(_audit_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"seq": entry.get("seq"), "run_id": entry.get("run_id"),
            "hash": entry.get("hash"), "signature": sig,
            "key_hint": "env" if os.getenv("KAVACH_AUDIT_KEY", "").strip() else "dev-only"}


def verify_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Verifies a receipt outside the run that produced it."""
    if not isinstance(receipt, dict) or not receipt.get("hash") or not receipt.get("signature"):
        return {"ok": False, "reason": "Receipt is missing hash or signature"}
    expected = sign_receipt(receipt)
    ok = hmac_mod.compare_digest(expected["signature"], str(receipt["signature"]))
    return {"ok": ok, "seq": receipt.get("seq"), "run_id": receipt.get("run_id"),
            "reason": "Receipt signature valid" if ok else "Receipt signature mismatch — receipt was tampered with"}


def get_receipt_for_seq(seq: int) -> Dict[str, Any]:
    """Returns a signed receipt for an audit entry by sequence number."""
    for entry in _audit_entries:
        if entry.get("seq") == int(seq):
            return sign_receipt(entry)
    return {"ok": False, "reason": f"No audit entry with seq {seq}"}

GENESIS_HASH = "0" * 64
DEFAULT_AUDIT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit.jsonl")

# In-memory chain
_audit_entries: List[Dict[str, Any]] = []

def canonical_json(obj: Dict[str, Any]) -> str:
    """Produces deterministic, canonical JSON string without whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def calculate_entry_hash(prev_hash: str, entry_without_hash: Dict[str, Any]) -> str:
    """Computes sha256(prev_hash + canonical_json(entry_without_hash))."""
    payload = prev_hash + canonical_json(entry_without_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def record_entry(
    run_id: str,
    kind: str,
    detail: str,
    result: str,
    reason: str,
    log_file: Optional[str] = DEFAULT_AUDIT_FILE
) -> Dict[str, Any]:
    """Appends a new hash-chained audit record and optionally writes to audit.jsonl."""
    global _audit_entries

    prev_hash = _audit_entries[-1]["hash"] if _audit_entries else GENESIS_HASH
    seq = len(_audit_entries) + 1
    timestamp = datetime.now(timezone.utc).isoformat()

    entry_data = {
        "seq": seq,
        "run_id": run_id,
        "time": timestamp,
        "kind": kind,
        "detail": detail,
        "result": result,
        "reason": reason,
        "prev_hash": prev_hash,
    }

    entry_hash = calculate_entry_hash(prev_hash, entry_data)
    full_entry = dict(entry_data)
    full_entry["hash"] = entry_hash

    _audit_entries.append(full_entry)

    # Append to disk
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(full_entry) + "\n")

    return full_entry

def get_audit_entries() -> List[Dict[str, Any]]:
    """Returns in-memory audit log entries."""
    return list(_audit_entries)

def verify_audit_chain(entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Verifies cryptographic hash chain integrity.
    Returns: {"ok": True, "length": n} or {"ok": False, "broken_seq": int, "reason": str}
    """
    chain = entries if entries is not None else _audit_entries

    if not chain:
        return {"ok": True, "length": 0}

    expected_prev = GENESIS_HASH

    for idx, entry in enumerate(chain):
        # 1. Verify prev_hash link
        if entry.get("prev_hash") != expected_prev:
            return {
                "ok": False,
                "broken_seq": entry.get("seq", idx + 1),
                "reason": f"Mismatched prev_hash at seq {entry.get('seq')}. Expected {expected_prev}, got {entry.get('prev_hash')}"
            }

        # 2. Recompute hash
        entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
        computed_hash = calculate_entry_hash(expected_prev, entry_without_hash)

        if computed_hash != entry.get("hash"):
            return {
                "ok": False,
                "broken_seq": entry.get("seq", idx + 1),
                "reason": f"Hash mismatch at seq {entry.get('seq')}. Tampering detected! Expected {computed_hash}, got {entry.get('hash')}"
            }

        expected_prev = entry.get("hash")

    return {"ok": True, "length": len(chain)}

def reset_audit_log(keep_disk: bool = False, log_file: Optional[str] = DEFAULT_AUDIT_FILE):
    """Resets in-memory audit log (useful for testing)."""
    global _audit_entries
    _audit_entries = []
    if not keep_disk and log_file and os.path.exists(log_file):
        try:
            os.remove(log_file)
        except OSError:
            pass
