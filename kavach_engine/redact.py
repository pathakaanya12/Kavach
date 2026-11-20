"""PII redaction (Tier-0, deterministic) — Kavach v4.

Masks Indian + general PII in tool results / agent output BEFORE it
reaches the user or the next tool. Regex only: no LLM, no model load,
no network. Masking is never a block — PII alone never stops a
legitimate task; the value is simply hidden from the agent/user.

Patterns (all synthetic / example values in tests only):
  Aadhaar: 12 digits (optionally spaced/hyphenated in 4-4-4 groups)
  PAN:     5 letters + 4 digits + 1 letter (e.g. ABCDE1234F)
  Phone:   Indian mobile, optional +91, 10 digits starting 6-9
  Email:   standard address shape
  UPI ID:  name@bank-handle (masked only when it is NOT an allowlisted
           payee — the legitimate bill payee stays readable)
  Card:    13-19 digits that pass the Luhn check (spaces/hyphens allowed)

Order matters: card/Aadhaar first (long digit runs), then PAN, phone,
email, UPI. The bill reference "4471 2290 18" (4-4-2) matches none of
these and is never masked.
"""

import re
from typing import Dict, List, Tuple

_AADHAAR_RE = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PHONE_RE = re.compile(r"(?:\+91[\s-]?|91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UPI_RE = re.compile(r"\b[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    """True when a digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask_card(text: str) -> Tuple[str, bool]:
    found = False

    def repl(m: "re.Match[str]") -> str:
        nonlocal found
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 13 or len(digits) > 19 or not _luhn_ok(digits):
            return raw
        found = True
        return "[REDACTED:Card]"

    return _CARD_RE.sub(repl, text), found


def redact_text(text: str, allowlisted_upi: Tuple[str, ...] = ()) -> Tuple[str, List[str]]:
    """Masks PII in text. Returns (redacted_text, [kinds masked]).

    allowlisted_upi: UPI IDs that must stay readable (the legitimate
    bill payee). Everything else matching a UPI shape is masked.
    """
    if not text:
        return text, []
    masked: List[str] = []
    out = text

    out, card_found = _mask_card(out)
    if card_found:
        masked.append("Card")

    def _sub(pattern, label, s):
        nonlocal_masked = []
        new, n = pattern.subn(f"[REDACTED:{label}]", s)
        if n:
            masked.append(label)
        return new

    out = _sub(_AADHAAR_RE, "Aadhaar", out)
    out = _sub(_PAN_RE, "PAN", out)
    out = _sub(_PHONE_RE, "Phone", out)
    out = _sub(_EMAIL_RE, "Email", out)

    # UPI: mask only non-allowlisted handles (e.g. an attacker's handle
    # pasted into a tool result). Legitimate payees stay readable.
    allowed = {u.strip().lower() for u in allowlisted_upi}

    def _upi_repl(m: "re.Match[str]") -> str:
        if m.group(0).lower() in allowed:
            return m.group(0)
        masked.append("UPI")
        return "[REDACTED:UPI]"

    out = _UPI_RE.sub(_upi_repl, out)
    # De-duplicate kinds, keep order of first appearance.
    kinds = list(dict.fromkeys(masked))
    return out, kinds


def redact_value(value, allowlisted_upi: Tuple[str, ...] = ()):
    """Recursively redacts strings inside dicts/lists; other values pass through."""
    if isinstance(value, str):
        return redact_text(value, allowlisted_upi)[0]
    if isinstance(value, dict):
        return {k: redact_value(v, allowlisted_upi) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v, allowlisted_upi) for v in value]
    return value


# Demo example for the dashboard: a clean bill email whose customer
# contact details are masked live. All values are synthetic.
DEMO_REDACTION_EXAMPLE = (
    "Dear customer, your Delhi Power Board bill of Rs 3,420 is due. "
    "Customer: Riya Sharma, phone 98765 43210, Aadhaar 2345 6789 0123, "
    "PAN ABCDE1234F, email riya.sharma@example.com, UPI riya@okhdfcbank. "
    "Pay only to Delhi Power Board, ref 4471 2290 18."
)
