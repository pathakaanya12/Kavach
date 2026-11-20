"""Deterministic Security Policies for Kavach.

Implements high-confidence tripwires and deterministic guardrails:
1. canary_in_args: Normalized canary tripwire check (Immediate BLOCK)
   Evasions normalized: URL encoding, Base64 encoding, zero-width chars,
   whitespace stripping, string reversal, and fragmented args across nested JSON.
2. restricted_file: Restricted file egress to external recipient (ASK or BLOCK)
3. session_taint: Session-level taint tracking (escalates non-allowlisted external actions to ASK)
4. tool_risk_tiers: Enforces risk tiers (read_only, internal_write, external_send, financial)
   and external domain allowlisting.
5. pay_bill financial limits and payee verification.
"""

import difflib
import os
import re
import json
import base64
import binascii
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional

DEMO_DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kavach_demo_data.json")
CONFIG_POLICY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "policies.json")

ZERO_WIDTH_REGEX = re.compile(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F]")

# Silent URL exfiltration detectors (shortcut: only http/https + markdown image/link)
URL_REGEX = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
MARKDOWN_URL_REGEX = re.compile(r"!?\[[^\]]*\]\((https?://[^)]+)\)", re.IGNORECASE)
EXFIL_QUERY_KEYS = ("data=", "file=", "exfil=", "content=", "q=", "body=")

# --- V2: destructive-action guard + secret-leak guard (defensive only) ---
DESTRUCTIVE_TOOL_NAMES = {
    "delete_file", "delete_database", "drop_table", "drop_database",
    "truncate_table", "remove_file", "erase_file", "format_disk",
    "delete_record", "delete_user", "delete_customer", "delete_account",
    "delete_table", "drop_collection", "delete_bucket",
}
_DESTRUCTIVE_NAME_RE = re.compile(
    r"(delete|drop|truncate|remove|erase|destroy|wipe|format|purge)\b", re.IGNORECASE)
_DESTRUCTIVE_ARG_RES = [
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\brm\s+-[a-z]*r[a-z]*f\b", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE),
]

def is_destructive(tool: str, args: Any) -> bool:
    """True for destructive tool calls: deleting/dropping/truncating data
    or files. Name-based first, then destructive SQL/shell phrases in args.
    Legitimate pay/send/share/read tools never match."""
    t = (tool or "").strip().lower()
    if t in DESTRUCTIVE_TOOL_NAMES:
        return True
    if _DESTRUCTIVE_NAME_RE.search(t):
        return True
    blob = " ".join(extract_all_strings(args, include_keys=False))
    return any(p.search(blob) for p in _DESTRUCTIVE_ARG_RES)

# Generic secret patterns only. Values below in tests/docs are the public
# AWS documentation example (AKIAIOSFODNN7EXAMPLE) and synthetic tokens.
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("api_key_sk", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("bearer_token", re.compile(r"(?:bearer|token|api[_-]?key)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE)),
    ("sensitive_filename", re.compile(r"(?:^|[/\\])(?:\.env|id_rsa|id_ed25519|id_ecdsa|\.pem)(?:\s|$|['\"])")),
]
# Plain .env / key-file names anywhere in an outbound arg value.
_SENSITIVE_FILE_RE = re.compile(r"(\.env\b|id_rsa|id_ed25519|id_ecdsa|\.pem\b)")

def detect_secret_leak(args: Any) -> Tuple[bool, str]:
    """Scan tool-call args (or any text) for secret-like material.
    Returns (found, pattern_name). customer_data.csv is data, not a
    secret, and does not match any pattern here."""
    if args is None:
        return False, ""
    texts = extract_all_strings(args, include_keys=False) if not isinstance(args, str) else [args]
    for text in texts:
        for name, pat in SECRET_PATTERNS:
            if pat.search(text):
                return True, name
        # Filename check: only flag when it looks like a credential file
        # being sent/shared (a bare path in an arg value), not a mention
        # in prose. Values here are short paths / filenames.
        if len(text.strip()) < 120 and _SENSITIVE_FILE_RE.search(text):
            return True, "sensitive_filename"
    return False, ""


# --- V3: honeypot tools, session budget, lookalike detection, egress ---
HONEYTOOLS = {"export_all_customers", "admin_transfer", "admin_reset_password"}

def is_honeypot(tool: str) -> bool:
    """Decoy tools no legitimate task ever calls. Any call = confirmed hijack."""
    return (tool or "").strip().lower() in HONEYTOOLS

# Session budget / velocity limits (per run, deterministic, no LLM).
SESSION_BUDGET = {
    "max_total_calls": 20,
    "max_send_email": 5,
    "max_file_reads": 10,
    "max_total_paid": 10000,  # Rs, reuses the auto-payment cap
}

def check_session_budget(tool: str, args: Any, counts: Dict[str, Any]) -> Tuple[bool, str]:
    """Returns (exceeded, reason) for the per-run budget counters.
    counts: {"total_calls": int, "send_email": int, "file_reads": int, "total_paid": float}
    The caller increments counts BEFORE calling this for the new call."""
    c = counts or {}
    if int(c.get("total_calls", 0)) > SESSION_BUDGET["max_total_calls"]:
        return True, f"Session budget exceeded: {c.get('total_calls')} tool calls (max {SESSION_BUDGET['max_total_calls']})"
    if tool == "send_email" and int(c.get("send_email", 0)) > SESSION_BUDGET["max_send_email"]:
        return True, f"Session budget exceeded: {c.get('send_email')} emails sent (max {SESSION_BUDGET['max_send_email']})"
    if tool in ("read_email", "get_emails", "list_files") and int(c.get("file_reads", 0)) > SESSION_BUDGET["max_file_reads"]:
        return True, f"Session budget exceeded: {c.get('file_reads')} file reads (max {SESSION_BUDGET['max_file_reads']})"
    if tool == "pay_bill" and float(c.get("total_paid", 0)) > SESSION_BUDGET["max_total_paid"]:
        return True, f"Session budget exceeded: Rs {float(c.get('total_paid')):,.0f} paid in this run (max Rs {SESSION_BUDGET['max_total_paid']:,})"
    return False, ""

_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "|": "l", "5": "s", "@": "a"})

def _norm_lookalike(s: str) -> str:
    return (s or "").strip().lower().translate(_CONFUSABLES).replace("rn", "m")

def similarity(a: str, b: str) -> float:
    """difflib ratio on the raw and confusable-normalised strings."""
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    r1 = difflib.SequenceMatcher(None, a, b).ratio()
    r2 = difflib.SequenceMatcher(None, _norm_lookalike(a), _norm_lookalike(b)).ratio()
    return max(r1, r2)

def detect_lookalike(value: str, allowlist: List[str]) -> Tuple[bool, str]:
    """True when value is suspiciously close to an allowlisted domain/UPI
    but is NOT an exact match (typosquat / homoglyph-style). Exact
    matches and clearly different values return False."""
    v = (value or "").strip().lower()
    if not v:
        return False, ""
    for allowed in allowlist:
        a = (allowed or "").strip().lower()
        if v == a:
            return False, ""
        if similarity(v, a) >= 0.80:
            return True, a
    return False, ""

def is_egress_allowed(url: str, config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """Egress allowlist: only internal + allowlisted hosts may be reached.
    Returns (allowed, host). No network call is made here."""
    host = url_domain(url or "")
    if not host:
        return False, ""
    cfg = config or load_policy_config()
    allowed = [d.lower() for d in cfg.get("internal_domains", [])] + \
        [d.lower() for d in cfg.get("allowed_external_domains", [])]
    ok = any(host == d or host.endswith("." + d) for d in allowed)
    return ok, host


def extract_urls(args: Any) -> List[str]:
    """Collects http/https URLs from all arg strings, including markdown links."""
    urls: List[str] = []
    for s in extract_all_strings(args, include_keys=False):
        urls.extend(URL_REGEX.findall(s))
        urls.extend(MARKDOWN_URL_REGEX.findall(s))
    return list(dict.fromkeys(urls))


def url_domain(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def load_policy_config() -> Dict[str, Any]:
    """Loads configuration and rules from config/policies.json and demo data."""
    config: Dict[str, Any] = {
        "internal_domains": ["brightpath.example"],
        "allowed_external_domains": ["delhipower.example", "tatapower.example"],
        "files": [
            {"name": "project_report.pdf", "sensitivity": "internal"},
            {"name": "customer_data.csv", "sensitivity": "restricted", "canary": "KVC-CANARY-7731"}
        ],
        "tool_risk_tiers": {
            "pay_bill": "financial",
            "send_email": "external_send",
            "share_file": "internal_write",
            "upload_file": "external_send",
            "http_post": "external_send",
            "read_email": "read_only",
            "get_emails": "read_only",
            "list_files": "read_only"
        }
    }

    if os.path.exists(CONFIG_POLICY_FILE):
        try:
            with open(CONFIG_POLICY_FILE, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                config.update(c_data)
        except Exception:
            pass

    if os.path.exists(DEMO_DATA_FILE):
        try:
            with open(DEMO_DATA_FILE, "r", encoding="utf-8") as f:
                d_data = json.load(f)
                if "files" in d_data:
                    config["files"] = d_data["files"]
                if "internal_domain" in d_data:
                    config["internal_domains"] = [d_data["internal_domain"]]
        except Exception:
            pass

    return config

KNOWN_PAYEES = {
    "delhi power board",
    "delhi power",
    "bses rajdhani",
    "bses yamuna",
    "tata power",
    "airtel broadband",
    "cloudnest accounts"
}

MAX_AUTO_PAYMENT_AMOUNT = 10000  # Rs 10,000

def get_tool_risk_tier(tool: str, config: Optional[Dict[str, Any]] = None) -> str:
    """Returns the risk tier of a tool. Defaults to 'external_send' (fail-closed)."""
    cfg = config or load_policy_config()
    tiers = cfg.get("tool_risk_tiers", {})
    return tiers.get(tool, "external_send")

def is_domain_allowed(recipient: str, config: Optional[Dict[str, Any]] = None) -> bool:
    """Checks if the recipient domain is internal or explicitly allowlisted."""
    if not recipient or "@" not in recipient:
        return True
    domain = recipient.strip().split("@")[-1].lower()
    cfg = config or load_policy_config()
    internal = [d.lower() for d in cfg.get("internal_domains", ["brightpath.example"])]
    allowed = [d.lower() for d in cfg.get("allowed_external_domains", [])]
    return domain in internal or domain in allowed

def is_external_recipient(recipient: str, internal_domain: str = "brightpath.example") -> bool:
    """Checks whether the recipient email is outside the organization domain."""
    if not recipient or "@" not in recipient:
        return False
    domain = recipient.strip().split("@")[-1].lower()
    return domain != internal_domain.lower()

def extract_all_strings(val: Any, include_keys: bool = False) -> List[str]:
    """Recursively collects string values from nested dicts, lists, or primitives."""
    strings = []
    if isinstance(val, str):
        strings.append(val)
    elif isinstance(val, dict):
        for k, v in val.items():
            if include_keys and isinstance(k, str):
                strings.append(k)
            strings.extend(extract_all_strings(v, include_keys=include_keys))
    elif isinstance(val, (list, tuple, set)):
        for item in val:
            strings.extend(extract_all_strings(item, include_keys=include_keys))
    return strings

def strip_noise(s: str) -> str:
    """Removes zero-width characters and whitespace."""
    no_zw = ZERO_WIDTH_REGEX.sub("", s)
    return re.sub(r"[\s\-_]+", "", no_zw).lower()

def try_base64_decode(token: str) -> Optional[str]:
    """Attempts to decode a token as Base64 text."""
    clean = token.strip()
    if len(clean) < 8:
        return None
    pad = (4 - len(clean) % 4) % 4
    padded = clean + ("=" * pad)
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        text = decoded_bytes.decode("utf-8", errors="ignore")
        if any(c.isalnum() for c in text):
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return None

def normalize_text_variants(raw: str) -> List[str]:
    """
    Produces normalized candidate strings to catch obfuscated canary tokens:
    1. Raw string
    2. URL-decoded variant
    3. Stripped zero-width and whitespace
    4. Base64 decoded variants for any long tokens
    5. Reversed string
    """
    variants = [raw, raw.lower()]

    try:
        unquoted = urllib.parse.unquote(raw)
        unquoted_plus = urllib.parse.unquote_plus(raw)
        variants.extend([unquoted, unquoted.lower(), unquoted_plus, unquoted_plus.lower()])
    except Exception:
        pass

    stripped = strip_noise(raw)
    variants.append(stripped)

    reversed_raw = raw[::-1]
    reversed_stripped = stripped[::-1]
    variants.extend([reversed_raw, reversed_raw.lower(), reversed_stripped])

    tokens = re.findall(r"[A-Za-z0-9+/=]{8,}", raw)
    for tok in tokens:
        decoded = try_base64_decode(tok)
        if decoded:
            variants.append(decoded)
            variants.append(decoded.lower())
            variants.append(strip_noise(decoded))

    return list(dict.fromkeys(variants))

def check_canary_in_text(text: str, canaries: List[str]) -> bool:
    """Backward-compatible helper for checking canary in raw text."""
    found, _ = check_canary_in_args(text, canaries)
    return found

def check_canary_in_args(args: Any, canaries: List[str]) -> Tuple[bool, str]:
    """
    Deep canary check:
    Inspects individual fields, concatenated nested fragments,
    and normalized/URL-decoded/Base64-decoded/reversed representations.
    Returns (True, reason) if any canary is detected.
    """
    if not args or not canaries:
        return False, ""

    all_values = extract_all_strings(args, include_keys=False)
    all_with_keys = extract_all_strings(args, include_keys=True)
    if not all_with_keys:
        return False, ""

    concatenated_values = "".join(all_values)
    concatenated_stripped = "".join(strip_noise(s) for s in all_values)
    concatenated_all = "".join(all_with_keys)

    all_candidates = list(all_with_keys) + [concatenated_values, concatenated_stripped, concatenated_all]

    for canary in canaries:
        canary_clean = canary.strip()
        canary_lower = canary_clean.lower()
        canary_stripped = strip_noise(canary_clean)

        for cand in all_candidates:
            variants = normalize_text_variants(cand)
            for v in variants:
                if canary_lower in v or canary_stripped in v:
                    return True, f"Canary token '{canary}' detected via evasion normalization"

    return False, ""

def evaluate_policy(
    tool: str,
    args: Dict[str, Any],
    flagged_sources: List[str],
    context_sources: List[str],
    is_session_tainted: bool = False,
    budget: Optional[Dict[str, Any]] = None,
    contract: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
    role: str = "operator",
) -> Tuple[str, str, List[str]]:
    """
    Evaluates deterministic security policies:
    1. Canary Tripwire check (BLOCK)
    2. Restricted file egress check (ASK or BLOCK)
    3. Session-level taint tracking (escalates unallowlisted external actions to ASK)
    4. Tool risk tiers and external allowlist verification
    5. Financial limits on payments
    6. (v4) Toxic-flow chain detection over the run's tool-call history
    7. (v4) ABAC attributes on the intent contract
    8. (v4) URL-reputation denylist for http_post
    """
    config = load_policy_config()
    internal_domains = config.get("internal_domains", ["brightpath.example"])
    primary_internal = internal_domains[0] if internal_domains else "brightpath.example"
    files_meta = config.get("files", [])

    canaries = [f["canary"] for f in files_meta if "canary" in f]
    restricted_file_names = {f["name"].lower() for f in files_meta if f.get("sensitivity") == "restricted"}

    policy_hits: List[str] = []
    reasons: List[str] = []
    strictest_decision = "allow"

    # 0h. Toxic-flow chain (v4): a dangerous SEQUENCE of individually
    # benign calls (read -> send outside, read -> delete). History is the
    # run's prior tool calls; gap tolerance is built into the detector.
    try:
        from kavach_engine.chain import detect_toxic_flow as _dtf
        _flow, _pname, _pdesc = _dtf(history or [], tool, args)
        if _flow:
            policy_hits.append("toxic_flow")
            reasons.append(f"Toxic tool-call chain detected ({_pname}): {_pdesc} — final step blocked")
            strictest_decision = "block"
    except Exception:
        pass

    # 0i. URL reputation (v4): http_post to a denylisted host is blocked.
    if tool == "http_post":
        _u = str(args.get("url") or args.get("target") or "")
        if _u:
            try:
                from kavach_engine.screen import url_reputation_check as _urc
                _bad2, _host2 = _urc(_u)
            except Exception:
                _bad2, _host2 = False, ""
            if _bad2:
                policy_hits.append("url_reputation_bad")
                reasons.append(f"URL host '{_host2}' is on the reputation denylist")
                strictest_decision = "block"

    # 0c. Honeypot (V3): a decoy tool no legit task ever calls. Any call
    # is confirmed hijack -> instant hard BLOCK (guard also kills the run).
    if is_honeypot(tool):
        policy_hits.append("honeypot_triggered")
        reasons.append(f"Honeypot tool '{tool}' called — decoy no legitimate task ever uses; confirmed hijack")
        strictest_decision = "block"

    # 0d. Intent contract (V3, lite): only when a contract is supplied.
    # Deterministic match; the LLM is never called for this.
    if contract is not None:
        try:
            from kavach_engine.contract import check_intent_contract as _cic
            violated, chits, creason = _cic(tool, args, contract)
            if violated:
                policy_hits.extend(h for h in chits if h not in policy_hits)
                reasons.append(creason)
                if strictest_decision == "allow":
                    strictest_decision = "ask"
        except Exception:
            pass
        # 0d2. ABAC attributes (v4): role / time window / data sensitivity.
        try:
            from kavach_engine.contract import check_abac as _abac
            _av, _ahits, _areason = _abac(tool, args, contract, role=role)
            if _av:
                policy_hits.extend(h for h in _ahits if h not in policy_hits)
                reasons.append(_areason)
                if strictest_decision == "allow":
                    strictest_decision = "ask"
        except Exception:
            pass

    # 0e. Session budget / velocity (V3): counts are supplied by the caller.
    if budget is not None:
        exceeded, breason = check_session_budget(tool, args, budget)
        if exceeded:
            policy_hits.append("session_budget_exceeded")
            reasons.append(breason)
            strictest_decision = "block"

    # 0f. Egress allowlist (V3): http_post may only reach allowlisted hosts.
    if tool == "http_post":
        _url = str(args.get("url") or args.get("target") or "")
        if _url:
            _ok, _host = is_egress_allowed(_url, config)
            if not _ok:
                policy_hits.append("egress_blocked")
                reasons.append(f"Egress to '{_host}' blocked — host is not on the egress allowlist; agents may only talk out through Kavach")
                strictest_decision = "block"

    # 0g. Lookalike sender/payee (V3): close-but-not-exact allowlist match.
    _recip = str(args.get("to") or args.get("with_email") or "")
    _payee_raw = str(args.get("payee", "")).strip()
    if _recip and "@" in _recip:
        _dom = _recip.split("@")[-1].lower()
        _allow_domains = [d.lower() for d in config.get("internal_domains", [])] + \
            [d.lower() for d in config.get("allowed_external_domains", [])]
        _look, _near = detect_lookalike(_dom, _allow_domains)
        if _look:
            policy_hits.append("lookalike_domain")
            reasons.append(f"Recipient domain '{_dom}' looks like allowlisted '{_near}' (typosquat/homoglyph) — not an exact match")
            if strictest_decision == "allow":
                strictest_decision = "ask"
    if _payee_raw and "@" in _payee_raw:
        _look2, _near2 = detect_lookalike(_payee_raw, [u.lower() for u in config.get("allowed_upi_ids", [])])
        if _look2:
            policy_hits.append("lookalike_upi")
            reasons.append(f"UPI ID '{_payee_raw}' looks like allowlisted '{_near2}' — not an exact match")
            if strictest_decision == "allow":
                strictest_decision = "ask"

    # 0a. Secret-leak guard (V2, hard BLOCK): secret-like material in any
    # tool-call argument must never leave the machine.
    secret_found, secret_kind = detect_secret_leak(args)
    if secret_found:
        policy_hits.append("secret_leak")
        reasons.append(f"Secret-like material detected in tool arguments ({secret_kind}); blocked to prevent credential leak")
        strictest_decision = "block"

    # 0b. Destructive-action guard (V2): deleting/dropping/truncating
    # always needs a human, even if it matches the user task.
    if is_destructive(tool, args):
        policy_hits.append("destructive_action")
        reasons.append(f"Destructive action '{tool}' always requires human approval (irreversible)")
        if strictest_decision != "block":
            strictest_decision = "ask"

    # 1. Canary Token Tripwire Check (Immediate BLOCK)
    canary_found, canary_reason = check_canary_in_args(args, canaries)
    if canary_found:
        policy_hits.append("canary_in_args")
        reasons.append(canary_reason)
        strictest_decision = "block"

    # 1b. Silent URL exfiltration (markdown image/link + query smuggling)
    allowed_hosts = [d.lower() for d in config.get("internal_domains", [])] + \
        [d.lower() for d in config.get("allowed_external_domains", [])]
    args_blob = " ".join(extract_all_strings(args, include_keys=False)).lower()
    for url in extract_urls(args):
        host = url_domain(url)
        if not host or any(host == d or host.endswith("." + d) for d in allowed_hosts):
            continue
        url_low = url.lower()
        is_markdown = "![" in args_blob or "](" in url_low
        carries_sensitive = any(k in url_low for k in list(restricted_file_names) + [c.lower() for c in canaries]) or \
            any(k in url_low for k in EXFIL_QUERY_KEYS)
        if carries_sensitive or is_markdown:
            policy_hits.append("silent_url_exfil")
            reasons.append(f"External URL '{url[:80]}' may smuggle sensitive data out")
            strictest_decision = "block"
            break
        policy_hits.append("external_url")
        reasons.append(f"External URL '{host}' is not allowlisted")
        if strictest_decision == "allow":
            strictest_decision = "ask"
        break

    # Destination and file inspection
    attachment_name = str(args.get("attachment") or args.get("file") or "").lower()
    recipient = str(args.get("to") or args.get("with_email") or "")
    tool_tier = get_tool_risk_tier(tool, config)

    # 2. Domain Allowlist & Restricted File Check
    is_external = is_external_recipient(recipient, primary_internal)
    domain_allowed = is_domain_allowed(recipient, config)

    if is_external:
        policy_hits.append("external_recipient")

        if attachment_name in restricted_file_names or any(rf in attachment_name for rf in restricted_file_names):
            policy_hits.append("restricted_file")
            reasons.append(f"Attempt to send restricted file '{attachment_name}' to external recipient '{recipient}'")
            if strictest_decision != "block":
                strictest_decision = "block" if "canary_in_args" in policy_hits else "ask"

        if not domain_allowed:
            policy_hits.append("non_allowlisted_domain")
            reasons.append(f"Recipient domain '{recipient}' is not in external allowlist")
            if strictest_decision == "allow":
                strictest_decision = "ask"

    # 3. Session-Level Taint Tracking (Pessimistic session escalation)
    # Once any source in a session is flagged, external-bound unallowlisted calls escalate to ASK
    taint_active = is_session_tainted or bool(flagged_sources)
    if taint_active:
        # Check if action leaves to non-allowlisted external destination or touches restricted data
        if (is_external and not domain_allowed) or (attachment_name in restricted_file_names):
            if "session_tainted" not in policy_hits:
                policy_hits.append("session_tainted")
                reasons.append("Session is tainted (screened source flagged); external-bound action escalated to ASK [Session-level taint]")
                if strictest_decision == "allow":
                    strictest_decision = "ask"

    # Context source taint correlation (Invariant-style)
    if flagged_sources and any(src in flagged_sources for src in context_sources):
        if is_external or attachment_name in restricted_file_names:
            if "tainted_context" not in policy_hits:
                policy_hits.append("tainted_context")
                reasons.append(f"Action influenced by tainted sources {flagged_sources} and attempts external egress")
                if strictest_decision == "allow":
                    strictest_decision = "ask"

    # 4b. UPI / payment-hijack rule: a pay_bill whose payee or reference
    # differs from the original bill, or that targets a UPI ID outside the
    # allowlist, must ask a human. The exact legitimate bill (payee /
    # amount / reference) is allowlisted, so this never fires on it.
    if tool == "pay_bill" or tool_tier == "financial":
        payee_raw = str(args.get("payee", "")).strip()
        payee = payee_raw.lower()
        reference = str(args.get("reference", "")).strip()
        allowed_upi = [u.lower() for u in config.get("allowed_upi_ids", [])]
        expected = config.get("expected_bill") or {}
        exp_payee = str(expected.get("payee", "")).strip().lower()
        exp_ref = str(expected.get("reference", "")).strip()
        if "@" in payee_raw and payee not in allowed_upi:
            policy_hits.append("upi_payee_not_allowlisted")
            reasons.append(
                f"Payment targets UPI ID '{payee_raw}' which is not in the allowlisted UPI IDs"
            )
            if strictest_decision == "allow":
                strictest_decision = "ask"
        if exp_payee and payee and payee != exp_payee:
            policy_hits.append("bill_payee_changed")
            reasons.append(
                f"Payee '{payee_raw}' differs from the original bill payee '{expected.get('payee')}'"
            )
            if strictest_decision == "allow":
                strictest_decision = "ask"
        if exp_ref and reference and reference != exp_ref:
            policy_hits.append("bill_reference_changed")
            reasons.append(
                f"Payment reference '{reference}' differs from the original bill reference '{exp_ref}'"
            )
            if strictest_decision == "allow":
                strictest_decision = "ask"

    # 4. Financial Limits & Unknown Payees
    if tool == "pay_bill" or tool_tier == "financial":
        payee = str(args.get("payee", "")).strip().lower()
        amount = args.get("amount", 0)
        try:
            amount_val = float(amount)
        except (ValueError, TypeError):
            amount_val = 0.0

        if amount_val > MAX_AUTO_PAYMENT_AMOUNT:
            policy_hits.append("payment_limit_exceeded")
            reasons.append(f"Payment amount Rs {amount_val:,.0f} exceeds auto-approval threshold Rs {MAX_AUTO_PAYMENT_AMOUNT:,.0f}")
            if strictest_decision == "allow":
                strictest_decision = "ask"

        if payee and not any(kp in payee for kp in KNOWN_PAYEES):
            policy_hits.append("unknown_payee")
            reasons.append(f"Payee '{args.get('payee')}' is not in pre-approved vendor list")
            if strictest_decision == "allow":
                strictest_decision = "ask"

    final_reason = "; ".join(reasons) if reasons else "Complies with deterministic security policies"
    return strictest_decision, final_reason, policy_hits
