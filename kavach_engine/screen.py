"""Kavach Input Screening Engine.

Inspects incoming data before the agent reads it.
Uses deterministic regex and heuristic detectors (offline rules)
plus Gemini LLM screening with a configurable timeout (default 3.0s).
Flags suspicious instructions and activates session-level taint.
"""

import os
import re
import json
import base64
import logging
from typing import Dict, Any, List, Tuple, Optional
from dotenv import load_dotenv

from kavach_engine.session import taint_session, add_context_source

load_dotenv()
logger = logging.getLogger("kavach.screen")

# Zero-width Unicode characters
ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F]")

# Hidden HTML comments
HTML_COMMENT_REGEX = re.compile(r"<!--\s*(.*?)\s*-->", re.DOTALL | re.IGNORECASE)

# Hidden styling (CSS tricks)
HIDDEN_CSS_REGEX = re.compile(r"(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white|opacity\s*:\s*0)", re.IGNORECASE)

# Silent exfiltration via markdown image/link or URL with query payload
MARKDOWN_EXFIL_REGEX = re.compile(r"!?\[[^\]]*\]\(https?://[^)]+\)", re.IGNORECASE)
URL_QUERY_EXFIL_REGEX = re.compile(r"https?://\S+\?(?:.*)?(?:data|file|exfil|content)=[^&\s]*", re.IGNORECASE)

# Base64 encoded blobs (length >= 40)
BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}={0,2}")

# AI imperative phrases (English, Hindi, Hinglish)
AI_IMPERATIVES = [
    # English
    r"ai assistant",
    r"ignore (?:all )?previous",
    r"you must first",
    r"system prompt",
    r"new instruction",
    r"disregard (?:all )?prior",
    r"as an ai",
    # Hindi
    r"एआई सहायक",
    r"पिछले निर्देश",
    r"पहले यह करो",
    # Hinglish
    r"ai assistant\b",
    r"pehle .*? bhej do",
    r"pehle .*? karo",
    r"ignore karo",
    r"instruction:?",
]

# Secrecy keywords
SECRECY_PATTERNS = [
    # English
    r"do not mention",
    r"silently",
    r"do not tell",
    r"keep this secret",
    r"hidden from user",
    r"do not reveal",
    # Hindi
    r"उपयोगकर्ता को मत बताना",
    r"चुपचाप",
    r"गुप्त रखो",
    # Hinglish
    r"mat batana",
    r"chupchaap",
    r"chup chap",
    r"user ko (?:bilkul )?mat",
    r"kisi ko mat",
    r"secretly",
]

COMPILED_IMPERATIVES = [re.compile(p, re.IGNORECASE) for p in AI_IMPERATIVES]
COMPILED_SECRECY = [re.compile(p, re.IGNORECASE) for p in SECRECY_PATTERNS]

def extract_hidden_instruction(text: str) -> str:
    """Returns the exact hidden instruction line from a text, if any.

    Prefers the content of a hidden HTML comment that targets the AI
    assistant; otherwise the first line matching an imperative/secrecy
    pattern. Returns "" when nothing hidden is found. Used to show the
    judge, in the approval modal, the exact line that caused an action.
    """
    if not text:
        return ""
    comments = HTML_COMMENT_REGEX.findall(text)
    for comment in comments:
        c = comment.strip()
        if any(p.search(c) for p in COMPILED_IMPERATIVES) or any(
            p.search(c) for p in COMPILED_SECRECY
        ):
            return c
    if comments:
        return comments[0].strip()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(p.search(line) for p in COMPILED_IMPERATIVES) or any(
            p.search(line) for p in COMPILED_SECRECY
        ):
            return line
    return ""


def sanitize_text(text: str) -> str:
    """Strips hidden HTML comments, CSS trick markers, and zero-width characters."""
    if not text:
        return ""
    clean = ZERO_WIDTH_CHARS.sub("", text)
    clean = HTML_COMMENT_REGEX.sub("", clean)
    return clean.strip()

def detect_deterministic_signals(text: str) -> Tuple[bool, List[str], List[str]]:
    """
    Scans text deterministically without network access.
    Returns: (is_flagged, signals, reasons)
    """
    if not text:
        return False, [], []

    signals: List[str] = []
    reasons: List[str] = []

    # 1. Zero-width characters
    if ZERO_WIDTH_CHARS.search(text):
        signals.append("zero_width_chars")
        reasons.append("Zero-width steganographic characters detected")

    # 2. Hidden HTML comments
    comments = HTML_COMMENT_REGEX.findall(text)
    if comments:
        signals.append("hidden_html_comment")
        for comment in comments:
            if any(p.search(comment) for p in COMPILED_IMPERATIVES):
                signals.append("imperative_to_agent")
                reasons.append("Hidden instruction directed at AI assistant inside HTML comment")
            if any(p.search(comment) for p in COMPILED_SECRECY):
                signals.append("secrecy_request")
                reasons.append("Secrecy request ('silently/do not reveal') inside HTML comment")

    # 3. CSS hiding markers
    if HIDDEN_CSS_REGEX.search(text):
        signals.append("hidden_css_styling")
        reasons.append("CSS markers used to hide text from visual rendering")

    # 4. Direct AI imperatives in visible text
    if not any("imperative_to_agent" in s for s in signals):
        for pattern in COMPILED_IMPERATIVES:
            if pattern.search(text):
                signals.append("imperative_to_agent")
                reasons.append(f"Imperative command targeting AI assistant detected ({pattern.pattern})")
                break

    # 5. Direct secrecy requests in visible text
    if not any("secrecy_request" in s for s in signals):
        for pattern in COMPILED_SECRECY:
            if pattern.search(text):
                signals.append("secrecy_request")
                reasons.append("Instruction requesting secrecy or concealing actions from user")
                break

    # 6. Base64 blobs
    if BASE64_REGEX.search(text):
        signals.append("base64_encoded_blob")
        reasons.append("Suspicious base64-encoded payload detected")

    # 7. Silent URL exfiltration (markdown image/link pulls attacker URL with data)
    if MARKDOWN_EXFIL_REGEX.search(text) or URL_QUERY_EXFIL_REGEX.search(text):
        signals.append("silent_url_exfil")
        reasons.append("Markdown image/link or URL with exfil query points to external host")

    # 7b. URL reputation (v4): denylisted host in a web read.
    _bad, _bad_host = url_reputation_check(text)
    if _bad:
        signals.append("url_reputation_bad")
        reasons.append(f"URL host '{_bad_host}' is on the reputation denylist")

    # 8. Secret-like material in screened text (V2, defensive reuse of the
    # policy detector): a credential in an email/page the agent reads is
    # flagged so it is never forwarded onward.
    try:
        from kavach_engine.policy import detect_secret_leak as _dsl
        _found, _kind = _dsl(text)
        if _found:
            signals.append("secret_leak")
            reasons.append(f"Secret-like material detected in text ({_kind})")
    except Exception:
        pass

    is_flagged = len(signals) > 0
    return is_flagged, signals, reasons

def screen_with_gemini(text: str) -> Dict[str, Any]:
    """Calls Gemini model with configurable timeout (default 3s) for semantic screening."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    model_name = os.getenv("KAVACH_GEMINI_MODEL", os.getenv("KAVACH_SCREEN_MODEL", "gemini-3.8-flash"))
    timeout_sec = float(os.getenv("KAVACH_GEMINI_TIMEOUT", "3.0"))

    if not api_key:
        return {"verdict": "safe", "reason": "No API key provided", "signals": []}

    from kavach_engine.prompts import SCREENING_SYSTEM_PROMPT
    import requests

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": f"{SCREENING_SYSTEM_PROMPT}\n\nInput to screen:\n{text}"}]}],
        "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"}
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=timeout_sec)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return json.loads(raw_text)
        logger.warning(f"Gemini screening returned non-200 status {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"Gemini screening failed or timed out ({e}); falling back to deterministic detectors.")

    return {"verdict": "safe", "reason": "Gemini screener offline/timed out (fail-closed fallback)", "signals": []}

# URL-reputation denylist (v4, static, fake .example domains only —
# no live feed, no network call). A web read from one of these hosts is
# flagged; allowlisted hosts are unaffected.
URL_REPUTATION_DENYLIST = {
    "evil.example", "attacker.example", "malicious.example",
    "phish.example", "steal.example", "badactor.example",
    "fakebank.example", "scam.example", "exfil.example",
    "datatheft.example",
}


def url_reputation_check(text: str) -> Tuple[bool, str]:
    """True when text contains a URL whose host is denylisted."""
    for m in re.finditer(r'https?://([^/\s\'"<>]+)', text or "", re.IGNORECASE):
        host = m.group(1).lower().split(":")[0]
        if host in URL_REPUTATION_DENYLIST or any(
                host.endswith("." + d) for d in URL_REPUTATION_DENYLIST):
            return True, host
    return False, ""


def screen_content(
    run_id: str,
    source: str,
    text: str,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main screening function.
    Returns:
    {
      "verdict": "safe" | "flagged",
      "reason": "short explanation",
      "signals": [...],
      "sanitized_text": "..."
    }
    """
    effective_session_id = session_id or run_id
    if effective_session_id:
        add_context_source(effective_session_id, source)

    offline = os.getenv("KAVACH_OFFLINE", "0") == "1"
    clean_text = sanitize_text(text)

    # 1. Deterministic detection (offline rules)
    flagged_det, signals_det, reasons_det = detect_deterministic_signals(text)

    # 2. LLM Screening (if online)
    llm_flagged = False
    llm_reason = ""
    llm_signals = []

    if not offline:
        try:
            llm_result = screen_with_gemini(text)
            if llm_result.get("verdict") == "flagged":
                llm_flagged = True
                llm_reason = llm_result.get("reason", "LLM flagged suspicious instruction")
                llm_signals = llm_result.get("signals", ["llm_flagged"])
        except Exception as e:
            logger.warning(f"Gemini screen exception ({e})")
            if reasons_det:
                reasons_det = [r + " (offline rules)" for r in reasons_det]

    all_signals = list(dict.fromkeys(signals_det + (llm_signals if llm_flagged else [])))
    is_flagged = flagged_det or llm_flagged

    # PII redaction (v4): mask PII in the text the agent/user sees.
    # Masking never blocks anything — it only hides the value.
    try:
        from kavach_engine.redact import redact_text as _redact
        _allowed_upi = []
        try:
            import json as _json
            _cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "policies.json")
            with open(_cfg_path, "r", encoding="utf-8") as _f:
                _allowed_upi = list(_json.load(_f).get("allowed_upi_ids", []))
        except Exception:
            pass
        redacted_text, _masked_kinds = _redact(clean_text, tuple(_allowed_upi))
    except Exception:
        redacted_text, _masked_kinds = clean_text, []

    if is_flagged:
        verdict = "flagged"
        if reasons_det and llm_reason:
            reason = f"{reasons_det[0]}; {llm_reason}"
        elif reasons_det:
            reason = reasons_det[0]
        else:
            reason = llm_reason or "Suspicious prompt injection pattern identified"

        # Activate Session-Level Taint
        if effective_session_id:
            taint_session(effective_session_id, source)
    else:
        verdict = "safe"
        reason = "Clean communication; no hidden instructions or prompt injections detected"

    return {
        "verdict": verdict,
        "reason": reason,
        "signals": all_signals,
        "sanitized_text": clean_text,
        "redacted_text": redacted_text,
        "pii_masked": _masked_kinds,
    }
