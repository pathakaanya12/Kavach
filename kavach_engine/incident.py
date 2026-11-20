"""Why-blocked explainer + incident report (text only, no PDF) — v3.

When a tool call is blocked, Kavach builds a short plain-language
report: what happened, which source it came from, what was attempted,
what was saved, and why it was blocked. Gemini generates it ONLY when
GEMINI_API_KEY is set and KAVACH_OFFLINE != 1; otherwise a deterministic
template built from the policy hits + hidden line is used — that is the
tested path, and it works fully offline.
"""

import os
from typing import Any, Dict, List, Optional

try:
    from kavach_engine.screen import extract_hidden_instruction as _extract
except Exception:  # pragma: no cover - import cycle guard
    def _extract(text: str) -> str:
        return ""


def build_incident_report(
    tool: str,
    args: Dict[str, Any],
    policy_hits: List[str],
    reason: str,
    source: str = "",
    hidden_line: str = "",
    saved: str = "",
) -> Dict[str, Any]:
    """Deterministic template report. No network, no LLM."""
    attempted = f"{tool}({', '.join(f'{k}={v}' for k, v in (args or {}).items())})"
    what_saved = saved or "No money moved, no file left the company, and the legitimate bill and report were unaffected."
    summary = (
        f"Kavach blocked '{tool}'. "
        f"Reason: {reason or ', '.join(policy_hits) or 'policy violation'}. "
        f"What was saved: {what_saved}"
    )
    return {
        "title": f"Incident report — blocked {tool}",
        "mode": "template",
        "summary": summary,
        "what_happened": f"Agent attempted {attempted}.",
        "source": source or "unknown source",
        "attempted": attempted,
        "hidden_line": hidden_line or "",
        "policy_hits": list(policy_hits or []),
        "why_blocked": reason or ", ".join(policy_hits or []),
        "what_was_saved": what_saved,
    }


def incident_to_markdown(report: Dict[str, Any]) -> str:
    """Renders an incident report as downloadable Markdown text."""
    rep = report or {}
    lines = [
        f"# {rep.get('title', 'Incident report')}",
        "",
        f"Mode: {rep.get('mode', 'template')}",
        "",
        f"**Summary:** {rep.get('summary', '')}",
        "",
        f"**What happened:** {rep.get('what_happened', '')}",
        "",
        f"**Source:** {rep.get('source', '')}",
        "",
        f"**Attempted:** {rep.get('attempted', '')}",
        "",
        f"**Hidden line:** {rep.get('hidden_line', '')}",
        "",
        f"**Policy hits:** {', '.join(rep.get('policy_hits', []))}",
        "",
        f"**Why blocked:** {rep.get('why_blocked', '')}",
        "",
        f"**What was saved:** {rep.get('what_was_saved', '')}",
        "",
    ]
    return "\n".join(lines)


def generate_incident_report(
    tool: str,
    args: Dict[str, Any],
    policy_hits: List[str],
    reason: str,
    source: str = "",
    hidden_line: str = "",
    saved: str = "",
) -> Dict[str, Any]:
    """Gemini version when a key is configured and we are online;
    otherwise the deterministic template (tested path)."""
    report = build_incident_report(tool, args, policy_hits, reason, source, hidden_line, saved)
    if os.getenv("KAVACH_OFFLINE", "0") == "1":
        return report
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return report
    try:
        import json as _json
        import requests as _requests
        model = os.getenv("KAVACH_GEMINI_MODEL", "gemini-3.8-flash")
        prompt = (
            "Write a 3-sentence plain-language incident report for a blocked AI-agent "
            f"tool call. Tool: {tool}. Args: {args}. Policy hits: {policy_hits}. "
            f"Reason: {reason}. Source: {source}. Hidden line: {hidden_line}. "
            "Say what happened, what was attempted, and what was saved. No extra formatting."
        )
        resp = _requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=5,
        )
        if resp.status_code == 200:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            if text:
                report = dict(report)
                report["mode"] = "gemini"
                report["summary"] = text
                return report
    except Exception:
        pass
    return report
