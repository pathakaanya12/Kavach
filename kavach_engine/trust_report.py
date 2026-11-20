"""Kavach Trust Report.

One-click report that turns what Kavach already observed (audit log, demo runs,
Red Team results) into:
  1. a transparent Trust Score (0-100, grade A-D),
  2. coverage against the OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10),
  3. evidence mapped to India's DPDP Rules 2025 security-safeguard themes,
  4. a breach-intimation draft with the 72-hour clock when a breach happened.

Important: this is EVIDENCE to support a security / compliance review.
It is not a legal certification and not legal advice.
"""

from __future__ import annotations

import datetime as _dt
import html
from typing import Any, Dict, List, Optional

DISCLAIMER = (
    "This report is generated evidence from Kavach's own logs to support a security and "
    "compliance review. It is not a legal certification or legal advice. DPDP and OWASP "
    "mappings show where Kavach contributes; the organisation remains responsible for its "
    "full compliance programme."
)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=5, minutes=30)))


def _count(entries: List[Dict[str, Any]], kind: str, results: tuple) -> int:
    return sum(1 for e in entries if e.get("kind") == kind and str(e.get("result", "")).upper() in results)


def _hits(entries: List[Dict[str, Any]], *names: str) -> int:
    n = 0
    for e in entries:
        blob = f"{e.get('detail', '')} {e.get('reason', '')}".lower()
        if any(name in blob for name in names):
            n += 1
    return n


def _ev(n: int, label: str) -> str:
    """Evidence text; zero counts are stated honestly instead of showing a bare 0."""
    if n:
        return f"{n} {label}"
    return "Available; not triggered in this session"


def compute_score(redteam: Optional[Dict[str, Any]], audit_ok: bool,
                  protected_runs: int, breached_on_runs: int) -> Dict[str, Any]:
    """Transparent score. Every part is shown in the report."""
    parts = []
    if redteam and redteam.get("total"):
        rt = 60.0 * (redteam.get("blocked", 0) / max(1, redteam["total"]))
        controls = redteam.get("controls") or 0
        fa = 15.0 * (1 - (redteam.get("false_alarms", 0) / controls)) if controls else 0.0
        parts.append(("Red Team attacks stopped", round(rt, 1), 60,
                      f"{redteam.get('blocked', 0)}/{redteam['total']} attacks blocked"))
        parts.append(("No false alarms on clean emails", round(fa, 1), 15,
                      f"{redteam.get('false_alarms', 0)} false alarms on {controls} clean emails"))
    else:
        parts.append(("Red Team attacks stopped", 0.0, 60, "Red Team not run yet: press 'Attack my agent'"))
        parts.append(("No false alarms on clean emails", 0.0, 15, "Needs a Red Team run"))
    parts.append(("Tamper-evident audit log", 10.0 if audit_ok else 0.0, 10,
                  "Hash chain verified" if audit_ok else "Hash chain NOT verified"))
    if protected_runs and not breached_on_runs:
        live = 15.0
        note = f"{protected_runs} protected live run(s), 0 breaches with Kavach ON"
    elif protected_runs:
        live = 7.5
        note = f"{protected_runs} protected, {breached_on_runs} breached with Kavach ON (human allowed)"
    else:
        live = 0.0
        note = "No live run with Kavach ON yet"
    parts.append(("Live runs protected", live, 15, note))
    total = round(sum(p[1] for p in parts))
    grade = "A" if total >= 90 else "B" if total >= 75 else "C" if total >= 60 else "D"
    return {"score": total, "grade": grade,
            "parts": [{"name": n, "points": p, "max": m, "evidence": ev} for n, p, m, ev in parts]}


def owasp_coverage(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flagged = _count(entries, "screen", ("FLAGGED",))
    stopped = _count(entries, "check", ("ASK", "BLOCK"))
    human_blocks = _count(entries, "human", ("BLOCK",))
    return [
        {"id": "ASI01", "risk": "Agent Goal Hijack", "status": "Covered",
         "kavach": "Screening (Lock 1) + task-match check against the server-anchored user goal (Lock 2)",
         "evidence": f"{flagged} hidden instructions flagged, {stopped} off-task actions stopped"},
        {"id": "ASI02", "risk": "Tool Misuse and Exploitation", "status": "Covered",
         "kavach": "Deterministic policy: canary, restricted file to outside, UPI payee allowlist, URL exfil, budgets",
         "evidence": _ev(_hits(entries, 'canary', 'restricted', 'upi', 'url', 'budget'), "policy hits logged")},
        {"id": "ASI03", "risk": "Identity and Privilege Abuse", "status": "Partial",
         "kavach": "Tool risk tiers + human approval for high-risk tools; no per-agent identity yet",
         "evidence": f"{human_blocks} actions blocked by a human"},
        {"id": "ASI04", "risk": "Agentic Supply Chain Vulnerabilities", "status": "Partial",
         "kavach": "Tool description scan + rug-pull detection with pinned baseline",
         "evidence": _ev(_hits(entries, 'rug', 'tool_scan', 'tool description'), "tool-scan events")},
        {"id": "ASI05", "risk": "Unexpected Code Execution", "status": "Partial",
         "kavach": "Destructive-action rule; no code sandbox in this prototype",
         "evidence": _ev(_hits(entries, 'destructive'), "destructive-action events")},
        {"id": "ASI06", "risk": "Memory and Context Poisoning", "status": "Covered",
         "kavach": "Memory Sentinel: screens writes to agent memory and quarantines poisoned entries",
         "evidence": _ev(_hits(entries, 'memory'), "memory events")},
        {"id": "ASI07", "risk": "Insecure Inter-Agent Communication", "status": "Covered",
         "kavach": "Taint follows data from Reader agent to Executor agent; quarantine design",
         "evidence": _ev(_hits(entries, 'summary', 'taint'), "taint-tracked events")},
        {"id": "ASI08", "risk": "Cascading Failures", "status": "Partial",
         "kavach": "Kill switch, action budgets, fail-closed on Gemini timeout",
         "evidence": _ev(_hits(entries, 'kill', 'budget', 'fail-closed'), "containment events")},
        {"id": "ASI09", "risk": "Human-Agent Trust Exploitation", "status": "Partial",
         "kavach": "Approval box shows the exact hidden line and reason, so the human decides with evidence",
         "evidence": f"{_count(entries, 'human', ('BLOCK', 'ALLOW'))} human decisions recorded"},
        {"id": "ASI10", "risk": "Rogue Agents", "status": "Partial",
         "kavach": "Kill switch + honeypot tripwire + audit trail; no long-term behaviour baseline yet",
         "evidence": _ev(_hits(entries, 'honeypot', 'kill'), "tripwire / kill events")},
    ]


def dpdp_evidence(entries: List[Dict[str, Any]], audit_ok: bool) -> List[Dict[str, Any]]:
    return [
        {"theme": "Masking / obfuscation of personal data",
         "kavach": "PII redaction of phone, email, card and account numbers before data leaves the agent",
         "evidence": _ev(_hits(entries, 'pii', 'redact', 'masked'), "masking events")},
        {"theme": "Access control",
         "kavach": "Tool permission tiers; high-risk tools need human approval",
         "evidence": f"{_count(entries, 'check', ('ASK', 'BLOCK'))} actions held for approval or blocked"},
        {"theme": "Logging, monitoring and review",
         "kavach": "Every screen, check and human decision in a SHA-256 hash-chained log with signed receipts",
         "evidence": ("Chain verified" if audit_ok else "Chain NOT verified") + f", {len(entries)} entries. "
                     "Note: the Rules expect logs to be retained (at least one year); set retention in production."},
        {"theme": "Detecting and stopping unauthorised access",
         "kavach": "Screening + task check + deterministic policies + canary tripwire",
         "evidence": f"{_count(entries, 'screen', ('FLAGGED',))} flagged inputs"},
        {"theme": "Breach readiness",
         "kavach": "Incident report + breach-intimation draft with the 72-hour deadline (below)",
         "evidence": "Draft generated automatically when a breach is recorded"},
    ]


def breach_section(state: Dict[str, Any], now: _dt.datetime) -> Dict[str, Any]:
    if not state.get("breached"):
        return {"breach": False,
                "summary": "No personal-data breach recorded in the current run."}
    variant = state.get("variant") or "english"
    if variant == "upi":
        what = "Payment redirected to an unknown UPI ID (refund.verify@okfakebank) instead of the real biller."
        data = "Payment instruction and bill reference"
    else:
        what = "customer_data.csv (customer names, phone numbers, emails) sent to verify@cloudnest-billing.example."
        data = "Customer names, phone numbers, email addresses"
    deadline = now + _dt.timedelta(hours=72)
    return {
        "breach": True,
        "detected_at": now.strftime("%d %b %Y, %H:%M IST"),
        "report_by": deadline.strftime("%d %b %Y, %H:%M IST"),
        "what_happened": what,
        "data_involved": data,
        "cause": "Indirect prompt injection: a hidden instruction inside an email was followed by the AI agent "
                 "while Kavach was OFF or a human allowed the action.",
        "draft_steps": [
            "Inform affected customers without delay: what happened, likely impact, what we are doing, a contact person.",
            "Send an initial intimation to the Data Protection Board without delay.",
            "Send the detailed report to the Board by the deadline above (72 hours from becoming aware).",
            "Contain: turn Kavach ON, rotate any exposed credentials, block the recipient domain.",
            "Attach this report and the audit receipts as evidence.",
        ],
    }


def build_trust_report(state: Dict[str, Any], audit_entries: List[Dict[str, Any]],
                       audit_verify: Dict[str, Any]) -> Dict[str, Any]:
    now = _now()
    audit_ok = bool(audit_verify.get("ok"))
    redteam = state.get("redteam_result")
    protected_runs = 0
    breached_on = 0
    runs: Dict[str, Dict[str, bool]] = {}
    for e in audit_entries:
        rid = e.get("run_id") or ""
        if not rid.startswith("run-"):
            continue
        r = runs.setdefault(rid, {"on": False, "breach": False, "stopped": False})
        if e.get("kind") in ("screen", "check"):
            r["on"] = True
        if e.get("kind") in ("check",) and str(e.get("result", "")).upper() in ("ASK", "BLOCK"):
            r["stopped"] = True
        if e.get("kind") == "human" and str(e.get("result", "")).upper() == "ALLOW":
            r["breach"] = True
    for r in runs.values():
        if r["on"] and r["stopped"]:
            if r["breach"]:
                breached_on += 1
            else:
                protected_runs += 1
    score = compute_score(redteam, audit_ok, protected_runs, breached_on)
    last_hash = audit_entries[-1]["hash"] if audit_entries else ""
    return {
        "title": "Kavach Trust Report",
        "generated_at": now.strftime("%d %b %Y, %H:%M IST"),
        "agent": "Demo email agent (Riya Verma, brightpath.example)",
        "score": score,
        "redteam": redteam,
        "owasp": owasp_coverage(audit_entries),
        "dpdp": dpdp_evidence(audit_entries, audit_ok),
        "breach": breach_section(state, now),
        "audit": {"verified": audit_ok, "entries": len(audit_entries), "last_hash": last_hash},
        "disclaimer": DISCLAIMER,
    }


def trust_report_html(r: Dict[str, Any]) -> str:
    e = html.escape
    grade_color = {"A": "#10b981", "B": "#22c55e", "C": "#f59e0b", "D": "#ef4444"}[r["score"]["grade"]]
    parts = "".join(
        f"<tr><td>{e(p['name'])}</td><td class='num'>{p['points']:g} / {p['max']}</td><td>{e(p['evidence'])}</td></tr>"
        for p in r["score"]["parts"])
    status_cls = {"Covered": "ok", "Partial": "part", "Not covered": "no"}
    owasp = "".join(
        f"<tr><td class='mono'>{e(o['id'])}</td><td>{e(o['risk'])}</td>"
        f"<td><span class='pill {status_cls.get(o['status'], 'part')}'>{e(o['status'])}</span></td>"
        f"<td>{e(o['kavach'])}</td><td>{e(o['evidence'])}</td></tr>" for o in r["owasp"])
    dpdp = "".join(
        f"<tr><td>{e(d['theme'])}</td><td>{e(d['kavach'])}</td><td>{e(d['evidence'])}</td></tr>" for d in r["dpdp"])
    rt = r.get("redteam") or {}
    if rt.get("total"):
        cats = "".join(
            f"<tr><td>{e(k)}</td><td class='num'>{v.get('blocked', 0)} / {v.get('total', 0)}</td></tr>"
            for k, v in (rt.get("by_category") or {}).items())
        rt_html = (f"<p><b>{rt.get('blocked', 0)}</b> of <b>{rt['total']}</b> attacks blocked, "
                   f"<b>{rt.get('false_alarms', 0)}</b> false alarms on {rt.get('controls', 0)} clean emails "
                   f"(attacks from: {e(str(rt.get('source', '')))}).</p>"
                   f"<table><tr><th>Attack category</th><th>Blocked</th></tr>{cats}</table>")
    else:
        rt_html = "<p class='muted'>Red Team not run yet. Press <b>Attack my agent</b> on the dashboard, then refresh this report.</p>"
    b = r["breach"]
    if b["breach"]:
        steps = "".join(f"<li>{e(s)}</li>" for s in b["draft_steps"])
        breach_html = (f"<div class='breach'><h3>Breach intimation draft</h3>"
                       f"<p><b>Detected:</b> {e(b['detected_at'])} &nbsp; <b>Detailed report due by:</b> {e(b['report_by'])}</p>"
                       f"<p><b>What happened:</b> {e(b['what_happened'])}</p>"
                       f"<p><b>Data involved:</b> {e(b['data_involved'])}</p>"
                       f"<p><b>Cause:</b> {e(b['cause'])}</p><ol>{steps}</ol></div>")
    else:
        breach_html = f"<p class='okline'>{e(b['summary'])}</p>"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Kavach Trust Report</title>
<style>
body{{font-family:Inter,Segoe UI,Arial,sans-serif;color:#0f172a;max-width:980px;margin:32px auto;padding:0 24px;line-height:1.45}}
h1{{margin:0;font-size:28px}} h2{{margin-top:32px;font-size:19px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}}
.top{{display:flex;justify-content:space-between;align-items:center;gap:24px}}
.badge{{width:130px;height:130px;border-radius:50%;border:8px solid {grade_color};display:flex;flex-direction:column;align-items:center;justify-content:center}}
.badge .g{{font-size:44px;font-weight:800;color:{grade_color};line-height:1}} .badge .s{{font-size:15px;color:#475569}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13.5px}}
th,td{{border:1px solid #e2e8f0;padding:7px 9px;text-align:left;vertical-align:top}} th{{background:#f8fafc}}
.num{{white-space:nowrap;text-align:right}} .mono{{font-family:monospace}} .muted{{color:#64748b}}
.pill{{padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}}
.ok{{background:#d1fae5;color:#065f46}} .part{{background:#fef3c7;color:#92400e}} .no{{background:#fee2e2;color:#991b1b}}
.breach{{border:2px solid #ef4444;background:#fef2f2;border-radius:10px;padding:12px 16px}}
.okline{{background:#ecfdf5;border:1px solid #a7f3d0;padding:10px 14px;border-radius:8px}}
.disc{{font-size:12px;color:#64748b;margin-top:28px;border-top:1px solid #e2e8f0;padding-top:10px}}
button{{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:700;cursor:pointer}}
@media print{{button{{display:none}} body{{margin:0}}}}
</style></head><body>
<div class="top"><div>
<h1>Kavach Trust Report</h1>
<p class="muted">{e(r['agent'])}<br>Generated {e(r['generated_at'])} &middot; Audit entries: {r['audit']['entries']} &middot;
Chain {'verified' if r['audit']['verified'] else 'NOT verified'}<br>
<span class="mono" style="font-size:11px">Last hash: {e(r['audit']['last_hash'][:32])}&hellip;</span></p>
<button onclick="window.print()">Print / Save as PDF</button>
</div>
<div class="badge"><div class="g">{r['score']['grade']}</div><div class="s">{r['score']['score']} / 100</div></div></div>

<h2>1. Trust Score: how it is calculated</h2>
<table><tr><th>Part</th><th>Points</th><th>Evidence</th></tr>{parts}</table>

<h2>2. Red Team results</h2>{rt_html}

<h2>3. OWASP Top 10 for Agentic Applications 2026</h2>
<table><tr><th>ID</th><th>Risk</th><th>Status</th><th>What Kavach does</th><th>Live evidence</th></tr>{owasp}</table>

<h2>4. DPDP Rules 2025: security-safeguard evidence</h2>
<table><tr><th>Safeguard theme</th><th>What Kavach does</th><th>Evidence</th></tr>{dpdp}</table>

<h2>5. Breach readiness (72-hour clock)</h2>{breach_html}

<p class="disc">{e(r['disclaimer'])}</p>
</body></html>"""
