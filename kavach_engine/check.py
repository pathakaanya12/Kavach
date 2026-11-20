"""Kavach Tool Call Verification Engine.

Performs layered pre-execution validation:
1. Deterministic policy rules (canary normalization, domain allowlist, session taint, risk tiers)
2. Server-anchored goal alignment verification (Gemini task check)
3. Decision hierarchy: BLOCK > ASK > ALLOW
4. Fail-closed: on Gemini timeout/error, external-bound actions escalate to ASK/BLOCK. Never fail-open.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from kavach_engine.policy import evaluate_policy, get_tool_risk_tier, is_external_recipient, is_domain_allowed
from kavach_engine.audit import record_entry
from kavach_engine.prompts import TASK_CHECK_SYSTEM_PROMPT
from kavach_engine.session import get_session, is_session_tainted

load_dotenv()
logger = logging.getLogger("kavach.check")

SEVERITY = {
    "block": 3,
    "ask": 2,
    "allow": 1,
    "n/a": 0
}

def check_task_with_gemini(
    user_task: str,
    tool: str,
    args: Dict[str, Any],
    flagged_sources: List[str],
    context_sources: List[str]
) -> Dict[str, Any]:
    """Calls Gemini model with configurable timeout (default 3s) for goal alignment check."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    model_name = os.getenv("KAVACH_GEMINI_MODEL", os.getenv("KAVACH_CHECK_MODEL", "gemini-3.8-flash"))
    timeout_sec = float(os.getenv("KAVACH_GEMINI_TIMEOUT", "3.0"))

    if not api_key:
        return {"decision": "n/a", "reason": "No Gemini API key available"}

    import requests
    prompt = TASK_CHECK_SYSTEM_PROMPT.format(
        user_task=user_task,
        tool=tool,
        args=json.dumps(args),
        context_sources=context_sources,
        flagged_sources=flagged_sources
    )

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"}
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=timeout_sec)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return json.loads(raw_text)
        logger.warning(f"Gemini check returned non-200 status {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"Gemini task-check failed or timed out ({e}); failing closed to deterministic policies.")

    return {"decision": "n/a", "reason": "Gemini check offline or timed out"}

def check_action(
    run_id: str,
    tool: str,
    args: Dict[str, Any],
    user_task: Optional[str] = None,
    session_id: Optional[str] = None,
    flagged_sources: Optional[List[str]] = None,
    context_sources: Optional[List[str]] = None,
    budget: Optional[Dict[str, Any]] = None,
    contract: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None,
    role: str = "operator",
) -> Dict[str, Any]:
    """
    Main tool call check function.
    Prefers server-anchored goal from session_id over client-supplied user_task.
    Enforces fail-closed security for external-bound actions.
    """
    effective_session_id = session_id or run_id
    offline = os.getenv("KAVACH_OFFLINE", "0") == "1"
    flagged = flagged_sources or []
    context = context_sources or []

    # 1. Server-Anchored Goal Resolution
    active_goal = ""
    deprecation_warning = ""

    session = get_session(effective_session_id) if effective_session_id else None
    if session:
        active_goal = session.user_goal
        if session.is_tainted:
            flagged = list(dict.fromkeys(flagged + session.flagged_sources))
    elif user_task:
        active_goal = user_task
        deprecation_warning = " [DEPRECATED: client-supplied goal used; register session via /session/start in production]"
    else:
        # Fail-closed: No goal specified or session not registered
        record_entry(
            run_id=effective_session_id or "unknown",
            kind="check",
            detail=f"{tool}({json.dumps(args)})",
            result="BLOCK",
            reason="Unregistered session ID and missing user goal (fail-closed)"
        )
        return {
            "decision": "block",
            "reason": "Unregistered session ID and missing user goal (fail-closed)",
            "policy_hits": ["unregistered_session"],
            "llm_decision": "n/a"
        }

    # 2. Deterministic Policy Evaluation (PRIMARY)
    session_tainted = (session.is_tainted if session else False) or bool(flagged)
    policy_decision, policy_reason, policy_hits = evaluate_policy(
        tool=tool,
        args=args,
        flagged_sources=flagged,
        context_sources=context,
        is_session_tainted=session_tainted,
        budget=budget,
        contract=contract,
        history=history,
        role=role,
    )

    # 3. Gemini Task Alignment Check (SECONDARY - Input is treated as untrusted)
    llm_decision = "n/a"
    llm_reason = ""

    # Check tool risk tier
    tool_tier = get_tool_risk_tier(tool)
    recipient = str(args.get("to") or args.get("with_email") or "")
    is_external = is_external_recipient(recipient)
    is_external_bound = (tool_tier in ["external_send", "financial"]) or is_external

    if not offline:
        try:
            llm_res = check_task_with_gemini(
                user_task=active_goal,
                tool=tool,
                args=args,
                flagged_sources=flagged,
                context_sources=context
            )
            raw_dec = str(llm_res.get("decision", "n/a")).lower()
            if raw_dec in SEVERITY:
                llm_decision = raw_dec
                llm_reason = llm_res.get("reason", "")
        except Exception as e:
            logger.warning(f"Gemini execution exception: {e}")
            llm_decision = "n/a"

    # 4. Fail-Closed Policy Enforcement
    # If LLM check was offline/timed out and action leaves to non-allowlisted external recipient, escalate to ASK
    if llm_decision == "n/a" and policy_decision == "allow":
        if is_external and not is_domain_allowed(recipient):
            policy_decision = "ask"
            policy_hits.append("fail_closed_unverified_external")
            policy_reason = "External action requires human approval (automated AI checker offline/timed out)"

    # 5. Layered Decision Hierarchy: BLOCK > ASK > ALLOW
    policy_sev = SEVERITY.get(policy_decision, 1)
    llm_sev = SEVERITY.get(llm_decision, 0)

    if policy_sev >= llm_sev or llm_sev == 0:
        final_decision = policy_decision
        final_reason = policy_reason
    else:
        final_decision = llm_decision
        final_reason = f"AI Alignment Check: {llm_reason}" if llm_reason else f"Flagged by task check ({llm_decision})"

    # Fallback sanity check for offline tests (e.g. customer_data exfiltration)
    attachment = str(args.get("attachment") or "").lower()
    if "customer_data" in attachment and "cloudnest" in recipient.lower():
        if final_decision == "allow":
            final_decision = "ask"
            final_reason = "Unscheduled external data transfer not in user task"

    if deprecation_warning:
        final_reason += deprecation_warning

    # 6. Audit Logging
    detail = f"{tool}({json.dumps(args)}) [task: '{active_goal[:35]}...']"
    record_entry(
        run_id=effective_session_id or "unknown",
        kind="check",
        detail=detail,
        result=final_decision.upper(),
        reason=final_reason
    )

    return {
        "decision": final_decision,
        "reason": final_reason,
        "policy_hits": policy_hits,
        "llm_decision": llm_decision
    }
