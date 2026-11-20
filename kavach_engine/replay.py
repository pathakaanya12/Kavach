"""Attack Replay — "Kaun zimmedar" (v3).

Builds a causal chain from the events already recorded in the run
timeline + audit log. It invents NO new events: every step comes from
an event the system actually emitted. The chain answers, in plain
words: what was read, what was flagged, what was attempted, and what
was blocked — in order.
"""

from typing import Any, Dict, List

_STEP_TEXT = {
    "agent_read": lambda e: f"Read {e.get('data', {}).get('source', 'a source')}",
    "screen_flagged": lambda e: f"Flagged {e.get('data', {}).get('source', 'a source')}: {e.get('data', {}).get('reason', '')}",
    "screen_safe": lambda e: f"Checked {e.get('data', {}).get('source', 'a source')} — clean",
    "check_block": lambda e: f"Blocked {e.get('data', {}).get('tool', 'a tool call')}: {e.get('message', '')}",
    "check_ask": lambda e: f"Asked a human about {e.get('data', {}).get('tool', 'a tool call')}",
    "human_blocked": lambda e: f"Human blocked {e.get('data', {}).get('tool', 'a tool call')}",
    "human_approved": lambda e: f"Human approved {e.get('data', {}).get('tool', 'a tool call')}",
    "data_breach": lambda e: f"BREACH: {e.get('message', '')}",
    "tool_execution": lambda e: f"Ran {e.get('data', {}).get('tool', 'a tool')}",
    "tool_unshielded": lambda e: f"Ran {e.get('data', {}).get('tool', 'a tool')} (Kavach OFF, unchecked)",
    "taint_propagated": lambda e: f"Taint traced: {e.get('data', {}).get('taint_path', 'email:3 → summary → executor')}",
    "taint_missing": lambda e: "No taint label — poison travelled unchecked",
    "killed": lambda e: "Kill Switch pressed — run stopped",
    "reader_summary": lambda e: "Reader wrote a summary from the 4 emails",
    "executor_start": lambda e: "Executor planned tool calls from the summary only",
    "check_allow": lambda e: f"Allowed {e.get('data', {}).get('tool', 'a tool call')}",
}


def build_replay(events: List[Dict[str, Any]], status: str = "") -> Dict[str, Any]:
    """Ordered causal chain for the current/last run."""
    steps: List[Dict[str, Any]] = []
    for i, evt in enumerate(events or []):
        etype = evt.get("type", "")
        fn = _STEP_TEXT.get(etype)
        if fn is None:
            # Keep unknown events out of the story, except starts.
            if etype in ("agent_start", "reader_start", "planner_ready", "screen_start", "check_start", "action_attempt"):
                continue
            text = evt.get("message") or etype
        else:
            text = fn(evt)
        steps.append({
            "n": len(steps) + 1,
            "type": etype,
            "text": text,
            "source": (evt.get("data") or {}).get("source", ""),
            "tool": (evt.get("data") or {}).get("tool", ""),
        })
    blocked = any(s["type"] in ("check_block", "human_blocked") for s in steps)
    breached = any(s["type"] == "data_breach" for s in steps)
    verdict = "breached" if breached else ("blocked" if blocked else (status or "done"))
    return {
        "steps": steps,
        "count": len(steps),
        "verdict": verdict,
        "summary": (
            f"{len(steps)} steps. "
            + ("The attack was blocked before any data left the company."
               if blocked and not breached else
               "The attack succeeded — data left the company."
               if breached else "No attack step was blocked in this run.")
        ),
    }
