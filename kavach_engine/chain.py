"""Tool-call chain / toxic-flow detection — Kavach v4.

Kavach v1-v3 checked each tool call in isolation. A multi-step attack
split across individually-benign calls can slip through that: read a
file, then (a few innocent calls later) send it outside. This module
detects dangerous SEQUENCES from the run's tool-call history with gap
tolerance — innocent calls in between do not evade it.

Patterns are (earlier-step tools, final tool, final-call condition).
All deterministic, no LLM, no network. History is a list of
{"tool": str, "args": dict} in call order (current call excluded).
"""

from typing import Any, Dict, List, Optional, Tuple

_READ_TOOLS = {"read_email", "get_emails", "list_files"}
_EXTERNAL_TOOLS = {"send_email", "share_file", "upload_file", "http_post"}
_DESTRUCTIVE_TOOLS = {"delete_file", "delete_database", "drop_table",
                      "truncate_table", "remove_file", "erase_file"}
_GAP = 6  # look back at most 6 prior calls

# (name, earlier tools, final tools, description)
_PATTERNS = [
    ("read_then_exfil", _READ_TOOLS, _EXTERNAL_TOOLS,
     "read → stage → exfil: data was read, then sent outside"),
    ("read_then_delete", _READ_TOOLS, _DESTRUCTIVE_TOOLS,
     "read → delete: data was read, then destroyed"),
    ("read_then_pay_new", _READ_TOOLS, {"pay_bill"},
     "read → pay new payee: data was read, then money moved"),
    ("stage_then_exfil", {"share_file", "upload_file"}, _EXTERNAL_TOOLS,
     "stage → exfil: a file was staged, then sent outside"),
    ("secrets_then_network", {"read_email", "get_emails"},
     {"http_post", "send_email"},
     "secrets → network: an email was read, then data left over the network"),
]


def _is_external_final(tool: str, args: Dict[str, Any]) -> bool:
    """Final step only counts as exfil when it leaves the company:
    an external recipient, a restricted attachment, or a non-allowlisted URL."""
    to = str(args.get("to") or args.get("with_email") or "").strip().lower()
    if to and not to.endswith("@brightpath.example"):
        return True
    att = str(args.get("attachment") or args.get("file") or "").lower()
    if "customer_data" in att:
        return True
    url = str(args.get("url") or args.get("target") or "").lower()
    if url and "brightpath.example" not in url:
        return True
    return False


def detect_toxic_flow(
    history: List[Dict[str, Any]],
    tool: str,
    args: Optional[Dict[str, Any]] = None,
    gap: int = _GAP,
) -> Tuple[bool, str, str]:
    """Returns (matched, pattern_name, description).

    A pattern matches when an earlier-step tool appears in the last
    `gap` history entries and the current call is the pattern's final
    tool. External-final patterns additionally require the final call
    to actually leave the company (see _is_external_final), so the
    legitimate bill + manager-report flow never triggers.
    """
    args = args or {}
    recent = list(history or [])[-gap:]
    earlier = {str(h.get("tool", "")).strip().lower() for h in recent}
    current = (tool or "").strip().lower()
    for name, first_tools, final_tools, desc in _PATTERNS:
        if current not in final_tools:
            continue
        if not (earlier & first_tools):
            continue
        if name in ("read_then_exfil", "stage_then_exfil", "secrets_then_network"):
            if not _is_external_final(current, args):
                continue
        if name == "read_then_pay_new":
            payee = str(args.get("payee", "")).strip().lower()
            if payee in ("delhi power board", ""):
                continue
        return True, name, desc
    return False, "", ""


def chain_summary(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Small summary of the run's tool-call chain for the dashboard."""
    tools = [str(h.get("tool", "")) for h in (history or [])]
    return {"calls": len(tools), "sequence": tools,
            "reads": sum(1 for t in tools if t in _READ_TOOLS),
            "external": sum(1 for t in tools if t in _EXTERNAL_TOOLS)}
