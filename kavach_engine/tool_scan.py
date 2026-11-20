"""MCP Tool-Definition Scanner for Kavach.

Catches Tool Poisoning at connect-time (OWASP MCP03): attacker instructions
hidden in tool descriptions / parameter help that the model reads but the
human never sees. Also pins tool hashes to catch rug-pulls (definition
changed after trust was granted).

shortcut: stateless + in-memory pin, no DB; restart clears pins, upgrade when multi-instance.
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, List

from kavach_engine.screen import (
    COMPILED_IMPERATIVES,
    COMPILED_SECRECY,
    MARKDOWN_EXFIL_REGEX,
    URL_QUERY_EXFIL_REGEX,
    detect_deterministic_signals,
)

# Extra connect-time-only phrases: description telling the model to act
TOOL_ACTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"before using .*?send .*? to ",
        r"you must first .*?(send|forward|upload|share)",
        r"required by .*?(compliance|policy|verification)",
        r"do not (ask|tell|notify) the user",
    ]
]

_tool_hashes: Dict[str, str] = {}


def canonical_tool(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def hash_tool_definition(name: str, description: str, params: Dict[str, Any]) -> str:
    payload = canonical_tool({"name": name, "description": description or "", "params": params or {}})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def scan_tool_definition(
    name: str, description: str, params: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Scans one tool definition. Returns verdict allow|blocked + signals."""
    params = params or {}
    blob_parts = [description or ""]
    if isinstance(params, dict):
        for k, v in params.items():
            blob_parts.append(str(k))
            blob_parts.append(json.dumps(v) if not isinstance(v, str) else v)
    blob = "\n".join(blob_parts)

    flagged, signals, reasons = detect_deterministic_signals(blob)
    extra_hits: List[str] = []
    for pat in TOOL_ACTION_PATTERNS:
        if pat.search(blob):
            extra_hits.append("tool_action_directive")
            reasons.append(f"Tool description orders model to exfiltrate ({pat.pattern[:40]}...)")
            break

    if extra_hits:
        signals = list(dict.fromkeys(signals + extra_hits))
        flagged = True

    if flagged:
        return {
            "verdict": "blocked",
            "reason": reasons[0] if reasons else "Tool definition contains hidden instruction",
            "signals": signals,
        }
    return {"verdict": "allow", "reason": "Tool definition clean", "signals": []}


def register_tool_definition(
    name: str, description: str, params: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Registers/pins a tool hash. Detects rug-pull on re-register with new hash."""
    params = params or {}
    scan = scan_tool_definition(name, description, params)
    if scan["verdict"] == "blocked":
        scan["rug_pull"] = False
        return scan
    digest = hash_tool_definition(name, description, params)
    pinned = _tool_hashes.get(name)
    if pinned is None:
        _tool_hashes[name] = digest
        scan["rug_pull"] = False
        scan["hash"] = digest
        return scan
    if pinned != digest:
        return {
            "verdict": "blocked",
            "reason": "Tool definition changed after trust (rug-pull)",
            "signals": ["rug_pull"],
            "rug_pull": True,
        }
    scan["rug_pull"] = False
    scan["hash"] = digest
    return scan


def clear_tool_registry() -> None:
    _tool_hashes.clear()


# --- V2: persistent hash pinning (rug-pull detection) ---
BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "tool_baseline.json",
)

def _norm_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": str(tool.get("name", "")),
        "description": str(tool.get("description", "") or ""),
        "params": tool.get("params") or tool.get("inputSchema") or tool.get("schema") or {},
    }

def _load_baseline_file() -> Dict[str, str]:
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}

def get_tool_baseline() -> Dict[str, str]:
    """Merged baseline: file on disk wins, else in-memory pins."""
    merged = dict(_tool_hashes)
    merged.update(_load_baseline_file())
    return merged

def pin_tool_definitions(tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pin SHA-256 hashes of each tool's name+description+schema.
    Stored in memory AND in data/tool_baseline.json so a later scan can
    detect a definition that changed after trust was granted."""
    pinned: Dict[str, str] = {}
    for tool in tools or []:
        nt = _norm_tool(tool)
        if not nt["name"]:
            continue
        digest = hash_tool_definition(nt["name"], nt["description"], nt["params"])
        _tool_hashes[nt["name"]] = digest
        pinned[nt["name"]] = digest
    try:
        os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(dict(sorted(pinned.items())), f, indent=2, sort_keys=True)
    except Exception:
        pass
    return {"pinned": len(pinned), "hashes": pinned}

def check_tool_drift(tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare current tool definitions against the pinned baseline.
    Returns changed/added/removed + rug_pull_suspected (True when a pinned
    tool's description/schema hash changed)."""
    baseline = get_tool_baseline()
    if not baseline:
        names = [str(t.get("name", "")) for t in (tools or []) if t.get("name")]
        return {"baseline_exists": False, "changed": [], "added": names,
                "removed": [], "rug_pull_suspected": False}
    current: Dict[str, str] = {}
    for tool in tools or []:
        nt = _norm_tool(tool)
        if nt["name"]:
            current[nt["name"]] = hash_tool_definition(nt["name"], nt["description"], nt["params"])
    changed = sorted(n for n in current if n in baseline and baseline[n] != current[n])
    added = sorted(n for n in current if n not in baseline)
    removed = sorted(n for n in baseline if n not in current)
    return {"baseline_exists": True, "changed": changed, "added": added,
            "removed": removed, "rug_pull_suspected": bool(changed)}

def clear_tool_baseline() -> None:
    _tool_hashes.clear()
    try:
        if os.path.exists(BASELINE_FILE):
            os.remove(BASELINE_FILE)
    except Exception:
        pass
