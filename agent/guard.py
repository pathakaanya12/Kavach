"""Kavach Guard - Interception Layer.

Sits between the AI agent and the external world/tools.
Enforces screening before reads and verification before tool execution.
When Kavach is OFF, interception is bypassed and actions are logged as kavach_off.
"""

import asyncio
import os
import json
from typing import Dict, Any, List, Optional, Callable

from sdk.kavach_client import KavachClient
from kavach_engine.audit import record_entry
import agent.tools as fake_tools

class KavachGuard:
    def __init__(
        self,
        run_id: str,
        user_task: str,
        session_id: Optional[str] = None,
        is_active: bool = True,
        client: Optional[KavachClient] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        approval_handler: Optional[Callable[[str, str, Dict[str, Any], str, List[str]], Any]] = None,
        kill_check: Optional[Callable[[], bool]] = None,
        kill_action: Optional[Callable[[], None]] = None,
        incident_handler: Optional[Callable[[Dict[str, Any]], None]] = None,
        contract: Optional[Dict[str, Any]] = None,
    ):
        self.run_id = run_id
        self.session_id = session_id or run_id
        self.user_task = user_task
        self.is_active = is_active
        self.client = client or KavachClient()
        self.event_emitter = event_emitter
        self.approval_handler = approval_handler
        self.kill_check = kill_check
        self.kill_action = kill_action
        self.incident_handler = incident_handler
        self.contract = contract
        self.budget_counts: Dict[str, Any] = {"total_calls": 0, "send_email": 0, "file_reads": 0, "total_paid": 0.0}
        self.budget_exceeded: bool = False
        self.last_incident: Optional[Dict[str, Any]] = None
        # v4: tool-call history for toxic-flow chain detection.
        self.tool_history: List[Dict[str, Any]] = []

        self.flagged_sources: List[str] = []
        self.context_sources: List[str] = []
        self.source_texts: Dict[str, str] = {}
        self.last_hidden_instruction: str = ""

    def emit(self, event_type: str, message: str, data: Optional[Dict[str, Any]] = None):
        if self.event_emitter:
            self.event_emitter({
                "type": event_type,
                "message": message,
                "data": data or {}
            })

    def _make_incident(self, tool: str, args: Dict[str, Any], policy_hits: List[str], reason: str):
        try:
            from kavach_engine.incident import generate_incident_report
            src = self.flagged_sources[0] if self.flagged_sources else ""
            rep = generate_incident_report(tool, args, policy_hits, reason,
                                           source=src, hidden_line=self.last_hidden_instruction)
            self.last_incident = rep
            if self.incident_handler:
                self.incident_handler(rep)
        except Exception:
            pass

    async def read(self, source: str, text: str) -> str:
        """
        Interception before reading external content.
        If Kavach is ON: screens text and returns sanitized version.
        If Kavach is OFF: returns raw text directly.
        """
        self.context_sources.append(source)
        self.source_texts[source] = text

        if not self.is_active:
            # Kavach OFF - Agent reads raw untrusted text with hidden instructions
            record_entry(
                run_id=self.run_id,
                kind="kavach_off",
                detail=f"Read {source} ({len(text)} chars)",
                result="UNSCREENED",
                reason="Kavach is OFF - input screening bypassed"
            )
            self.emit("agent_read", f"Read {source} (Kavach OFF - unshielded)", {
                "source": source,
                "raw_text": text,
                "status": "unscreened"
            })
            return text

        # Kavach ON - Screen content
        self.emit("screen_start", f"Screening content from {source}...", {"source": source})

        try:
            from kavach_engine.screen import screen_content
            res = screen_content(self.run_id, source, text, session_id=self.session_id)
        except Exception:
            res = self.client.screen(self.run_id, source, text, session_id=self.session_id)

        # Record screening audit entry
        record_entry(
            run_id=self.run_id,
            kind="screen",
            detail=f"Source: {source}",
            result=res["verdict"].upper(),
            reason=res["reason"]
        )

        # v4: the agent sees the REDACTED text — PII is masked in what
        # it reads, never blocked. Sanitized text is kept for the audit.
        redacted = res.get("redacted_text") or res.get("sanitized_text", text)
        if res["verdict"] == "flagged":
            self.flagged_sources.append(source)
            self.emit("screen_flagged", f"⚠️ FLAGGED {source}: {res['reason']}", {
                "source": source,
                "signals": res.get("signals", []),
                "reason": res["reason"],
                "raw_text": text
            })
            return redacted
        else:
            self.emit("screen_safe", f"✓ Safe {source}: {res['reason']}", {"source": source})
            return redacted

    async def call(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Interception before calling any tool.
        If Kavach is ON: checks policy and task alignment.
        If Kavach is OFF: tool runs directly.
        """
        tool_func = getattr(fake_tools, tool, None)
        if not tool_func:
            return {"status": "error", "message": f"Unknown tool: {tool}"}

        # V3 honeypot: instant block + kill, even when Kavach is OFF.
        try:
            from kavach_engine.policy import is_honeypot as _is_hp
        except Exception:
            _is_hp = lambda t: t in ("export_all_customers", "admin_transfer", "admin_reset_password")
        if _is_hp(tool):
            self.emit("honeypot", f"🍯 HONEYPOT '{tool}' called — confirmed hijack, killing run", {"tool": tool, "args": args})
            record_entry(run_id=self.run_id, kind="tool", detail=f"Honeypot {tool}({json.dumps(args)})",
                         result="BLOCKED", reason="Honeypot decoy tool called — confirmed hijack")
            if self.kill_action:
                try:
                    self.kill_action()
                except Exception:
                    pass
            self._make_incident(tool, args, ["honeypot_triggered"], "Honeypot decoy tool called — confirmed hijack")
            return {"status": "blocked", "tool": tool, "reason": "Honeypot triggered — confirmed hijack, run killed"}

        # v4: record this attempted call in the chain history (current
        # call excluded from the history passed to the check below).
        _prior_history = list(self.tool_history)
        self.tool_history.append({"tool": tool, "args": dict(args or {})})

        # V3 session budget: count this attempted call, then enforce.
        self.budget_counts["total_calls"] = int(self.budget_counts.get("total_calls", 0)) + 1
        if tool == "send_email":
            self.budget_counts["send_email"] = int(self.budget_counts.get("send_email", 0)) + 1
        if tool in ("read_email", "get_emails", "list_files"):
            self.budget_counts["file_reads"] = int(self.budget_counts.get("file_reads", 0)) + 1
        if tool == "pay_bill":
            try:
                self.budget_counts["total_paid"] = float(self.budget_counts.get("total_paid", 0)) + float(args.get("amount", 0) or 0)
            except (TypeError, ValueError):
                pass
        try:
            from kavach_engine.policy import check_session_budget as _csb
            _exceeded, _breason = _csb(tool, args, self.budget_counts)
        except Exception:
            _exceeded, _breason = False, ""
        if _exceeded:
            self.budget_exceeded = True
            self.emit("budget_exceeded", f"⏱️ Session budget exceeded — {_breason}", {"tool": tool, "args": args})
            record_entry(run_id=self.run_id, kind="tool", detail=f"Budget stop {tool}({json.dumps(args)})",
                         result="BLOCKED", reason=_breason)
            self._make_incident(tool, args, ["session_budget_exceeded"], _breason)
            return {"status": "blocked", "tool": tool, "reason": _breason}

        # Kill switch (V2): stop before ANY further tool call, even OFF.
        if self.kill_check and self.kill_check():
            self.emit("killed", "Kill switch active — tool call stopped", {"tool": tool, "args": args})
            return {"status": "killed", "tool": tool, "reason": "Kill switch activated - run stopped"}

        args_str = json.dumps(args)

        if not self.is_active:
            record_entry(
                run_id=self.run_id,
                kind="kavach_off",
                detail=f"Tool call: {tool}({args_str})",
                result="UNCHECKED",
                reason="Kavach is OFF - tool call executed without task verification"
            )
            self.emit("tool_unshielded", f"Calling {tool} (Kavach OFF)", {"tool": tool, "args": args})
            return tool_func(**args)

        self.emit("check_start", f"Kavach checking tool call: {tool}...", {"tool": tool, "args": args})

        try:
            from kavach_engine.check import check_action
            check_res = check_action(
                run_id=self.run_id,
                session_id=self.session_id,
                user_task=self.user_task,
                tool=tool,
                args=args,
                flagged_sources=self.flagged_sources,
                context_sources=self.context_sources,
                budget=dict(self.budget_counts),
                contract=self.contract,
                history=_prior_history,
            )
        except Exception:
            check_res = self.client.check(
                session_id=self.session_id,
                run_id=self.run_id,
                user_task=self.user_task,
                tool=tool,
                args=args,
                flagged_sources=self.flagged_sources,
                context_sources=self.context_sources
            )

        decision = check_res.get("decision", "allow")
        reason = check_res.get("reason", "")
        policy_hits = check_res.get("policy_hits", [])

        if decision == "allow":
            self.emit("check_allow", f"✓ Kavach: ALLOW - {reason}", {"tool": tool, "args": args})
            result = tool_func(**args)
            record_entry(
                run_id=self.run_id,
                kind="tool",
                detail=f"Executed {tool}({args_str})",
                result="SUCCESS",
                reason=reason
            )
            return result

        elif decision == "block":
            if "honeypot_triggered" in policy_hits and self.kill_action:
                try:
                    self.kill_action()
                except Exception:
                    pass
            self._make_incident(tool, args, policy_hits, reason)
            self.emit("check_block", f"🛑 Kavach: BLOCK - {reason}", {
                "tool": tool,
                "args": args,
                "policy_hits": policy_hits
            })
            record_entry(
                run_id=self.run_id,
                kind="tool",
                detail=f"Blocked {tool}({args_str})",
                result="BLOCKED",
                reason=reason
            )
            return {"status": "blocked", "tool": tool, "reason": reason}

        elif decision == "ask":
            self.emit("check_ask", f"⚠️ Kavach: ASK - Human Approval Required: {reason}", {
                "tool": tool,
                "args": args,
                "reason": reason,
                "policy_hits": policy_hits
            })

            human_decision = "block"
            if self.approval_handler:
                try:
                    # Exact hidden line that caused this action, for the
                    # approval modal (red highlight). Searched in flagged
                    # sources first, then any read source.
                    from kavach_engine.screen import extract_hidden_instruction
                    hidden = ""
                    for src in list(self.flagged_sources) + list(self.source_texts):
                        hidden = extract_hidden_instruction(self.source_texts.get(src, ""))
                        if hidden:
                            break
                    self.last_hidden_instruction = hidden
                    try:
                        human_decision = await self.approval_handler(
                            self.run_id, tool, args, reason, policy_hits, hidden
                        )
                    except TypeError:
                        human_decision = await self.approval_handler(
                            self.run_id, tool, args, reason, policy_hits
                        )
                except Exception:
                    human_decision = "block"

            record_entry(
                run_id=self.run_id,
                kind="human",
                detail=f"Approval for {tool}({args_str})",
                result=human_decision.upper(),
                reason=f"Human operator clicked {human_decision.upper()}"
            )

            if human_decision == "allow":
                self.emit("human_approved", f"✓ Human operator APPROVED {tool}", {"tool": tool})
                result = tool_func(**args)
                record_entry(
                    run_id=self.run_id,
                    kind="tool",
                    detail=f"Executed {tool}({args_str}) [post-approval]",
                    result="SUCCESS",
                    reason="Human approved"
                )
                return result
            else:
                self._make_incident(tool, args, policy_hits, reason)
                self.emit("human_blocked", f"🛑 Human operator BLOCKED {tool}", {"tool": tool})
                record_entry(
                    run_id=self.run_id,
                    kind="tool",
                    detail=f"Blocked {tool}({args_str}) by human decision",
                    result="BLOCKED_BY_HUMAN",
                    reason="Operator rejected action"
                )
                return {"status": "blocked", "tool": tool, "reason": "Operator rejected action"}

        return {"status": "error", "message": f"Unknown decision: {decision}"}
