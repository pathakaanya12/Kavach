"""Kavach Demo Agent.

Reads user task and emails via guard.read(),
plans tool actions using Gemini or scripted fallback planner,
and executes tool calls via guard.call().
"""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional, Callable
from dotenv import load_dotenv

from agent.guard import KavachGuard
from agent.planner_scripted import plan_scripted_actions
from kavach_engine.prompts import AGENT_SYSTEM_PROMPT

load_dotenv()

async def call_gemini_planner(user_task: str, read_emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Calls Gemini model to plan tool calls based on emails read."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    model_name = os.getenv("AGENT_MODEL", "gemini-3.8-flash")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not configured")

    import requests

    context_text = f"USER GOAL: {user_task}\n\nINBOX EMAILS:\n"
    for email in read_emails:
        context_text += f"--- Email ID: {email['id']} | From: {email.get('from', '')} | Subject: {email.get('subject', '')} ---\n{email.get('text', '')}\n\n"

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": f"{AGENT_SYSTEM_PROMPT}\n\n{context_text}"}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}
    }

    import time as _time
    last_status = None
    for attempt in range(2):
        resp = requests.post(endpoint, json=payload, timeout=8.0)
        last_status = resp.status_code
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict) and "actions" in parsed:
                return parsed["actions"]
            break
        if resp.status_code in (429, 503) and attempt == 0:
            _time.sleep(2.5)
            continue
        break
    raise RuntimeError(f"Gemini planner returned status {last_status}")

class DemoAgent:
    def __init__(self, guard: KavachGuard):
        self.guard = guard
        self.active_planner = "scripted"

    async def run(
        self,
        emails: List[Dict[str, Any]],
        variant: str = "english"
    ) -> Dict[str, Any]:
        """
        Executes the agent lifecycle:
        1. Read all inbox emails via guard.read()
        2. Plan tool calls (Gemini or scripted fallback)
        3. Execute tool calls via guard.call()
        """
        self.guard.emit("agent_start", f"Agent activated for user task: '{self.guard.user_task}'")

        # Step 1: Read all emails through guard
        read_emails: List[Dict[str, Any]] = []
        for em in emails:
            source_id = f"email:{em['id']}"
            raw_body = em["body"]

            # Intercept read through guard
            sanitized_body = await self.guard.read(source_id, raw_body)
            read_emails.append({
                "id": em["id"],
                "from": em.get("from", ""),
                "subject": em.get("subject", ""),
                "text": sanitized_body,
                "raw_body": raw_body
            })

            # Small delay for realistic UI streaming
            await asyncio.sleep(0.3)

        # Step 2: Plan tool actions
        planner_mode = os.getenv("AGENT_PLANNER", "auto").lower()
        actions: List[Dict[str, Any]] = []

        if planner_mode in ["gemini", "auto"]:
            try:
                self.guard.emit("planner_thinking", "Consulting Gemini model to plan tool calls...")
                actions = await call_gemini_planner(self.guard.user_task, read_emails)
                self.active_planner = "gemini"
                try:
                    from kavach_engine.health import note_gemini
                    note_gemini(True)
                except Exception:
                    pass

                # If Run 1 (unshielded) and Gemini didn't produce the attack call, fall back to scripted
                has_attack = any("customer_data" in json.dumps(a) for a in actions)
                if not self.guard.is_active and not has_attack and planner_mode == "auto":
                    self.guard.emit("planner_fallback", "Auto-fallback to scripted planner to ensure deterministic demo test.")
                    actions = plan_scripted_actions(self.guard.user_task, read_emails)
                    self.active_planner = "scripted"
            except Exception as e:
                try:
                    from kavach_engine.health import note_gemini
                    note_gemini(False, f"planner: {str(e)[:80]}")
                except Exception:
                    pass
                self.guard.emit("planner_fallback", f"Gemini planner unavailable ({str(e)[:60]}); using scripted planner.")
                actions = plan_scripted_actions(self.guard.user_task, read_emails)
                self.active_planner = "scripted"
        else:
            actions = plan_scripted_actions(self.guard.user_task, read_emails)
            self.active_planner = "scripted"

        self.guard.emit("planner_ready", f"Planner ({self.active_planner}) generated {len(actions)} actions.")

        # Step 3: Execute tool actions through guard
        results = []
        for action in actions:
            tool = action.get("tool")
            args = action.get("args", {})
            self.guard.emit("action_attempt", f"Attempting action: {tool} with args {args}")

            res = await self.guard.call(tool, args)
            results.append({"tool": tool, "args": args, "result": res})
            if isinstance(res, dict) and res.get("status") == "killed":
                break
            await asyncio.sleep(0.4)

        return {
            "status": "completed",
            "planner": self.active_planner,
            "actions_executed": results
        }
