"""Kavach Client SDK.

Minimal HTTP client to interact with the Kavach Security Engine.
Enables any agent, tool, or framework to integrate Kavach protection.
"""

from typing import Dict, Any, List, Optional
import os
import httpx

class KavachBlockedException(Exception):
    """Raised when a tool call is blocked by Kavach policy or human operator."""
    pass

class KavachClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("KAVACH_API_KEY", "kavach-secret-key")

    def start_session(self, user_goal: str, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Registers a server-anchored user goal before the agent starts executing."""
        url = f"{self.base_url}/session/start"
        headers = {"X-API-Key": self.api_key}
        payload = {"user_goal": user_goal, "session_id": session_id, "metadata": metadata or {}}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def screen(self, run_id: str, source: str, text: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Screens input text before agent consumes it."""
        url = f"{self.base_url}/screen"
        payload = {
            "run_id": run_id,
            "session_id": session_id or run_id,
            "source": source,
            "text": text
        }
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()

    def check(
        self,
        tool: str,
        args: Dict[str, Any],
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        user_task: Optional[str] = None,
        flagged_sources: Optional[List[str]] = None,
        context_sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Checks a proposed tool call against policies and server-anchored task."""
        url = f"{self.base_url}/check"
        payload = {
            "session_id": session_id,
            "run_id": run_id or session_id,
            "user_task": user_task,
            "tool": tool,
            "args": args,
            "flagged_sources": flagged_sources or [],
            "context_sources": context_sources or []
        }
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()

    def register_tool(self, name: str, description: str = "", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Pins a tool definition; blocks poisoned defs and rug-pulls."""
        url = f"{self.base_url}/tools/register"
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json={"name": name, "description": description, "params": params or {}})
            resp.raise_for_status()
            return resp.json()

    def get_audit(self) -> List[Dict[str, Any]]:
        """Fetches complete audit log."""
        url = f"{self.base_url}/audit"
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()

    def verify_audit(self) -> Dict[str, Any]:
        """Verifies hash-chain integrity."""
        url = f"{self.base_url}/audit/verify"
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
