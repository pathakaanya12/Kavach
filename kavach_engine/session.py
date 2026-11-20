"""Kavach Session & Goal Anchoring Engine.

Provides server-anchored task registration and session-level taint tracking.
Documented limitation: This implements session-level taint (pessimistic whole-session
risk escalation), not fine-grained token-level data-flow tracking.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class KavachSession(BaseModel):
    session_id: str
    user_goal: str
    is_tainted: bool = False
    flagged_sources: List[str] = Field(default_factory=list)
    context_sources: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

# In-memory session registry
_sessions: Dict[str, KavachSession] = {}

def create_session(user_goal: str, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> KavachSession:
    """Creates and anchors a new user task session on the server."""
    global _sessions
    sid = session_id or f"sess-{uuid.uuid4().hex[:8]}"
    session = KavachSession(
        session_id=sid,
        user_goal=user_goal.strip(),
        is_tainted=False,
        flagged_sources=[],
        context_sources=[],
        metadata=metadata or {}
    )
    _sessions[sid] = session
    return session

def get_session(session_id: str) -> Optional[KavachSession]:
    """Retrieves an anchored session by ID."""
    return _sessions.get(session_id)

def taint_session(session_id: str, source: str):
    """Marks a session as tainted once any source in the session is flagged."""
    sess = _sessions.get(session_id)
    if sess:
        sess.is_tainted = True
        if source not in sess.flagged_sources:
            sess.flagged_sources.append(source)

def is_session_tainted(session_id: str) -> bool:
    """Checks whether the session is marked tainted."""
    sess = _sessions.get(session_id)
    return sess.is_tainted if sess else False

def add_context_source(session_id: str, source: str):
    """Records context sources read within a session."""
    sess = _sessions.get(session_id)
    if sess and source not in sess.context_sources:
        sess.context_sources.append(source)

def clear_all_sessions():
    """Clears sessions (used for test isolation)."""
    global _sessions
    _sessions.clear()
