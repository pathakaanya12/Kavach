"""FastAPI Router for Kavach Engine.

Endpoints:
- POST /session/start (Server-anchored goal registration with API key)
- POST /screen (Screens external text before agent reads it)
- POST /check (Verifies tool call against policies and server-anchored task)
- GET /audit (Fetches hash-chained audit ledger)
- GET /audit/verify (Cryptographically validates SHA-256 chain)
"""

import os
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field

from kavach_engine.screen import screen_content
from kavach_engine.check import check_action
from kavach_engine.audit import get_audit_entries, verify_audit_chain, record_entry
from kavach_engine.session import create_session, get_session
from kavach_engine.tool_scan import register_tool_definition

router = APIRouter()

KAVACH_API_KEY = os.getenv("KAVACH_API_KEY", "kavach-secret-key")

def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Validates the API key for administrative / session operations."""
    expected = os.getenv("KAVACH_API_KEY", "kavach-secret-key")
    if not x_api_key or x_api_key.strip() != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header"
        )
    return x_api_key

class SessionStartRequest(BaseModel):
    user_goal: str = Field(..., min_length=1, description="The user's authentic initial task")
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SessionStartResponse(BaseModel):
    session_id: str
    user_goal: str
    status: str
    created_at: str

class ScreenRequest(BaseModel):
    run_id: Optional[str] = None
    session_id: Optional[str] = None
    source: str
    text: str

class ScreenResponse(BaseModel):
    verdict: str
    reason: str
    signals: List[str]
    sanitized_text: str

class CheckRequest(BaseModel):
    session_id: Optional[str] = None
    run_id: Optional[str] = None
    user_task: Optional[str] = None  # Deprecated dev fallback
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    flagged_sources: List[str] = Field(default_factory=list)
    context_sources: List[str] = Field(default_factory=list)

class CheckResponse(BaseModel):
    decision: str
    reason: str
    policy_hits: List[str]
    llm_decision: str

@router.post("/session/start", response_model=SessionStartResponse)
def start_session_endpoint(req: SessionStartRequest, api_key: str = Depends(verify_api_key)):
    """Registers the authentic user goal on the server before the agent runs."""
    session = create_session(
        user_goal=req.user_goal,
        session_id=req.session_id,
        metadata=req.metadata
    )
    record_entry(
        run_id=session.session_id,
        kind="human",
        detail=f"Session started for task: '{session.user_goal[:50]}...'",
        result="SESSION_INITIALIZED",
        reason="Server-anchored goal registered via /session/start"
    )
    return SessionStartResponse(
        session_id=session.session_id,
        user_goal=session.user_goal,
        status="active",
        created_at=session.created_at
    )

@router.post("/screen", response_model=ScreenResponse)
def screen_endpoint(req: ScreenRequest):
    """Screens external text before an agent reads it."""
    sid = req.session_id or req.run_id or "default"
    result = screen_content(run_id=sid, source=req.source, text=req.text, session_id=sid)

    # Log to audit trail
    record_entry(
        run_id=sid,
        kind="screen",
        detail=f"Source: {req.source} (len: {len(req.text)} chars)",
        result=result["verdict"].upper(),
        reason=result["reason"]
    )

    return ScreenResponse(**result)

@router.post("/check", response_model=CheckResponse)
def check_endpoint(req: CheckRequest):
    """Verifies a tool action before execution."""
    sid = req.session_id or req.run_id or "default"
    result = check_action(
        run_id=sid,
        session_id=req.session_id,
        user_task=req.user_task,
        tool=req.tool,
        args=req.args,
        flagged_sources=req.flagged_sources,
        context_sources=req.context_sources
    )
    return CheckResponse(**result)

class ToolRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = Field(default="")
    params: Dict[str, Any] = Field(default_factory=dict)


@router.post("/tools/register")
def register_tool_endpoint(req: ToolRegisterRequest):
    """Pins a tool definition; blocks poisoned defs and rug-pull rewrites."""
    result = register_tool_definition(req.name, req.description, req.params)
    record_entry(
        run_id="default",
        kind="tool_register",
        detail=f"Tool '{req.name}'",
        result=result["verdict"].upper(),
        reason=result["reason"],
    )
    return result


@router.get("/audit")
def get_audit_log():
    """Returns the hash-chained audit trail."""
    return get_audit_entries()

@router.get("/audit/verify")
def verify_audit():
    """Cryptographically verifies the SHA-256 hash chain."""
    return verify_audit_chain()
