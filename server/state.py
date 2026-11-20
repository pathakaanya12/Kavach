"""State Management for Kavach Server & Orchestrator."""

import uuid
import asyncio
from typing import Dict, Any, List, Optional

class ServerState:
    def __init__(self):
        self.kavach_switch: bool = False
        self.run_id: str = f"run-{uuid.uuid4().hex[:6]}"
        self.status: str = "idle"  # idle | running | waiting_approval | breached | protected | done
        self.events: List[Dict[str, Any]] = []
        self.pending_approval: Optional[Dict[str, Any]] = None
        self.approval_future: Optional[asyncio.Future] = None
        self.planner: str = "scripted"
        self.custom_emails: Optional[List[Dict[str, Any]]] = None
        self.variant: str = "english"
        self.taint_path: Optional[str] = None
        self.killed: bool = False
        self.kill_reason: str = ""

        # Race guard: id of the demo run currently owning the state.
        # Callbacks / final evaluation ignore events from a stale run.
        self.active_task_run: Optional[str] = None

        # Red Team state
        self.redteam_status: str = "idle"  # idle | running | done | error
        self.redteam_progress: Dict[str, int] = {"done": 0, "total": 0}
        self.redteam_result: Optional[Dict[str, Any]] = None
        self.redteam_run_id: Optional[str] = None

        # Tracking outcomes
        self.breached: bool = False
        self.paid_bill: bool = False
        self.sent_report: bool = False
        self.attack_attempted: bool = False
        self.attack_stopped: bool = False
        self.upi_attack_attempted: bool = False
        # V3: session budget counters, intent contract, incident, honeypot
        self.budget_counts: Dict[str, Any] = {"total_calls": 0, "send_email": 0, "file_reads": 0, "total_paid": 0.0}
        self.budget_exceeded: bool = False
        self.honeypot_triggered: bool = False
        self.contract: Optional[Dict[str, Any]] = None
        self.incident_report: Optional[Dict[str, Any]] = None

    def reset_run(self):
        self.run_id = f"run-{uuid.uuid4().hex[:6]}"
        self.status = "idle"
        self.events = []
        self.pending_approval = None
        if self.approval_future and not self.approval_future.done():
            self.approval_future.cancel()
        self.approval_future = None
        self.breached = False
        self.paid_bill = False
        self.sent_report = False
        self.attack_attempted = False
        self.attack_stopped = False
        self.upi_attack_attempted = False
        self.budget_counts = {"total_calls": 0, "send_email": 0, "file_reads": 0, "total_paid": 0.0}
        self.budget_exceeded = False
        self.honeypot_triggered = False
        self.contract = None
        self.incident_report = None
        self.variant = "english"
        self.taint_path = None
        self.active_task_run = None
        self.killed = False
        self.kill_reason = ""

    def add_event(self, event: Dict[str, Any]):
        self.events.append(event)

    def scoreboard(self) -> Dict[str, Any]:
        legit_done = (1 if self.paid_bill else 0) + (1 if self.sent_report else 0)
        return {
            "attacks_attempted": 1 if (self.attack_attempted or self.upi_attack_attempted) else 0,
            "blocked": 1 if self.attack_stopped else 0,
            "legit_done": legit_done,
            "legit_total": 2,
            "breached": self.breached,
            "paid_bill": self.paid_bill,
            "sent_report": self.sent_report,
        }

    def kill(self, reason: str = "Operator pressed Kill Switch") -> None:
        self.killed = True
        self.kill_reason = reason
        self.status = "killed"
        # Release run ownership so a new run / red-team run can start
        # immediately; the winding-down thread's callbacks ignore stale
        # events and its final evaluation is skipped (status is killed).
        self.active_task_run = None
        if self.approval_future and not self.approval_future.done():
            self.approval_future.cancel()
        self.pending_approval = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "switch": self.kavach_switch,
            "run_id": self.run_id,
            "status": self.status,
            "events": self.events,
            "pending_approval": self.pending_approval,
            "planner": self.planner,
            "breached": self.breached,
            "paid_bill": self.paid_bill,
            "sent_report": self.sent_report,
            "attack_attempted": self.attack_attempted,
            "attack_stopped": self.attack_stopped,
            "variant": self.variant,
            "taint_path": self.taint_path,
            "killed": self.killed,
            "kill_reason": self.kill_reason,
            "budget": dict(self.budget_counts),
            "budget_exceeded": self.budget_exceeded,
            "honeypot_triggered": self.honeypot_triggered,
            "contract": self.contract,
            "incident": self.incident_report,
            "scoreboard": self.scoreboard(),
            "redteam": {
                "status": self.redteam_status,
                "progress": self.redteam_progress,
                "result": self.redteam_result,
            },
        }

state = ServerState()
