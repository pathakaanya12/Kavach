"""Runtime Gemini health tracker.

Records the outcome of the most recent Gemini API calls so the dashboard
can report honestly: live when calls succeed, degraded when the API is
rate limiting or unreachable (deterministic rules keep working either way).
"""

import time

_STATE = {"status": "unknown", "detail": "", "updated_at": 0.0}


def note_gemini(ok: bool, detail: str = "") -> None:
    _STATE["status"] = "live" if ok else "degraded"
    _STATE["detail"] = detail[:120]
    _STATE["updated_at"] = time.time()


def gemini_health() -> dict:
    return dict(_STATE)
