"""Phone / webhook alert on block (lite, optional) — Kavach v4.

Same pattern as the v3 Telegram stub: disabled by default, the
dashboard works exactly as before when nothing is configured. When
KAVACH_ALERT_WEBHOOK is set (e.g. a Telegram bot webhook, an SMS
gateway, or a Slack incoming webhook), Kavach POSTs a short JSON alert
— event + detail only, never secrets, never email bodies — whenever a
honeypot fires or the Kill Switch stops a run.

No live test with a real webhook is done here; the tested path is
"disabled" (unset) and a mocked requests.post in tests.
"""

import os
from typing import Any, Dict


def alert_configured() -> bool:
    return bool(os.getenv("KAVACH_ALERT_WEBHOOK", "").strip())


def send_alert(event: str, detail: str) -> Dict[str, Any]:
    """POSTs {event, detail, source: 'kavach'} to the webhook, or
    returns {"status": "disabled"} when unconfigured. Never raises."""
    url = os.getenv("KAVACH_ALERT_WEBHOOK", "").strip()
    if not url:
        return {"status": "disabled",
                "reason": "No KAVACH_ALERT_WEBHOOK configured"}
    try:
        import requests
        resp = requests.post(
            url,
            json={"event": event, "detail": detail, "source": "kavach"},
            timeout=3,
        )
        if resp.status_code in (200, 201, 202, 204):
            return {"status": "sent", "event": event}
        return {"status": "error", "reason": f"Webhook returned {resp.status_code}"}
    except Exception as e:  # noqa: BLE001 - alerting must never break a run
        return {"status": "error", "reason": str(e)}
