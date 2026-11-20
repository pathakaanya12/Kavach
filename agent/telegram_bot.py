"""Telegram bot approval (lite, optional, never required) — Kavach v3.

Disabled by default: with no TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
configured, every function returns {"status": "disabled"} and the
dashboard approval works exactly as before. When configured, an
approval can be sent to Telegram with Allow/Block buttons.
Plain requests only, no new heavy dependency; all imports are guarded
so a missing token or library never breaks startup or tests.
Never live-tested with a real bot — code-review only.
"""

import os
from typing import Any, Dict, Optional


def telegram_configured() -> bool:
    return bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
                and os.getenv("TELEGRAM_CHAT_ID", "").strip())


def send_approval(tool: str, args: Dict[str, Any], reason: str, approval_id: str) -> Dict[str, Any]:
    """Sends an approval request to Telegram. Disabled when unconfigured."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return {"status": "disabled", "reason": "Telegram not configured (no TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)"}
    try:
        import requests
        text = (
            f"Kavach approval needed\nTool: {tool}\nArgs: {args}\n"
            f"Reason: {reason}\nApproval: {approval_id}"
        )
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "reply_markup": {"inline_keyboard": [[
                    {"text": "✅ Allow", "callback_data": f"allow:{approval_id}"},
                    {"text": "🛑 Block", "callback_data": f"block:{approval_id}"},
                ]]},
            },
            timeout=5,
        )
        if resp.status_code == 200:
            return {"status": "sent", "approval_id": approval_id}
        return {"status": "error", "reason": f"Telegram returned {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def handle_callback(callback_data: str) -> Optional[Dict[str, str]]:
    """Parses an inline-button callback: 'allow:<id>' / 'block:<id>'."""
    if not callback_data or ":" not in callback_data:
        return None
    decision, approval_id = callback_data.split(":", 1)
    if decision not in ("allow", "block") or not approval_id:
        return None
    return {"decision": decision, "id": approval_id}
