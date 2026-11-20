"""Live Gmail Integration for Kavach via IMAP & App Passwords.

Enables Kavach to screen incoming emails from a real Gmail account.
Extracts Sender, Subject, and Body (stripping complex MIME) and converts
them into Kavach-compatible email records for input screening.
"""

import os
import email
from email.header import decode_header
import imaplib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Load from adjacent or parent .env
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
load_dotenv()

def decode_mime_words(raw_header: Optional[str]) -> str:
    """Decodes MIME encoded header words into standard unicode strings."""
    if not raw_header:
        return ""
    decoded_fragments = []
    for fragment, encoding in decode_header(raw_header):
        if isinstance(fragment, bytes):
            try:
                decoded_fragments.append(fragment.decode(encoding or "utf-8", errors="replace"))
            except Exception:
                decoded_fragments.append(fragment.decode("latin-1", errors="replace"))
        else:
            decoded_fragments.append(str(fragment))
    return " ".join(decoded_fragments).strip()

def extract_body(msg: email.message.Message) -> str:
    """Extracts plain text or HTML body from an email message."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except Exception:
                        text = payload.decode("latin-1", errors="replace")
                    if content_type == "text/plain":
                        return text.strip()
                    elif content_type == "text/html":
                        body_parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace").strip()
            except Exception:
                return payload.decode("latin-1", errors="replace").strip()

    return "\n".join(body_parts).strip() if body_parts else "[No readable body text]"

def fetch_live_gmail(
    email_address: Optional[str] = None,
    app_password: Optional[str] = None,
    limit: int = 4
) -> List[Dict[str, Any]]:
    """
    Connects to Gmail via IMAP and retrieves the latest N emails.
    Returns: List of Kavach-formatted email dictionaries.
    """
    # Reload environment if credentials are not in memory or explicitly passed
    if email_address is None and not os.getenv("GMAIL_ADDRESS"):
        if _env_path.exists():
            load_dotenv(dotenv_path=_env_path, override=True)
        load_dotenv(override=True)

    user = email_address if email_address is not None else os.getenv("GMAIL_ADDRESS", "")
    pwd = (app_password if app_password is not None else os.getenv("GMAIL_APP_PASSWORD", "")).replace(" ", "")

    if not user or not pwd:
        raise ValueError("Gmail address or App Password is missing. Please set GMAIL_ADDRESS and GMAIL_APP_PASSWORD in .env")

    # Connect to Gmail IMAP
    mail = imaplib.IMAP4_SSL("imap.gmail.com", port=993)
    try:
        mail.login(user, pwd)
    except Exception as e:
        raise RuntimeError(f"Gmail Login Failed: {e}. Check email ID, App Password, and ensure IMAP is enabled in Gmail settings.")

    mail.select("INBOX", readonly=True)

    # Search for all emails
    status, messages = mail.search(None, "ALL")
    if status != "OK" or not messages or not messages[0]:
        mail.logout()
        return []

    mail_ids = messages[0].split()
    # Get the latest `limit` emails
    recent_ids = mail_ids[-limit:] if len(mail_ids) >= limit else mail_ids
    recent_ids.reverse()  # Newest first

    fetched_emails: List[Dict[str, Any]] = []

    for idx, mid in enumerate(recent_ids, 1):
        res, data = mail.fetch(mid, "(RFC822)")
        if res != "OK":
            continue

        raw_email = data[0][1]
        msg = email.message_from_bytes(raw_email)

        subject = decode_mime_words(msg.get("Subject", "(No Subject)"))
        from_hdr = decode_mime_words(msg.get("From", "Unknown Sender"))
        date_hdr = decode_mime_words(msg.get("Date", ""))
        body = extract_body(msg)

        # Truncate very long bodies to keep context reasonable
        if len(body) > 3000:
            body = body[:3000] + "\n...[truncated]"

        fetched_emails.append({
            "id": idx,
            "from": from_hdr,
            "subject": subject,
            "date": date_hdr,
            "body": body,
            "poisoned": False  # Will be dynamically evaluated by Kavach /screen
        })

    mail.logout()
    return fetched_emails
