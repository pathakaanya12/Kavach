"""Unit and integration tests for Live Gmail fetching & screening."""

import pytest
from unittest.mock import MagicMock, patch
from agent.gmail_live import fetch_live_gmail, decode_mime_words, extract_body
from server.main import app, state
from fastapi.testclient import TestClient

client = TestClient(app)

def test_missing_credentials_raises_error():
    with patch.dict("os.environ", {"GMAIL_ADDRESS": "", "GMAIL_APP_PASSWORD": ""}):
        with pytest.raises(ValueError, match="Gmail address or App Password is missing"):
            fetch_live_gmail(email_address="", app_password="")

def test_decode_mime_words():
    assert decode_mime_words("") == ""
    assert decode_mime_words("Hello World") == "Hello World"

def test_live_gmail_fetch_endpoint_handles_error():
    # Calling endpoint with invalid credentials should gracefully return error with instructions
    resp = client.post("/api/emails/live-fetch", json={
        "email": "invalid_user_test@gmail.com",
        "app_password": "invalidpassword",
        "limit": 2,
        "set_as_inbox": False
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "error"
    assert "error" in data
    assert "hints" in data
    assert len(data["hints"]) >= 2

def test_reset_inbox_endpoint():
    state.custom_emails = [{"id": 99, "subject": "Test", "body": "Custom", "from": "test@test.com"}]
    assert len(state.custom_emails) == 1
    resp = client.post("/api/emails/reset-inbox")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert state.custom_emails is None
