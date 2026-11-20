"""Trust Report: score, OWASP coverage, DPDP evidence, breach draft."""
from fastapi.testclient import TestClient
from server.main import app, state
from kavach_engine.trust_report import build_trust_report, compute_score, trust_report_html

client = TestClient(app)


def test_score_without_redteam_is_low_and_explained():
    s = compute_score(None, True, 0, 0)
    assert s["score"] == 10 and s["grade"] == "D"
    assert any("Red Team not run" in p["evidence"] for p in s["parts"])


def test_full_score_with_perfect_redteam():
    rt = {"total": 20, "blocked": 20, "false_alarms": 0, "controls": 10}
    s = compute_score(rt, True, 2, 0)
    assert s["score"] == 100 and s["grade"] == "A"


def test_report_has_all_ten_owasp_rows_and_breach_draft():
    r = build_trust_report({"breached": True, "variant": "english", "redteam_result": None},
                           [], {"ok": True})
    assert [o["id"] for o in r["owasp"]] == [f"ASI{i:02d}" for i in range(1, 11)]
    assert r["breach"]["breach"] is True
    assert "customer_data.csv" in r["breach"]["what_happened"]
    assert r["breach"]["report_by"]
    html = trust_report_html(r)
    assert "Breach intimation draft" in html and "OWASP" in html and "DPDP" in html


def test_upi_breach_text():
    r = build_trust_report({"breached": True, "variant": "upi", "redteam_result": None}, [], {"ok": True})
    assert "UPI" in r["breach"]["what_happened"]


def test_endpoints():
    j = client.get("/api/trust-report").json()
    assert "score" in j and len(j["owasp"]) == 10
    page = client.get("/trust-report")
    assert page.status_code == 200 and "Kavach Trust Report" in page.text
