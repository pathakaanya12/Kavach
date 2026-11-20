"""Red Team tests (library / runtime-generator mode, offline).

Attacks are generated at runtime from the demo injection already in
data/kavach_demo_data.json — no static attack library on disk.
"""
import os

os.environ["KAVACH_OFFLINE"] = "1"
os.environ["AGENT_PLANNER"] = "scripted"

from kavach_engine.audit import reset_audit_log
from kavach_engine.redteam import (
    CATEGORIES,
    default_controls,
    evaluate,
    generate_attacks,
    generate_runtime_attacks,
    load_manifest,
)


def test_manifest_has_no_email_bodies():
    manifest = load_manifest()
    text = str(manifest)
    assert "email_body" not in text
    cats = {c["category"] for c in manifest["categories"]}
    assert set(CATEGORIES) <= cats


def test_generate_runtime_all_categories_present():
    attacks = generate_runtime_attacks(20)
    assert len(attacks) == 20
    cats = {a["category"] for a in attacks}
    assert set(CATEGORIES) <= cats
    for a in attacks:
        assert a["target_action"]["tool"] in ("pay_bill", "send_email", "share_file")
        assert a["email_body"]
        assert a["language"]


def test_generate_library_source_label():
    gen = generate_attacks(20, source="library")
    assert gen["source"] == "library"
    assert len(gen["attacks"]) == 20


def test_evaluate_library_offline():
    reset_audit_log(keep_disk=False)
    try:
        gen = generate_attacks(20, source="library")
        result = evaluate(gen["attacks"], default_controls(), session_id="redteam-test-1")
        result["source"] = gen["source"]
        assert result["total"] == 20
        assert result["blocked"] + result["missed"] == 20
        assert result["controls"] == 10
        assert result["false_alarms"] <= 1
        assert result["source"] == "library"
        assert set(result["by_category"]) == set(CATEGORIES)
        for cat, v in result["by_category"].items():
            assert v["total"] + v["blocked"] <= 2 * v["total"]
            assert v["blocked"] <= v["total"]
        assert result["blocked"] >= 15, f"too many missed: {result}"
        assert isinstance(result["duration_s"], (int, float))
        for item in result["missed_items"]:
            assert "category" in item and "subject" in item
    finally:
        reset_audit_log(keep_disk=False)


def test_evaluate_controls_are_clean():
    controls = default_controls()
    assert len(controls) == 10
    from kavach_engine.screen import screen_content

    flagged = 0
    for ctl in controls:
        res = screen_content(
            run_id="redteam-ctl", source=f"ctl:{ctl['id']}",
            text=f"{ctl['email_subject']}\n\n{ctl['email_body']}",
            session_id="redteam-ctl",
        )
        if res["verdict"] == "flagged":
            flagged += 1
    assert flagged <= 1
