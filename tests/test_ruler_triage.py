import subprocess
import sys
import pytest

from ruler_triage import (
    GROUND_TRUTH_CASE,
    SCORING_RATIONALE,
    VERDICT_THRESHOLDS,
    check_whitelist,
    compute_hashes,
    compute_verdict,
)


@pytest.fixture
def manageengine_db():
    return {
        GROUND_TRUTH_CASE["sha256"]: {
            "vendor": "ManageEngine",
            "product": "UEMS Agent",
            "version": "test",
            "status": "pending_verification",
        }
    }


def test_ground_truth_hash_present():
    assert len(GROUND_TRUTH_CASE["sha256"]) == 64


def test_compute_hashes_known_string(tmp_path):
    f = tmp_path / "test.txt"
    f.write_bytes(b"hello")
    h = compute_hashes(f)
    assert h["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert len(h["sha1"]) == 40 and len(h["md5"]) == 32


def test_whitelist_hit_pending(manageengine_db):
    r = check_whitelist(GROUND_TRUTH_CASE["sha256"], manageengine_db)
    assert r["match"] is True
    assert r["status"] == "pending_verification"


def test_whitelist_miss():
    assert check_whitelist("0" * 64, {})["match"] is False


def test_verdict_low_manageengine(manageengine_db):
    """The exact ground-truth scenario must produce Low Confidence, score 20."""
    sig = {"status": "Unsigned", "signer_cn": "", "expiry": "", "detail": "", "tier": 2}
    vt = {"found": True, "detection_ratio": "1/69", "malicious": 1, "suspicious": 0,
          "total_engines": 69, "community_score": 0, "permalink": "", "error": None}
    wl = check_whitelist(GROUND_TRUTH_CASE["sha256"], manageengine_db)
    v = compute_verdict(sig, vt, wl)
    assert v["score"] == 20
    assert "Low" in v["verdict"]


def test_verdict_high_unsigned_high_vt():
    sig = {"status": "Unsigned", "signer_cn": "", "expiry": "", "detail": "", "tier": 2}
    vt = {"found": True, "detection_ratio": "30/69", "malicious": 30, "suspicious": 0,
          "total_engines": 69, "community_score": 0, "permalink": "", "error": None}
    v = compute_verdict(sig, vt, {"match": False})
    assert v["score"] >= VERDICT_THRESHOLDS["high"]


def test_validate_case_cli_passes():
    """--validate-case must exit 0."""
    r = subprocess.run(
        [sys.executable, "ruler_triage.py", "--validate-case"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "VALIDATION PASSED" in r.stdout


def test_scoring_rationale_keys_present():
    for key in ["unsigned", "vt_any_detection", "whitelist_approved",
                "whitelist_pending", "whitelist_blocked", "whitelist_miss"]:
        assert key in SCORING_RATIONALE


def test_non_pe_does_not_print_tier2_warning():
    result = subprocess.run(
        [sys.executable, "ruler_triage.py", "/bin/ls"],
        capture_output=True, text=True,
    )
    assert "Tier-2 (structural check only)" not in result.stderr + result.stdout
