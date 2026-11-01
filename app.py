"""Streamlit interface for the Ruler Triage Framework."""

import json
import os
import tempfile
from pathlib import Path

import streamlit as st

from ruler_triage import (
    GROUND_TRUTH_CASE,
    SCORING_RATIONALE,
    VERDICT_THRESHOLDS,
    _TOOL_VERSION,
    build_case_validation,
    build_report,
    check_signature,
    check_whitelist,
    compute_hashes,
    compute_verdict,
    load_vendor_db,
    query_virustotal,
)


st.set_page_config(page_title="Ruler Triage Framework", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    [data-testid="stMetricValue"] {
        font-size: 1.2rem;
        white-space: normal !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <style>
    .verdict-banner { padding: 1rem 1.25rem; border-radius: .6rem;
      border: 1px solid rgba(128,128,128,.35); margin: .5rem 0 1rem; }
    .status-badge { display:inline-block; padding:.15rem .55rem;
      border-radius:1rem; background:rgba(128,128,128,.18); font-weight:600; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "report" not in st.session_state:
    st.session_state.report = None
if "validation" not in st.session_state:
    st.session_state.validation = None

with st.sidebar:
    st.title(f"🛡️ Ruler Triage Framework v{_TOOL_VERSION}")
    st.caption("University of Ha'il — Information Security")
    vt_key = st.text_input(
        "VirusTotal API Key", value=os.environ.get("VT_API_KEY", ""), type="password"
    )
    db_path = st.text_input("Vendor DB Path", value="vendor_hashes.json")
    vt_delay = st.slider("VT Delay (seconds)", 5, 60, 15)
    offline = st.checkbox("Offline mode (skip VT)")
    analyze_clicked = st.button("🔍 Analyze File", type="primary", use_container_width=True)
    validate_clicked = st.button("✓ Run Case Validation", use_container_width=True)

st.title("Ruler Triage Framework")
st.caption("A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers")
tabs = st.tabs(["📁 Analysis", "📊 Scoring Breakdown", "🎯 Case Validation", "📄 JSON Report"])

with tabs[0]:
    uploaded = st.file_uploader("Choose a suspicious Windows binary", type=["exe", "dll", "sys"])
    if analyze_clicked:
        if uploaded is None:
            st.error("Upload a file before starting analysis.")
        else:
            if not vt_key and not offline:
                st.warning("⚠️ No VT API key — accuracy reduced.")
            temp_path = None
            try:
                suffix = Path(uploaded.name).suffix or ".exe"
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
                    temp_file.write(uploaded.getvalue())
                    temp_path = Path(temp_file.name)
                hashes = compute_hashes(temp_path)
                signature = check_signature(temp_path)
                # An empty key makes the engine return its offline result without a network request.
                vt = query_virustotal(hashes["sha256"], "" if offline else vt_key, vt_delay)
                vendor_db = load_vendor_db(Path(db_path))
                whitelist = check_whitelist(hashes["sha256"], vendor_db)
                verdict = compute_verdict(signature, vt, whitelist)
                case_validation = build_case_validation(hashes["sha256"], verdict)
                report = build_report(
                    temp_path, hashes, signature, vt, whitelist, verdict, case_validation
                )
                st.session_state.report = report
            except Exception as exc:
                st.error(f"Analysis failed: {exc}")
                st.session_state.report = None
            finally:
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError as exc:
                        st.warning(f"Could not remove temporary upload: {exc}")

    report = st.session_state.report
    if report:
        verdict = report["verdict"]
        verdict_text = verdict["verdict"]
        banner = st.error if verdict_text.startswith("High") else st.warning if verdict_text.startswith("Medium") else st.info
        banner(f"**{verdict_text}** — score {verdict['score']}")
        if verdict["warnings"]:
            for warning in verdict["warnings"]:
                st.warning(warning)
        if report["hashes"]["sha256"].lower() == GROUND_TRUTH_CASE["sha256"].lower():
            st.balloons()
        hashes = report["hashes"]
        metrics = st.columns(5)
        metric_values = [
            ("Signature", report["signature"]["status"]),
            ("VT Ratio", report["virustotal"]["detection_ratio"]),
            ("DB Status", report["whitelist_check"].get("status") or "miss"),
            ("Score", str(verdict["score"])),
            ("Verdict", verdict_text.split()[0]),
        ]
        for column, (label, value) in zip(metrics, metric_values):
            column.metric(label, value if len(value) < 42 else value[:39] + "…")
        st.caption("SHA-256 Hash")
        st.code(hashes["sha256"], language="text")
        with st.expander("Detailed Evidence", expanded=True):
            st.write("**File:**", report["target_file"]["filename"])
            st.write("**Signature detail:**", report["signature"]["detail"])
            st.write("**VirusTotal:**", report["virustotal"])
            st.write("**Vendor database:**", report["whitelist_check"])
            st.write("**Reasons:**")
            for reason in verdict["reasons"]:
                st.write(f"- {reason}")
        report_json = json.dumps(report, indent=2, ensure_ascii=False)
        with st.expander("Raw JSON"):
            st.code(report_json, language="json")
        st.download_button(
            "Download JSON report", report_json,
            file_name="triage_report.json", mime="application/json",
        )
    else:
        st.info("Upload a file and choose Analyze File to view triage results.")

with tabs[1]:
    st.subheader("Scoring indicators")
    point_values = {
        "unsigned": "+30", "signed_invalid": "+30",
        "vt_any_detection": "+20", "vt_high_detection": "+20 additive",
        "whitelist_approved": "−80", "whitelist_pending": "−30",
        "whitelist_blocked": "+40", "whitelist_miss": "+10",
    }
    rationale_rows = [
        {"Indicator": key.replace("_", " ").title(), "Points": point_values.get(key, "±0"), "Rationale": text}
        for key, text in SCORING_RATIONALE.items()
    ]
    st.dataframe(rationale_rows, use_container_width=True, hide_index=True)
    current = st.session_state.report
    if current:
        score = current["verdict"]["score"]
        st.progress(max(0.0, min(1.0, score / 100)))
        st.caption(f"Current score: {score}. Medium threshold: {VERDICT_THRESHOLDS['medium']}; High threshold: {VERDICT_THRESHOLDS['high']}.")
    else:
        st.progress(0.0)
        st.caption(f"Medium threshold: {VERDICT_THRESHOLDS['medium']}; High threshold: {VERDICT_THRESHOLDS['high']}.")

with tabs[2]:
    st.subheader(GROUND_TRUTH_CASE["name"])
    left, right = st.columns(2)
    left.markdown(f"**Date:** {GROUND_TRUTH_CASE['date']}")
    left.markdown(f"**SHA-256:** {GROUND_TRUTH_CASE['sha256']}")
    left.markdown(f"**Artifact:** {GROUND_TRUTH_CASE['artifact']}")
    right.markdown(f"**Network:** {GROUND_TRUTH_CASE['network']}")
    right.markdown(f"**VirusTotal:** {GROUND_TRUTH_CASE['vt_ratio']}")
    right.markdown(f"**Expected verdict:** {GROUND_TRUTH_CASE['final_verdict']}")
    if validate_clicked:
        try:
            sim_sig = {"status": "Unsigned", "signer_cn": "", "expiry": "", "detail": "Simulated ground-truth signature.", "tier": 2}
            sim_vt = {"found": True, "detection_ratio": "1/69", "malicious": 1, "suspicious": 0, "total_engines": 69, "community_score": 0, "permalink": "", "error": None}
            whitelist = check_whitelist(GROUND_TRUTH_CASE["sha256"], load_vendor_db(Path(db_path)))
            verdict = compute_verdict(sim_sig, sim_vt, whitelist)
            cv = build_case_validation(GROUND_TRUTH_CASE["sha256"], verdict)
            st.session_state.validation = (sim_sig, sim_vt, whitelist, verdict, cv)
        except Exception as exc:
            st.error(f"Case validation failed: {exc}")
            st.session_state.validation = None
    if st.session_state.validation:
        sim_sig, sim_vt, whitelist, verdict, cv = st.session_state.validation
        rows = [
            ("Signature", sim_sig["status"], "Unsigned"),
            ("VT Ratio", sim_vt["detection_ratio"], GROUND_TRUTH_CASE["vt_ratio"].split()[0]),
            ("DB Status", whitelist.get("status") or "miss", "pending_verification"),
            ("Score", str(verdict["score"]), str(GROUND_TRUTH_CASE["expected_score"])),
            ("Verdict", verdict["verdict"], GROUND_TRUTH_CASE["final_verdict"]),
        ]
        comparison = [
            {"Indicator": label, "Tool": tool, "Ground-Truth": expected, "Match": tool.lower() == expected.lower() or ("low" in tool.lower() and "low" in expected.lower())}
            for label, tool, expected in rows
        ]
        st.dataframe(comparison, use_container_width=True, hide_index=True)
        if all(row["Match"] for row in comparison):
            st.success(cv["framework_confidence"])
        else:
            st.error(cv["framework_confidence"])
    else:
        st.caption("Use Run Case Validation in the sidebar to compare engine results with the reference case.")

with tabs[3]:
    report = st.session_state.report
    if report:
        st.json(report)
        st.download_button(
            "Download JSON report", json.dumps(report, indent=2, ensure_ascii=False),
            file_name="triage_report.json", mime="application/json",
            key="json_tab_download",
        )
    else:
        st.info("Run an analysis to populate the structured report.")
