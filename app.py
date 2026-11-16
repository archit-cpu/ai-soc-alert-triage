"""Streamlit dashboard for an educational SOC alert-triage prototype."""

from pathlib import Path

import pandas as pd
import streamlit as st

from soc_triage import analyze_logs, safe_csv_export

st.set_page_config(page_title="AI SOC Alert Triage", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered SOC Alert Triage")
st.caption("Educational prototype • Rule-based detections + IsolationForest • UTC timestamps")

with st.sidebar:
    st.header("Controls")
    use_ml = st.checkbox("Enable ML anomaly detection", value=True)
    st.write("Upload authentication logs, or use the included synthetic example.")
    st.markdown("**Required CSV columns:** `timestamp`, `username`, `src_ip`, `status`")
    st.markdown("Valid `status` values: `success` and `failure`.")
    st.info("Do not upload private, real-world authentication logs to a public demo.")

uploaded_file = st.file_uploader("Optional: upload your own CSV", type=["csv"])

if uploaded_file is not None and uploaded_file.size > 5 * 1024 * 1024:
    st.error("File is too large. Upload a CSV smaller than 5 MB.")
    st.stop()

try:
    if uploaded_file is None:
        data_path = Path(__file__).resolve().parent / "data" / "sample_auth_logs.csv"
        logs = pd.read_csv(data_path, dtype={"username": "string", "src_ip": "string", "status": "string"})
        st.caption("Data source: bundled synthetic authentication logs")
    else:
        logs = pd.read_csv(uploaded_file, dtype={"username": "string", "src_ip": "string", "status": "string"})
        st.caption("Data source: uploaded CSV (processed locally by this app instance)")
    results = analyze_logs(logs, use_ml=use_ml)
except (ValueError, OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
    st.error(f"Could not analyze the file: {exc}")
    st.stop()

alerts = results.loc[results["risk_score"] >= 20].copy()
high_alerts = alerts.loc[alerts["severity"] == "High"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{len(results):,}")
c2.metric("Potential alerts", f"{len(alerts):,}")
c3.metric("High severity", f"{len(high_alerts):,}")
c4.metric("ML outliers", f"{int(results['ml_anomaly'].sum()):,}")

st.subheader("Alert severity breakdown")
if not alerts.empty:
    severity_counts = alerts["severity"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0)
    st.bar_chart(severity_counts)
else:
    st.success("No events matched the alert conditions.")

st.subheader("Potential security alerts")
columns = [
    "timestamp", "username", "src_ip", "status", "failed_ip_10m",
    "ml_anomaly", "risk_score", "severity", "reason", "mitre_technique",
]
if not alerts.empty:
    st.dataframe(alerts.sort_values("risk_score", ascending=False)[columns], use_container_width=True, hide_index=True)
    st.download_button(
        "Download potential alerts (CSV)",
        data=safe_csv_export(alerts[columns]),
        file_name="soc_alerts.csv",
        mime="text/csv",
    )

with st.expander("Show all analyzed events"):
    st.dataframe(results[columns], use_container_width=True, hide_index=True)

st.info(
    "Risk scores are simple rules, NOT probabilities. IsolationForest learns from this "
    "file and only marks outliers; it has not been evaluated as a production detector. "
    "T1110 is a possible ATT&CK mapping for repeated failures, not proof of an attack. "
    "The night-time rule uses UTC, not a user-specific baseline."
)
st.markdown("Technique reference: [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)")
