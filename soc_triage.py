"""Small, explainable SOC triage engine for authentication logs.

Rules identify plausible brute-force behavior. IsolationForest adds an
unsupervised *outlier indicator*; it does not identify a confirmed attack.
"""

from __future__ import annotations

from collections import defaultdict, deque
import ipaddress

import pandas as pd
from sklearn.ensemble import IsolationForest

REQUIRED_COLUMNS = ("timestamp", "username", "src_ip", "status")
MAX_ROWS = 50_000


def validate_logs(logs: pd.DataFrame) -> pd.DataFrame:
    """Validate a CSV-like DataFrame and return timestamp-sorted UTC events."""
    if not isinstance(logs, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame.")
    if logs.empty:
        raise ValueError("The log file is empty.")
    if len(logs) > MAX_ROWS:
        raise ValueError(f"Too many rows. Maximum supported: {MAX_ROWS:,}.")

    missing = [column for column in REQUIRED_COLUMNS if column not in logs.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    result = logs.loc[:, list(REQUIRED_COLUMNS)].copy()
    result["timestamp"] = pd.to_datetime(result["timestamp"], errors="coerce", utc=True)
    if result["timestamp"].isna().any():
        raise ValueError("Every timestamp must be a valid date/time (ISO 8601 recommended).")

    for column in ("username", "src_ip", "status"):
        if result[column].isna().any():
            raise ValueError(f"Column '{column}' contains missing values.")
        result[column] = result[column].astype(str).str.strip()
        if result[column].eq("").any():
            raise ValueError(f"Column '{column}' contains an empty value.")

    result["status"] = result["status"].str.lower()
    if not result["status"].isin(("success", "failure")).all():
        raise ValueError("Status values must be 'success' or 'failure'.")

    if not result["src_ip"].map(_valid_ip).all():
        raise ValueError("Column 'src_ip' must contain valid IPv4 or IPv6 addresses.")

    return result.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def analyze_logs(logs: pd.DataFrame, use_ml: bool = True) -> pd.DataFrame:
    """Add rule-based alerts and optional ML anomaly indicators to each event.

    * The rolling failure count includes the current event if it is a failure.
    * Anomaly scores are *not* calibrated probabilities.
    * All time comparisons use UTC; the night-time rule is illustrative.
    """
    result = validate_logs(logs)
    failed_by_ip: dict[str, deque] = defaultdict(deque)
    recent_failures = []

    for event in result.itertuples(index=False):
        window = failed_by_ip[event.src_ip]
        # Remove failures more than 10 minutes old.
        while window and (event.timestamp - window[0]).total_seconds() > 600:
            window.popleft()
        if event.status == "failure":
            window.append(event.timestamp)
        recent_failures.append(len(window))

    result["failed_ip_10m"] = recent_failures
    result["ml_anomaly"] = False

    # IsolationForest is unsupervised. It trains on the currently loaded data;
    # that makes this a demonstration, not a validated production classifier.
    if use_ml and len(result) >= 30:
        features = pd.DataFrame(
            {
                "hour_utc": result["timestamp"].dt.hour,
                "is_failure": result["status"].eq("failure").astype(int),
                "failed_ip_10m": result["failed_ip_10m"],
            }
        )
        model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
        result["ml_anomaly"] = model.fit_predict(features) == -1

    scores = []
    severities = []
    explanations = []
    techniques = []

    for event in result.itertuples(index=False):
        score = 0
        reasons = []
        technique = "Not assigned"

        if event.failed_ip_10m >= 5 and event.status == "failure":
            score += 75
            reasons.append("5+ failures from the same IP in 10 minutes")
            technique = "T1110 (possible brute force)"
        elif event.failed_ip_10m >= 5 and event.status == "success":
            score += 90
            reasons.append("Successful login after 5+ recent failures from this IP")
            technique = "T1110 (possible brute force)"

        if event.status == "success" and event.timestamp.hour < 6:
            score += 30
            reasons.append("Success outside example hours (00:00-05:59 UTC)")

        if event.ml_anomaly:
            score += 20
            reasons.append("Unusual pattern flagged by IsolationForest")

        score = min(100, score)
        severity = (
            "High" if score >= 70 else
            "Medium" if score >= 40 else
            "Low" if score >= 20 else
            "Informational"
        )
        scores.append(score)
        severities.append(severity)
        explanations.append("; ".join(reasons) if reasons else "No alert conditions matched")
        techniques.append(technique)

    result["risk_score"] = scores
    result["severity"] = severities
    result["reason"] = explanations
    result["mitre_technique"] = techniques
    return result


def safe_csv_export(frame: pd.DataFrame) -> bytes:
    """Reduce spreadsheet formula-injection risk in exported CSV text fields."""
    safe = frame.copy()
    for column in safe.select_dtypes(include=["object", "string"]).columns:
        safe[column] = safe[column].map(
            lambda value: "'" + value
            if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
            else value
        )
    return safe.to_csv(index=False).encode("utf-8-sig")
