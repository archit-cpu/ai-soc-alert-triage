"""Tests covering detection rules, input validation, and safe CSV export."""

from pathlib import Path

import pandas as pd
import pytest

from generate_logs import generate_logs
from soc_triage import analyze_logs, safe_csv_export, validate_logs


def sample(rows):
    return pd.DataFrame(rows, columns=["timestamp", "username", "src_ip", "status"])


def event(timestamp, status="failure", ip="203.0.113.9", user="alice"):
    return {"timestamp": timestamp, "username": user, "src_ip": ip, "status": status}


def test_five_failures_create_high_severity_possible_brute_force():
    logs = sample([event(f"2026-11-10T12:0{i}:00Z") for i in range(5)])
    result = analyze_logs(logs, use_ml=False)
    assert list(result["failed_ip_10m"]) == [1, 2, 3, 4, 5]
    assert result.iloc[-1]["severity"] == "High"
    assert "T1110" in result.iloc[-1]["mitre_technique"]


def test_success_after_five_failures_gets_high_score():
    logs = sample(
        [event(f"2026-11-10T12:0{i}:00Z") for i in range(5)]
        + [event("2026-11-10T12:06:00Z", status="success")]
    )
    result = analyze_logs(logs, use_ml=False)
    assert result.iloc[-1]["risk_score"] == 90
    assert "Successful login" in result.iloc[-1]["reason"]


def test_failures_expire_after_ten_minutes():
    logs = sample(
        [event(f"2026-11-10T12:0{i}:00Z") for i in range(4)]
        + [event("2026-11-10T12:20:00Z")]
    )
    result = analyze_logs(logs, use_ml=False)
    assert result.iloc[-1]["failed_ip_10m"] == 1
    assert result.iloc[-1]["severity"] == "Informational"


def test_daytime_success_is_not_an_alert_without_ml():
    result = analyze_logs(sample([event("2026-11-10T13:00:00Z", status="success")]), use_ml=False)
    assert result.iloc[0]["risk_score"] == 0


def test_night_time_success_is_low_severity():
    result = analyze_logs(sample([event("2026-11-10T02:30:00Z", status="success")]), use_ml=False)
    assert result.iloc[0]["severity"] == "Low"


@pytest.mark.parametrize(
    "bad_logs, error",
    [
        (sample([]), "empty"),
        (pd.DataFrame([{"timestamp": "2026-11-10T12:00:00Z"}]), "Missing required"),
        (sample([event("not-a-date")]), "timestamp"),
        (sample([event("2026-11-10T12:00:00Z", status="unknown")]), "Status"),
        (sample([event("2026-11-10T12:00:00Z", ip="not-an-ip")]), "src_ip"),
    ],
)
def test_invalid_inputs_fail_with_clear_messages(bad_logs, error):
    with pytest.raises(ValueError, match=error):
        validate_logs(bad_logs)


def test_csv_export_escapes_spreadsheet_formulas():
    original = pd.DataFrame({"username": ["=1+1", " normal", "@SUM(A1:A2)"]})
    exported = safe_csv_export(original).decode("utf-8-sig")
    assert "'=1+1" in exported
    assert "'@SUM(A1:A2)" in exported
    assert " normal" in exported


def test_synthetic_data_contains_injected_attack(tmp_path: Path):
    path = generate_logs(tmp_path / "logs.csv")
    dataset = pd.read_csv(path)
    result = analyze_logs(dataset, use_ml=False)
    assert len(result) == 254
    assert (result["severity"] == "High").any()
    assert (result["src_ip"] == "203.0.113.77").sum() == 13


def test_optional_ml_runs_and_returns_boolean_column(tmp_path: Path):
    path = generate_logs(tmp_path / "logs.csv")
    result = analyze_logs(pd.read_csv(path), use_ml=True)
    assert len(result) == 254
    assert result["ml_anomaly"].dtype == bool
    assert result["ml_anomaly"].any()
