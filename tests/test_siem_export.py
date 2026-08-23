from __future__ import annotations

import csv
import json

import pytest

from pcap_analyzer.models import Alert, Severity
from pcap_analyzer.siem_export import export_siem, export_siem_csv, export_siem_json, to_siem_records


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        detector="port_scan",
        severity=Severity.HIGH,
        title="Possible TCP port scan",
        evidence="192.168.1.15 contacted 50 unique TCP ports on 10.0.0.8 -- possible port scan (HIGH).",
        src_ip="192.168.1.15",
        dst_ip="10.0.0.8",
        metric_value=50,
        threshold=8,
        window_seconds=30,
        timestamp=1700000000.0,
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_to_siem_records_maps_fields():
    alert = _make_alert()
    [record] = to_siem_records([alert])

    assert record["alert_name"] == "Possible TCP port scan"
    assert record["severity"] == "HIGH"
    assert record["source_ip"] == "192.168.1.15"
    assert record["username"] == "N/A"
    assert record["event_count"] == 50
    assert record["description"] == alert.evidence
    assert record["evidence"] == [alert.evidence]
    assert record["timestamp"] == "2023-11-14T22:13:20+00:00"


def test_known_detector_gets_mitre_mapping():
    [record] = to_siem_records([_make_alert(detector="port_scan")])
    assert record["mitre_id"] == "T1046"
    assert record["mitre_name"] == "Network Service Discovery"


def test_unknown_detector_gets_no_mitre_mapping():
    [record] = to_siem_records([_make_alert(detector="some_future_detector")])
    assert record["mitre_id"] is None
    assert record["mitre_name"] is None


def test_missing_timestamp_falls_back_to_generation_time():
    [record] = to_siem_records([_make_alert(timestamp=None)])
    assert record["timestamp"]  # non-empty ISO string, not a crash


def test_export_siem_json_round_trip(tmp_path):
    path = tmp_path / "alerts.json"
    export_siem_json([_make_alert()], str(path))

    with open(path) as f:
        data = json.load(f)

    assert len(data) == 1
    assert data[0]["alert_name"] == "Possible TCP port scan"
    assert data[0]["evidence"] == [_make_alert().evidence]


def test_export_siem_csv_flattens_evidence(tmp_path):
    path = tmp_path / "alerts.csv"
    export_siem_csv([_make_alert()], str(path))

    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["evidence"] == _make_alert().evidence
    assert rows[0]["alert_name"] == "Possible TCP port scan"


def test_export_siem_dispatches_on_extension(tmp_path):
    json_path = tmp_path / "alerts.json"
    csv_path = tmp_path / "alerts.csv"
    export_siem([_make_alert()], str(json_path))
    export_siem([_make_alert()], str(csv_path))

    assert json.loads(json_path.read_text())
    assert csv_path.read_text().strip()


def test_export_siem_rejects_unsupported_extension(tmp_path):
    path = tmp_path / "alerts.txt"
    with pytest.raises(ValueError):
        export_siem([_make_alert()], str(path))


def test_export_siem_handles_no_alerts(tmp_path):
    path = tmp_path / "alerts.json"
    export_siem_json([], str(path))
    assert json.loads(path.read_text()) == []
