"""Exports detected alerts into the record schema used by the Mini SIEM
Log Analyzer project's `Alert` model (see that project's `src/models.py`).

This module does not import anything from that project -- it only mirrors
its field names/types so a PCAP Threat Analyzer alerts file can be pointed
at by the Mini SIEM dashboard as an additional alert source. See the README
"SIEM export" section for how to wire that up.

Mini SIEM's Alert fields: alert_name, severity (LOW/MEDIUM/HIGH/CRITICAL),
timestamp, source_ip, username, event_count, description, evidence
(list[str]), mitre_id, mitre_name. PCAP traffic has no authenticated
identity, so `username` is always exported as "N/A".
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from pcap_analyzer.models import Alert

# Best-effort MITRE ATT&CK mapping per detector. Approximate, not
# authoritative -- these detectors are simple thresholds, not confirmed
# technique identification.
MITRE_MAP: Dict[str, Tuple[str, str]] = {
    "port_scan": ("T1046", "Network Service Discovery"),
    "broad_port_usage": ("T1046", "Network Service Discovery"),
    "high_connection_rate": ("T1498", "Network Denial of Service"),
    "dns_repetitive": ("T1071.004", "Application Layer Protocol: DNS"),
    "dns_high_rate": ("T1071.004", "Application Layer Protocol: DNS"),
    "long_dns_label": ("T1071.004", "Application Layer Protocol: DNS"),
}

SIEM_FIELDS = [
    "alert_name",
    "severity",
    "timestamp",
    "source_ip",
    "username",
    "event_count",
    "description",
    "evidence",
    "mitre_id",
    "mitre_name",
]


def to_siem_records(alerts: List[Alert]) -> List[dict]:
    """Convert PCAP Threat Analyzer alerts into dicts matching the Mini SIEM
    Alert schema."""
    generated_at = datetime.now(timezone.utc).isoformat()
    records = []
    for alert in alerts:
        if alert.timestamp is not None:
            timestamp = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat()
        else:
            timestamp = generated_at

        mitre_id, mitre_name = MITRE_MAP.get(alert.detector, (None, None))

        records.append(
            {
                "alert_name": alert.title,
                "severity": alert.severity.value,
                "timestamp": timestamp,
                "source_ip": alert.src_ip or "",
                "username": "N/A",
                "event_count": int(round(alert.metric_value)),
                "description": alert.evidence,
                "evidence": [alert.evidence],
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
            }
        )
    return records


def export_siem_json(alerts: List[Alert], path: str) -> None:
    """Write alerts as a JSON array of Mini-SIEM-schema records to `path`."""
    with open(path, "w") as f:
        json.dump(to_siem_records(alerts), f, indent=2)


def export_siem_csv(alerts: List[Alert], path: str) -> None:
    """Write alerts as a CSV of Mini-SIEM-schema records to `path`.

    `evidence` (a list in the JSON schema) is flattened to a single
    semicolon-joined string, since CSV has no native list type.
    """
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SIEM_FIELDS)
        writer.writeheader()
        for record in to_siem_records(alerts):
            row = dict(record)
            row["evidence"] = "; ".join(row["evidence"])
            writer.writerow(row)


def export_siem(alerts: List[Alert], path: str) -> None:
    """Write alerts in the Mini SIEM schema to `path`, choosing JSON or CSV
    based on the file extension."""
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if suffix == "json":
        export_siem_json(alerts, path)
    elif suffix == "csv":
        export_siem_csv(alerts, path)
    else:
        raise ValueError(
            f"unsupported SIEM export format for '{path}': expected a .json or .csv file extension"
        )
