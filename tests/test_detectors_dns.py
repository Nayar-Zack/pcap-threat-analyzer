from pcap_analyzer.detectors import (
    DNS_LABEL_LOW,
    DNS_LABEL_MAX,
    DNS_LABEL_MEDIUM,
    DNS_RATE_WINDOW_SECONDS,
    DNS_REPEAT_HIGH,
    DNS_REPEAT_LOW,
    detect_long_dns_labels,
    detect_suspicious_dns,
)

_SPREAD = DNS_RATE_WINDOW_SECONDS * 2  # keeps repetition tests from also tripping the rate detector
from pcap_analyzer.models import Severity
from tests.factories import make_dns_query


def test_normal_dns_triggers_no_alerts():
    queries = [
        make_dns_query(1000.0 + i, "192.168.1.10", "example.com") for i in range(3)
    ] + [make_dns_query(1000.0, "192.168.1.10", "api.example.com")]
    assert detect_suspicious_dns(queries) == []
    assert detect_long_dns_labels(queries) == []


def test_repetitive_dns_below_low_threshold_no_alert():
    queries = [
        make_dns_query(i * _SPREAD, "192.168.1.10", "example.com") for i in range(DNS_REPEAT_LOW - 1)
    ]
    assert detect_suspicious_dns(queries) == []


def test_repetitive_dns_at_high_threshold():
    # Spread across time so the rate detector doesn't also fire, isolating
    # the repetition detector's behavior.
    queries = [
        make_dns_query(i * _SPREAD, "192.168.1.10", "malicious-c2.example.com")
        for i in range(DNS_REPEAT_HIGH)
    ]
    alerts = detect_suspicious_dns(queries)
    repeat_alerts = [a for a in alerts if a.detector == "dns_repetitive"]
    assert len(repeat_alerts) == 1
    assert repeat_alerts[0].severity == Severity.HIGH
    assert "malicious-c2.example.com" in repeat_alerts[0].evidence


def test_long_label_below_low_threshold_no_alert():
    label = "a" * (DNS_LABEL_LOW - 1)
    queries = [make_dns_query(0.0, "192.168.1.10", f"{label}.example.com")]
    assert detect_long_dns_labels(queries) == []


def test_long_label_at_medium_threshold():
    label = "a" * DNS_LABEL_MEDIUM
    queries = [make_dns_query(0.0, "192.168.1.10", f"{label}.example.com")]
    alerts = detect_long_dns_labels(queries)
    assert alerts[0].severity == Severity.MEDIUM


def test_long_label_at_protocol_max_is_high_but_wording_is_accurate():
    label = "a" * DNS_LABEL_MAX
    queries = [make_dns_query(0.0, "192.168.1.10", f"{label}.example.com")]
    alerts = detect_long_dns_labels(queries)
    assert alerts[0].severity == Severity.HIGH
    # Must not claim the label exceeds/violates the DNS protocol -- 63 chars
    # is a valid label length, just unusual.
    evidence = alerts[0].evidence.lower()
    assert "exceed" not in evidence
    assert "violat" not in evidence
    assert "maximum length allowed by the dns protocol" in evidence
    assert "not confirmation" in evidence
