from pcap_analyzer.detectors import (
    PORT_SCAN_HIGH,
    PORT_SCAN_LOW,
    PORT_SCAN_MEDIUM,
    PORT_SCAN_WINDOW_SECONDS,
    detect_broad_port_usage,
    detect_port_scan,
)
from pcap_analyzer.models import Severity
from tests.factories import make_packet


def _scan_packets(port_count, src_ip="192.168.1.15", dst_ip="10.0.0.8", start=1000.0, spacing=0.1):
    return [
        make_packet(timestamp=start + i * spacing, src_ip=src_ip, dst_ip=dst_ip, dst_port=2000 + i)
        for i in range(port_count)
    ]


def test_normal_traffic_triggers_no_port_scan_alert(normal_traffic_packets):
    assert detect_port_scan(normal_traffic_packets) == []
    assert detect_broad_port_usage(normal_traffic_packets) == []


def test_port_scan_below_low_threshold_no_alert():
    packets = _scan_packets(PORT_SCAN_LOW - 1)
    assert detect_port_scan(packets) == []


def test_port_scan_at_low_threshold():
    packets = _scan_packets(PORT_SCAN_LOW)
    alerts = detect_port_scan(packets)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.LOW


def test_port_scan_at_medium_threshold():
    packets = _scan_packets(PORT_SCAN_MEDIUM)
    alerts = detect_port_scan(packets)
    assert alerts[0].severity == Severity.MEDIUM


def test_port_scan_at_high_threshold():
    packets = _scan_packets(PORT_SCAN_HIGH)
    alerts = detect_port_scan(packets)
    assert alerts[0].severity == Severity.HIGH
    assert "192.168.1.15" in alerts[0].evidence
    assert "10.0.0.8" in alerts[0].evidence
    assert "possible port scan" in alerts[0].evidence


def test_ports_spread_beyond_window_do_not_trigger_windowed_detector():
    # Same total unique ports as a HIGH scan, but spread out well beyond the
    # 30s window -- should not trip the windowed detector.
    packets = [
        make_packet(
            timestamp=1000.0 + i * (PORT_SCAN_WINDOW_SECONDS * 2),
            src_ip="192.168.1.15",
            dst_ip="10.0.0.8",
            dst_port=2000 + i,
        )
        for i in range(PORT_SCAN_HIGH)
    ]
    assert detect_port_scan(packets) == []


def test_slow_scan_caught_by_unwindowed_detector():
    # Same spread-out packets should still trip the broad-port-usage detector,
    # since it looks at the whole capture regardless of timing.
    packets = [
        make_packet(
            timestamp=1000.0 + i * (PORT_SCAN_WINDOW_SECONDS * 2),
            src_ip="192.168.1.15",
            dst_ip="10.0.0.8",
            dst_port=2000 + i,
        )
        for i in range(120)
    ]
    alerts = detect_broad_port_usage(packets)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
