from __future__ import annotations

import os

from pcap_analyzer.models import Alert, Severity, StatsSummary
from pcap_analyzer.visualization import generate_visualizations
from tests.factories import make_packet


def _make_stats() -> StatsSummary:
    return StatsSummary(
        total_packets=6,
        total_bytes=600,
        duration_seconds=25.0,
        protocol_counts={"TCP": 6},
        top_src_ips=[("192.168.1.10", 4), ("192.168.1.15", 2)],
        top_dst_ips=[("10.0.0.8", 6)],
        top_dst_ports=[(80, 3), (443, 3)],
        unique_hosts=2,
        dns_query_count=0,
    )


def _make_alert(src_ip="192.168.1.15", severity=Severity.HIGH, timestamp=1000.0) -> Alert:
    return Alert(
        detector="port_scan",
        severity=severity,
        title="Possible TCP port scan",
        evidence="evidence text",
        src_ip=src_ip,
        dst_ip="10.0.0.8",
        metric_value=50,
        threshold=8,
        window_seconds=30,
        timestamp=timestamp,
    )


def test_generate_visualizations_writes_png_and_svg(tmp_path):
    packets = [make_packet(timestamp=1000.0 + i, src_ip="192.168.1.10") for i in range(6)]
    stats = _make_stats()
    alerts = [_make_alert()]

    written = generate_visualizations(packets, stats, alerts, "sample.pcap", str(tmp_path))

    assert len(written) == 2
    png_path = next(p for p in written if p.endswith(".png"))
    svg_path = next(p for p in written if p.endswith(".svg"))

    with open(png_path, "rb") as f:
        assert f.read(8) == b"\x89PNG\r\n\x1a\n"

    with open(svg_path, "r") as f:
        assert "<svg" in f.read(200)


def test_generate_visualizations_handles_no_alerts(tmp_path):
    packets = [make_packet(timestamp=1000.0 + i, src_ip="192.168.1.10") for i in range(3)]
    stats = _make_stats()

    written = generate_visualizations(packets, stats, [], "sample.pcap", str(tmp_path))

    assert len(written) == 2
    for path in written:
        assert os.path.getsize(path) > 0


def test_generate_visualizations_handles_no_packets(tmp_path):
    stats = StatsSummary(total_packets=0, total_bytes=0, duration_seconds=0.0)

    written = generate_visualizations([], stats, [], "empty.pcap", str(tmp_path))

    assert len(written) == 2
    for path in written:
        assert os.path.getsize(path) > 0
