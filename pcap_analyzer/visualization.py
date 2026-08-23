"""Renders a summary-view chart (PNG + SVG) of a capture's traffic and alerts.

Like reporting.py, this module is a formatting/rendering layer -- it consumes
the same PacketRecord/StatsSummary/Alert objects produced by parser.py,
stats.py, and detectors.py, and does not compute anything new itself beyond
bucketing data for plotting. matplotlib's Agg backend is selected explicitly
so this works headlessly on a machine with no display, which is the normal
case for a CLI tool.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402

from pcap_analyzer.models import Alert, PacketRecord, Severity, StatsSummary  # noqa: E402

SEVERITY_COLOR = {
    Severity.HIGH: "#b00020",
    Severity.MEDIUM: "#a06a00",
    Severity.LOW: "#0066a1",
}

# Roughly this many buckets across the capture's duration for the
# packets-over-time chart, regardless of how long the capture is.
TARGET_TIME_BUCKETS = 50


def _bucket_packets_over_time(packets: List[PacketRecord]):
    """Bucket packet counts into evenly-sized time buckets for a line chart.

    Returns (bucket_start_times, packet_counts). Buckets are relative to the
    capture's own start time (0 == first packet).
    """
    if not packets:
        return [], []

    timestamps = sorted(p.timestamp for p in packets)
    start, end = timestamps[0], timestamps[-1]
    duration = end - start
    if duration <= 0:
        return [0.0], [len(packets)]

    bucket_width = max(duration / TARGET_TIME_BUCKETS, 1e-6)
    bucket_counts: Counter = Counter()
    for ts in timestamps:
        bucket_index = int((ts - start) / bucket_width)
        bucket_counts[bucket_index] += 1

    num_buckets = max(bucket_counts) + 1
    bucket_times = [i * bucket_width for i in range(num_buckets)]
    counts = [bucket_counts.get(i, 0) for i in range(num_buckets)]
    return bucket_times, counts


def _plot_packets_over_time(ax, packets: List[PacketRecord]) -> None:
    bucket_times, counts = _bucket_packets_over_time(packets)
    if not bucket_times:
        ax.text(0.5, 0.5, "No packets", ha="center", va="center", transform=ax.transAxes)
    else:
        ax.plot(bucket_times, counts, color="#2b6cb0", linewidth=1.5)
        ax.fill_between(bucket_times, counts, color="#2b6cb0", alpha=0.15)
    ax.set_title("Packets over time")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel("Packets per bucket")


def _plot_top_source_ips_by_volume(ax, stats: StatsSummary) -> None:
    if not stats.top_src_ips:
        ax.text(0.5, 0.5, "No traffic", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Top source IPs (by packet volume)")
        return
    ips, counts = zip(*stats.top_src_ips)
    ax.barh(range(len(ips)), counts, color="#2b6cb0")
    ax.set_yticks(range(len(ips)))
    ax.set_yticklabels(ips, fontsize=8)
    ax.invert_yaxis()
    ax.set_title("Top source IPs (by packet volume)")
    ax.set_xlabel("Packets")


def _plot_top_source_ips_by_alerts(ax, alerts: List[Alert]) -> None:
    counts = Counter(a.src_ip for a in alerts if a.src_ip)
    if not counts:
        ax.text(0.5, 0.5, "No alerts", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Top source IPs (by alerts triggered)")
        return
    top = counts.most_common(10)
    ips, values = zip(*top)
    ax.barh(range(len(ips)), values, color="#b00020")
    ax.set_yticks(range(len(ips)))
    ax.set_yticklabels(ips, fontsize=8)
    ax.invert_yaxis()
    ax.set_title("Top source IPs (by alerts triggered)")
    ax.set_xlabel("Alerts")


def _plot_alert_timeline(ax, alerts: List[Alert], packets: List[PacketRecord]) -> None:
    timed_alerts = [a for a in alerts if a.timestamp is not None]
    if not timed_alerts:
        ax.text(0.5, 0.5, "No alerts", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Alert timeline")
        return

    start = min(p.timestamp for p in packets) if packets else min(a.timestamp for a in timed_alerts)
    severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH]
    y_positions = {sev: i for i, sev in enumerate(severities)}

    for sev in severities:
        xs = [a.timestamp - start for a in timed_alerts if a.severity == sev]
        ys = [y_positions[sev]] * len(xs)
        if xs:
            ax.scatter(xs, ys, color=SEVERITY_COLOR[sev], label=sev.value, s=40, zorder=3)

    ax.set_yticks(list(y_positions.values()))
    ax.set_yticklabels([sev.value for sev in severities])
    ax.set_title("Alert timeline")
    ax.set_xlabel("Seconds since capture start")
    ax.legend(loc="upper right", fontsize=7)


def generate_visualizations(
    packets: List[PacketRecord],
    stats: StatsSummary,
    alerts: List[Alert],
    source_file: str,
    output_dir: str,
) -> List[str]:
    """Build a single 2x2 summary figure (packets over time, top source IPs by
    volume, top source IPs by alert count, and an alert timeline) and save it
    as both PNG and SVG under `output_dir`. Returns the list of file paths
    written.
    """
    os.makedirs(output_dir, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle(f"PCAP Threat Analyzer -- visualization summary for {source_file}", fontsize=12)

    _plot_packets_over_time(axes[0][0], packets)
    _plot_top_source_ips_by_volume(axes[0][1], stats)
    _plot_top_source_ips_by_alerts(axes[1][0], alerts)
    _plot_alert_timeline(axes[1][1], alerts, packets)

    fig.tight_layout(rect=(0, 0, 1, 0.96))

    stem = Path(source_file).stem or "capture"
    base_name = f"{stem}_summary"

    written_paths = []
    for ext in ("png", "svg"):
        path = os.path.join(output_dir, f"{base_name}.{ext}")
        fig.savefig(path)
        written_paths.append(path)

    plt.close(fig)
    return written_paths
