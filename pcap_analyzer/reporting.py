"""Renders a StatsSummary + list[Alert] as terminal output, JSON, or HTML.

All three renderers work off the same data -- reporting is purely a
formatting layer, it does not compute anything.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from string import Template
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from pcap_analyzer.models import Alert, Severity, StatsSummary

SEVERITY_COLOR = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_terminal(
    stats: StatsSummary,
    alerts: List[Alert],
    source_file: str,
    verbose: bool = False,
    console: Optional[Console] = None,
) -> None:
    """Print a human-readable investigation summary to the terminal.

    Accepts an optional pre-built `Console` (e.g. one created with
    `record=True`) so output can be captured for docs/screenshots without
    duplicating the rendering logic.
    """
    if console is None:
        console = Console()

    console.print(f"\n[bold]PCAP Threat Analyzer[/bold] -- report for [bold]{source_file}[/bold]")

    overview = Table(title="Capture Overview", show_header=False)
    overview.add_row("Total packets", str(stats.total_packets))
    overview.add_row("Total bytes", f"{stats.total_bytes:,}")
    overview.add_row("Duration (s)", f"{stats.duration_seconds:.2f}")
    overview.add_row("Unique hosts", str(stats.unique_hosts))
    overview.add_row("DNS queries", str(stats.dns_query_count))
    console.print(overview)

    proto_table = Table(title="Protocol Breakdown")
    proto_table.add_column("Protocol")
    proto_table.add_column("Packets", justify="right")
    for proto, count in sorted(stats.protocol_counts.items(), key=lambda kv: kv[1], reverse=True):
        proto_table.add_row(proto, str(count))
    console.print(proto_table)

    talkers = Table(title="Top Source IPs")
    talkers.add_column("Source IP")
    talkers.add_column("Packets", justify="right")
    for ip, count in stats.top_src_ips:
        talkers.add_row(ip, str(count))
    console.print(talkers)

    dst_talkers = Table(title="Top Destination IPs")
    dst_talkers.add_column("Destination IP")
    dst_talkers.add_column("Packets", justify="right")
    for ip, count in stats.top_dst_ips:
        dst_talkers.add_row(ip, str(count))
    console.print(dst_talkers)

    ports = Table(title="Most Contacted Ports")
    ports.add_column("Port")
    ports.add_column("Hits", justify="right")
    for port, count in stats.top_dst_ports:
        ports.add_row(str(port), str(count))
    console.print(ports)

    if verbose:
        flows_table = Table(title="Top Conversations (by bytes)")
        flows_table.add_column("Src IP:Port")
        flows_table.add_column("Dst IP:Port")
        flows_table.add_column("Proto")
        flows_table.add_column("Packets", justify="right")
        flows_table.add_column("Bytes", justify="right")
        for flow in stats.top_flows:
            k = flow.key
            flows_table.add_row(
                f"{k.src_ip}:{k.src_port if k.src_port is not None else '-'}",
                f"{k.dst_ip}:{k.dst_port if k.dst_port is not None else '-'}",
                k.proto,
                str(flow.packet_count),
                f"{flow.byte_count:,}",
            )
        console.print(flows_table)

    alert_table = Table(title=f"Security Alerts ({len(alerts)})")
    alert_table.add_column("Severity")
    alert_table.add_column("Detector")
    alert_table.add_column("Evidence")
    for alert in alerts:
        color = SEVERITY_COLOR[alert.severity]
        alert_table.add_row(f"[{color}]{alert.severity.value}[/{color}]", alert.detector, alert.evidence)
    console.print(alert_table)

    if not alerts:
        console.print("[green]No alerts triggered by the configured heuristics.[/green]")


def to_json_dict(stats: StatsSummary, alerts: List[Alert], source_file: str) -> dict:
    """Build the plain-dict representation shared by JSON and HTML output."""
    stats_dict = asdict(stats)
    stats_dict["top_flows"] = [
        {
            "src_ip": f.key.src_ip,
            "dst_ip": f.key.dst_ip,
            "src_port": f.key.src_port,
            "dst_port": f.key.dst_port,
            "proto": f.key.proto,
            "packet_count": f.packet_count,
            "byte_count": f.byte_count,
        }
        for f in stats.top_flows
    ]
    alerts_list = []
    for a in alerts:
        alert_dict = asdict(a)
        alert_dict["severity"] = a.severity.value
        alerts_list.append(alert_dict)

    return {
        "source_file": source_file,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats_dict,
        "alerts": alerts_list,
    }


def render_json(stats: StatsSummary, alerts: List[Alert], source_file: str, path: str) -> None:
    """Write the report as JSON to `path`."""
    data = to_json_dict(stats, alerts, source_file)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


_HTML_TEMPLATE = Template(
    """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PCAP Threat Analyzer Report - $source_file</title>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
  th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 0.9rem; }
  th { background: #f2f2f2; }
  .sev-HIGH { color: #b00020; font-weight: bold; }
  .sev-MEDIUM { color: #a06a00; font-weight: bold; }
  .sev-LOW { color: #0066a1; font-weight: bold; }
  .summary-grid { display: flex; gap: 2rem; margin-bottom: 1.5rem; }
  .summary-item { background: #f7f7f7; padding: 0.75rem 1rem; border-radius: 6px; }
  .note { color: #555; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>PCAP Threat Analyzer -- Investigation Report</h1>
<p class="note">Source: $source_file &middot; Generated: $generated_at</p>
<p class="note">Heuristic alerts below indicate <strong>suspicious</strong> behavior worth investigating.
They are not proof that malicious activity occurred.</p>

<div class="summary-grid">
  <div class="summary-item"><strong>Packets:</strong> $total_packets</div>
  <div class="summary-item"><strong>Bytes:</strong> $total_bytes</div>
  <div class="summary-item"><strong>Duration (s):</strong> $duration_seconds</div>
  <div class="summary-item"><strong>Unique hosts:</strong> $unique_hosts</div>
  <div class="summary-item"><strong>DNS queries:</strong> $dns_query_count</div>
</div>

<h2>Security Alerts</h2>
<table>
<tr><th>Severity</th><th>Detector</th><th>Evidence</th></tr>
$alert_rows
</table>

<h2>Protocol Breakdown</h2>
<table>
<tr><th>Protocol</th><th>Packets</th></tr>
$protocol_rows
</table>

<h2>Top Source IPs</h2>
<table>
<tr><th>Source IP</th><th>Packets</th></tr>
$src_ip_rows
</table>

<h2>Top Destination IPs</h2>
<table>
<tr><th>Destination IP</th><th>Packets</th></tr>
$dst_ip_rows
</table>

<h2>Most Contacted Ports</h2>
<table>
<tr><th>Port</th><th>Hits</th></tr>
$port_rows
</table>

</body>
</html>
"""
)


def render_html(stats: StatsSummary, alerts: List[Alert], source_file: str, path: str) -> None:
    """Write the report as a single self-contained static HTML page to `path`."""
    data = to_json_dict(stats, alerts, source_file)

    alert_rows = "\n".join(
        f'<tr><td class="sev-{a["severity"]}">{a["severity"]}</td>'
        f'<td>{a["detector"]}</td><td>{a["evidence"]}</td></tr>'
        for a in data["alerts"]
    ) or "<tr><td colspan=\"3\">No alerts triggered.</td></tr>"

    protocol_rows = "\n".join(
        f"<tr><td>{proto}</td><td>{count}</td></tr>"
        for proto, count in sorted(stats.protocol_counts.items(), key=lambda kv: kv[1], reverse=True)
    )
    src_ip_rows = "\n".join(f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in stats.top_src_ips)
    dst_ip_rows = "\n".join(f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in stats.top_dst_ips)
    port_rows = "\n".join(f"<tr><td>{port}</td><td>{count}</td></tr>" for port, count in stats.top_dst_ports)

    html = _HTML_TEMPLATE.substitute(
        source_file=source_file,
        generated_at=data["generated_at"],
        total_packets=stats.total_packets,
        total_bytes=f"{stats.total_bytes:,}",
        duration_seconds=f"{stats.duration_seconds:.2f}",
        unique_hosts=stats.unique_hosts,
        dns_query_count=stats.dns_query_count,
        alert_rows=alert_rows,
        protocol_rows=protocol_rows,
        src_ip_rows=src_ip_rows,
        dst_ip_rows=dst_ip_rows,
        port_rows=port_rows,
    )
    with open(path, "w") as f:
        f.write(html)
