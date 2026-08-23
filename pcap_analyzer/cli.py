"""Command-line interface: orchestrates parser -> stats -> detectors -> reporting."""

from __future__ import annotations

import argparse
import sys

from pcap_analyzer.detectors import run_all_detectors
from pcap_analyzer.parser import parse_pcap
from pcap_analyzer.reporting import render_html, render_json, render_terminal
from pcap_analyzer.siem_export import export_siem
from pcap_analyzer.stats import compute_stats
from pcap_analyzer.visualization import generate_visualizations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap_analyzer",
        description=(
            "Analyze a PCAP/PCAPNG capture for traffic statistics and "
            "explainable, heuristic security alerts. Not a production IDS."
        ),
    )
    parser.add_argument("capture", help="Path to a .pcap or .pcapng file")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write the report as JSON to FILE")
    parser.add_argument("--html", metavar="FILE", help="Write the report as a static HTML page to FILE")
    parser.add_argument(
        "--verbose", action="store_true", help="Include the top-conversations table in terminal output"
    )
    parser.add_argument(
        "--visualize",
        metavar="DIR",
        nargs="?",
        const="visualizations",
        default=None,
        help=(
            "Generate a PNG/SVG visualization summary (packets over time, top source IPs, "
            "alert timeline) and write it to DIR (default: ./visualizations/)"
        ),
    )
    parser.add_argument(
        "--export-siem-format",
        metavar="FILE",
        help="Export alerts to FILE in the Mini SIEM Log Analyzer's alert schema (.json or .csv)",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        packets, dns_queries = parse_pcap(args.capture)
    except FileNotFoundError:
        print(f"error: capture file not found: {args.capture}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface any Scapy parse error to the user
        print(f"error: failed to parse {args.capture}: {exc}", file=sys.stderr)
        return 1

    stats = compute_stats(packets, dns_queries)
    alerts = run_all_detectors(packets, dns_queries)

    render_terminal(stats, alerts, args.capture, verbose=args.verbose)

    if args.output:
        render_json(stats, alerts, args.capture, args.output)
        print(f"\nJSON report written to {args.output}")

    if args.html:
        render_html(stats, alerts, args.capture, args.html)
        print(f"HTML report written to {args.html}")

    if args.visualize:
        written = generate_visualizations(packets, stats, alerts, args.capture, args.visualize)
        for path in written:
            print(f"Visualization written to {path}")

    if args.export_siem_format:
        export_siem(alerts, args.export_siem_format)
        print(f"SIEM-format alert export written to {args.export_siem_format}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
