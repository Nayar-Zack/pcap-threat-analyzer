"""Pure functions that turn parsed packets into capture-wide statistics.

Nothing here touches Scapy or file I/O, so all of this is testable with
hand-built PacketRecord lists.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, List

from pcap_analyzer.models import Flow, FlowKey, PacketRecord, StatsSummary

TOP_N = 10


def build_flows(packets: Iterable[PacketRecord]) -> List[Flow]:
    """Group packets into unidirectional flows keyed by the 5-tuple."""
    flows: dict = {}
    for pkt in packets:
        key = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto)
        flow = flows.get(key)
        if flow is None:
            flow = Flow(key=key, start_time=pkt.timestamp, end_time=pkt.timestamp)
            flows[key] = flow
        flow.packet_count += 1
        flow.byte_count += pkt.length
        flow.start_time = min(flow.start_time, pkt.timestamp)
        flow.end_time = max(flow.end_time, pkt.timestamp)
        if pkt.proto == "TCP" and "S" in pkt.flags and "A" not in pkt.flags:
            flow.syn_count += 1
    return list(flows.values())


def compute_stats(packets: List[PacketRecord], dns_queries: List) -> StatsSummary:
    """Compute top talkers, protocol mix, port activity, and flow summaries."""
    if not packets:
        return StatsSummary(
            total_packets=0,
            total_bytes=0,
            duration_seconds=0.0,
            dns_query_count=len(dns_queries),
        )

    total_bytes = sum(p.length for p in packets)
    timestamps = [p.timestamp for p in packets]
    duration = max(timestamps) - min(timestamps)

    protocol_counts = Counter(p.proto for p in packets)
    src_ip_counts = Counter(p.src_ip for p in packets)
    dst_ip_counts = Counter(p.dst_ip for p in packets)
    dst_port_counts = Counter(p.dst_port for p in packets if p.dst_port is not None)

    hosts = {p.src_ip for p in packets} | {p.dst_ip for p in packets}

    flows = build_flows(packets)
    top_flows = sorted(flows, key=lambda f: f.byte_count, reverse=True)[:TOP_N]

    return StatsSummary(
        total_packets=len(packets),
        total_bytes=total_bytes,
        duration_seconds=duration,
        protocol_counts=dict(protocol_counts),
        top_src_ips=src_ip_counts.most_common(TOP_N),
        top_dst_ips=dst_ip_counts.most_common(TOP_N),
        top_dst_ports=dst_port_counts.most_common(TOP_N),
        top_flows=top_flows,
        unique_hosts=len(hosts),
        dns_query_count=len(dns_queries),
    )
