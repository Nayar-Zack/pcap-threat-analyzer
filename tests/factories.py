"""Plain object builders shared across test modules (kept separate from
conftest.py so test files can import them directly without relying on
pytest's fixture-injection machinery)."""

from __future__ import annotations

from pcap_analyzer.models import DNSQuery, PacketRecord


def make_packet(
    timestamp: float,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.8",
    proto: str = "TCP",
    src_port=54321,
    dst_port=80,
    length: int = 100,
    flags: str = "S",
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        flags=flags,
    )


def make_dns_query(timestamp: float, src_ip: str, query_name: str, query_type: str = "A") -> DNSQuery:
    return DNSQuery(timestamp=timestamp, src_ip=src_ip, query_name=query_name, query_type=query_type)
