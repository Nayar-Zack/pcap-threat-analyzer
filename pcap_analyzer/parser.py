"""Reads a .pcap/.pcapng capture with Scapy and extracts PacketRecord/DNSQuery data.

This is the only module that touches Scapy or does file I/O -- everything
downstream (stats.py, detectors.py) works on the plain dataclasses produced
here, which keeps those modules testable without real capture files.
"""

from __future__ import annotations

from typing import List, Tuple

from scapy.all import DNS, DNSQR, IP, PcapReader, TCP, UDP

from pcap_analyzer.models import DNSQuery, PacketRecord


def parse_pcap(path: str) -> Tuple[List[PacketRecord], List[DNSQuery]]:
    """Stream a pcap/pcapng file and extract packet and DNS query summaries.

    Uses Scapy's PcapReader (streaming) rather than rdpcap (loads everything
    into memory) so reasonably large captures don't need to fit in RAM at once.
    """
    packets: List[PacketRecord] = []
    dns_queries: List[DNSQuery] = []

    with PcapReader(path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            timestamp = float(pkt.time)
            length = len(pkt)

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                proto = "TCP"
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                flags = str(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                proto = "UDP"
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
                flags = ""
            else:
                proto = "OTHER"
                src_port = None
                dst_port = None
                flags = ""

            packets.append(
                PacketRecord(
                    timestamp=timestamp,
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    proto=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    length=length,
                    flags=flags,
                )
            )

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                query_name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                query_type = _qtype_name(pkt[DNSQR].qtype)
                dns_queries.append(
                    DNSQuery(
                        timestamp=timestamp,
                        src_ip=ip_layer.src,
                        query_name=query_name,
                        query_type=query_type,
                    )
                )

    return packets, dns_queries


_QTYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA", 12: "PTR"}


def _qtype_name(qtype: int) -> str:
    return _QTYPE_NAMES.get(int(qtype), str(qtype))
