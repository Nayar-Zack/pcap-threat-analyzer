"""Shared test fixtures.

Two strategies are used deliberately:
- `make_packet` and the packet-list fixtures build plain PacketRecord objects
  by hand, for testing stats.py/detectors.py as pure functions.
- The `synthetic_pcap_*` fixtures use Scapy to *write* tiny synthetic pcap
  files at test time (into tmp_path, never committed) so parser.py can be
  tested against real capture bytes without downloading any real-world or
  malicious traffic.
"""

from __future__ import annotations

import pytest

from tests.factories import make_packet


@pytest.fixture
def normal_traffic_packets():
    """A handful of packets to a few ports at a modest rate -- must not
    trigger any detector."""
    packets = []
    ports = [80, 443, 22]
    for i in range(6):
        packets.append(
            make_packet(
                timestamp=1000.0 + i * 5,
                src_ip="192.168.1.10",
                dst_ip="93.184.216.34",
                dst_port=ports[i % len(ports)],
                flags="S" if i % 2 == 0 else "SA",
            )
        )
    return packets


@pytest.fixture
def portscan_packets():
    """One source hitting 40 distinct ports on one destination within a few
    seconds -- should trigger the windowed port-scan detector at HIGH."""
    return [
        make_packet(timestamp=2000.0 + i * 0.1, src_ip="192.168.1.15", dst_ip="10.0.0.8", dst_port=1000 + i)
        for i in range(40)
    ]


@pytest.fixture
def synthetic_pcap_normal(tmp_path):
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, wrpcap

    pkts = [
        IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="S"),
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=51001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ]
    path = tmp_path / "normal.pcap"
    wrpcap(str(path), pkts)
    return str(path)


@pytest.fixture
def synthetic_pcap_portscan(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    pkts = [
        IP(src="192.168.1.15", dst="10.0.0.8") / TCP(sport=51000, dport=port, flags="S")
        for port in range(2000, 2040)
    ]
    path = tmp_path / "portscan.pcap"
    wrpcap(str(path), pkts)
    return str(path)
