"""Generates two small, entirely synthetic demo captures used in the README
and for manual smoke-testing. No real or malicious traffic is captured or
downloaded -- every packet here is crafted in-process with Scapy.

Run with: python samples/generate_samples.py
"""

from scapy.all import DNS, DNSQR, IP, TCP, UDP, wrpcap


def build_normal_traffic():
    """A short, unremarkable browsing session: a few HTTPS/SSH connections
    and a handful of ordinary DNS lookups."""
    packets = []
    t = 1_700_000_000.0

    for i, port in enumerate([443, 443, 22, 443]):
        pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51000 + i, dport=port, flags="S", seq=1000)
        pkt.time = t
        packets.append(pkt)
        t += 2

    for domain in ["example.com", "api.example.com", "cdn.example.com"]:
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=52000, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = t
        packets.append(pkt)
        t += 1

    return packets


def build_port_scan_traffic():
    """192.168.1.15 scanning 50 ports on 10.0.0.8 within a few seconds, plus a
    handful of DNS queries with an unusually long, tunneling-style subdomain
    label sent by the same host."""
    packets = []
    t = 1_700_000_000.0

    for i, port in enumerate(range(20, 70)):
        pkt = IP(src="192.168.1.15", dst="10.0.0.8") / TCP(sport=40000 + i, dport=port, flags="S", seq=2000)
        pkt.time = t
        packets.append(pkt)
        t += 0.2

    long_label = "c9f1a3e7b2d4f6a8c1e3b5d7f9a1c3e5b7d9f1a3e5c7b9d1f3a5c7e9b1d3f5"  # 62 chars
    for _ in range(3):
        pkt = (
            IP(src="192.168.1.15", dst="8.8.8.8")
            / UDP(sport=52500, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{long_label}.tunnel.example.net"))
        )
        pkt.time = t
        packets.append(pkt)
        t += 0.5

    return packets


if __name__ == "__main__":
    wrpcap("samples/normal_traffic.pcap", build_normal_traffic())
    wrpcap("samples/portscan_demo.pcap", build_port_scan_traffic())
    print("Wrote samples/normal_traffic.pcap and samples/portscan_demo.pcap")
