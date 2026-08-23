from pcap_analyzer.parser import parse_pcap


def test_parser_extracts_tcp_and_dns_fields(synthetic_pcap_normal):
    packets, dns_queries = parse_pcap(synthetic_pcap_normal)

    tcp_packets = [p for p in packets if p.proto == "TCP"]
    assert len(tcp_packets) == 1
    tcp = tcp_packets[0]
    assert tcp.src_ip == "192.168.1.10"
    assert tcp.dst_ip == "93.184.216.34"
    assert tcp.dst_port == 443
    assert "S" in tcp.flags

    assert len(dns_queries) == 1
    assert dns_queries[0].query_name == "example.com"
    assert dns_queries[0].src_ip == "192.168.1.10"


def test_parser_extracts_full_port_scan(synthetic_pcap_portscan):
    packets, _ = parse_pcap(synthetic_pcap_portscan)
    assert len(packets) == 40
    dst_ports = {p.dst_port for p in packets}
    assert dst_ports == set(range(2000, 2040))
    assert all(p.src_ip == "192.168.1.15" for p in packets)
