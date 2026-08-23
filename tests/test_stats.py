from pcap_analyzer.stats import build_flows, compute_stats
from tests.factories import make_dns_query, make_packet


def test_protocol_counts():
    packets = [
        make_packet(1.0, proto="TCP"),
        make_packet(2.0, proto="TCP"),
        make_packet(3.0, proto="UDP"),
    ]
    stats = compute_stats(packets, [])
    assert stats.protocol_counts == {"TCP": 2, "UDP": 1}


def test_top_ips_ordering_and_truncation():
    packets = []
    for i in range(3):
        packets.append(make_packet(float(i), src_ip="1.1.1.1"))
    for i in range(2):
        packets.append(make_packet(float(i), src_ip="2.2.2.2"))
    packets.append(make_packet(0.0, src_ip="3.3.3.3"))

    stats = compute_stats(packets, [])
    assert stats.top_src_ips[0] == ("1.1.1.1", 3)
    assert stats.top_src_ips[1] == ("2.2.2.2", 2)
    assert stats.top_src_ips[2] == ("3.3.3.3", 1)


def test_byte_volume_sums_correctly():
    packets = [make_packet(0.0, length=100), make_packet(1.0, length=250)]
    stats = compute_stats(packets, [])
    assert stats.total_bytes == 350


def test_duration_from_min_max_timestamps():
    packets = [make_packet(10.0), make_packet(45.0), make_packet(20.0)]
    stats = compute_stats(packets, [])
    assert stats.duration_seconds == 35.0


def test_flow_grouping_aggregates_by_five_tuple():
    packets = [
        make_packet(0.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, length=50),
        make_packet(1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, length=60),
        make_packet(2.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1001, dst_port=80, length=70),
    ]
    flows = build_flows(packets)
    assert len(flows) == 2
    matching = [f for f in flows if f.key.src_port == 1000][0]
    assert matching.packet_count == 2
    assert matching.byte_count == 110


def test_dns_query_count_reflected_in_stats():
    packets = [make_packet(0.0)]
    dns_queries = [make_dns_query(0.0, "1.1.1.1", "example.com")]
    stats = compute_stats(packets, dns_queries)
    assert stats.dns_query_count == 1


def test_empty_capture_does_not_crash():
    stats = compute_stats([], [])
    assert stats.total_packets == 0
    assert stats.duration_seconds == 0.0
