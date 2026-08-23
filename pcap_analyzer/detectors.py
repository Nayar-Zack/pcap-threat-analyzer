"""Explainable, threshold-based heuristic detectors.

Every detector here is a pure function: it takes already-parsed packet/DNS data
in and returns a list of Alert objects out. None of them do file I/O, and none
of them use machine learning or statistical baselining -- these are simple,
auditable threshold rules, which is deliberate: a security analyst (or an
interviewer) should be able to read a threshold and immediately understand
why an alert fired.

Every alert carries an `evidence` string that states the exact metric and uses
hedged language ("possible", "suspicious") -- these heuristics indicate
behavior worth investigating, not confirmed malicious activity. See the
README "Detection Methodology" and "Limitations" sections for known
false-positive scenarios for each rule below.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from pcap_analyzer.models import Alert, DNSQuery, PacketRecord, Severity

# --- Port scan (windowed): unique destination ports one host hits on another
#     host within a short sliding window. ---
PORT_SCAN_WINDOW_SECONDS = 30
PORT_SCAN_LOW = 8
PORT_SCAN_MEDIUM = 15
PORT_SCAN_HIGH = 30

# --- Broad port usage (unwindowed): unique destination ports one host
#     contacts across the entire capture, regardless of timing. Catches slow
#     scans that stay under the windowed threshold above. ---
BROAD_PORTS_LOW = 20
BROAD_PORTS_MEDIUM = 50
BROAD_PORTS_HIGH = 100

# --- Connection rate: new TCP SYNs from one host within a short window. ---
CONN_RATE_WINDOW_SECONDS = 10
CONN_RATE_LOW = 15
CONN_RATE_MEDIUM = 30
CONN_RATE_HIGH = 75

# --- Repetitive DNS: queries for the same domain, from the same host, across
#     the whole capture. ---
DNS_REPEAT_LOW = 20
DNS_REPEAT_MEDIUM = 50
DNS_REPEAT_HIGH = 150

# --- DNS query rate: queries from one host within a short window. ---
DNS_RATE_WINDOW_SECONDS = 10
DNS_RATE_LOW = 10
DNS_RATE_MEDIUM = 20
DNS_RATE_HIGH = 50

# --- Long DNS labels: a single label (the text between two dots) approaching
#     the DNS protocol's 63-character maximum. 63 is a valid label length, not
#     a violation -- we flag it purely because it is unusual, not illegal. ---
DNS_LABEL_MAX = 63
DNS_LABEL_LOW = 30
DNS_LABEL_MEDIUM = 45


def _severity_for(value: float, low: float, medium: float, high: float) -> Optional[Severity]:
    """Map a metric value to a severity tier, or None if below the LOW threshold."""
    if value >= high:
        return Severity.HIGH
    if value >= medium:
        return Severity.MEDIUM
    if value >= low:
        return Severity.LOW
    return None


def _max_distinct_in_window(
    events: Sequence[Tuple[float, object]], window_seconds: float
) -> Tuple[int, float, float]:
    """Slide a trailing window of `window_seconds` over time-ordered events and
    return the largest number of distinct values seen in any window, along with
    that window's start/end time.

    `events` is a list of (timestamp, value) pairs; distinctness is measured on
    `value` (e.g. destination port).
    """
    ordered = sorted(events, key=lambda e: e[0])
    if not ordered:
        return 0, 0.0, 0.0

    best_count = 0
    best_start = ordered[0][0]
    best_end = ordered[0][0]

    left = 0
    window_counts: Dict[object, int] = defaultdict(int)
    distinct = 0

    for right in range(len(ordered)):
        right_time, right_value = ordered[right]
        if window_counts[right_value] == 0:
            distinct += 1
        window_counts[right_value] += 1

        while ordered[left][0] < right_time - window_seconds:
            left_value = ordered[left][1]
            window_counts[left_value] -= 1
            if window_counts[left_value] == 0:
                distinct -= 1
            left += 1

        if distinct > best_count:
            best_count = distinct
            best_start = ordered[left][0]
            best_end = right_time

    return best_count, best_start, best_end


def _max_count_in_window(timestamps: Sequence[float], window_seconds: float) -> Tuple[int, float, float]:
    """Slide a trailing window over sorted timestamps and return the largest
    number of events in any window, plus that window's start/end time."""
    ordered = sorted(timestamps)
    if not ordered:
        return 0, 0.0, 0.0

    best_count = 0
    best_start = ordered[0]
    best_end = ordered[0]
    left = 0

    for right in range(len(ordered)):
        while ordered[left] < ordered[right] - window_seconds:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = ordered[left]
            best_end = ordered[right]

    return best_count, best_start, best_end


def detect_port_scan(packets: List[PacketRecord]) -> List[Alert]:
    """Flag a host that contacts many unique destination ports on a single
    other host within a short time window -- the classic pattern of a TCP
    port scan against one target.

    False positives: reverse proxies/load balancers fanning out to many
    backend ports, and NAT gateways where many real hosts appear as one
    source IP.
    """
    alerts: List[Alert] = []
    pairs: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
    for pkt in packets:
        if pkt.proto == "TCP" and pkt.dst_port is not None:
            pairs[(pkt.src_ip, pkt.dst_ip)].append((pkt.timestamp, pkt.dst_port))

    for (src_ip, dst_ip), events in pairs.items():
        count, start, end = _max_distinct_in_window(events, PORT_SCAN_WINDOW_SECONDS)
        severity = _severity_for(count, PORT_SCAN_LOW, PORT_SCAN_MEDIUM, PORT_SCAN_HIGH)
        if severity is None:
            continue
        alerts.append(
            Alert(
                detector="port_scan",
                severity=severity,
                title="Possible TCP port scan",
                evidence=(
                    f"{src_ip} contacted {count} unique TCP ports on {dst_ip} within "
                    f"{PORT_SCAN_WINDOW_SECONDS} seconds -- possible port scan ({severity.value})."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                metric_value=count,
                threshold=PORT_SCAN_LOW,
                window_seconds=PORT_SCAN_WINDOW_SECONDS,
                timestamp=end,
            )
        )
    return alerts


def detect_broad_port_usage(packets: List[PacketRecord]) -> List[Alert]:
    """Flag a host that contacts an unusually large number of distinct
    destination ports across the whole capture, regardless of timing. This
    catches slow/low-and-slow scans spread out enough to stay under the
    windowed port-scan threshold above.

    False positives: NAT/proxy devices, P2P clients, or a single busy
    workstation that legitimately talks to many varied services.
    """
    alerts: List[Alert] = []
    ports_by_src: Dict[str, set] = defaultdict(set)
    last_seen_by_src: Dict[str, float] = {}
    for pkt in packets:
        if pkt.proto == "TCP" and pkt.dst_port is not None:
            ports_by_src[pkt.src_ip].add(pkt.dst_port)
            last_seen_by_src[pkt.src_ip] = max(last_seen_by_src.get(pkt.src_ip, pkt.timestamp), pkt.timestamp)

    for src_ip, ports in ports_by_src.items():
        count = len(ports)
        severity = _severity_for(count, BROAD_PORTS_LOW, BROAD_PORTS_MEDIUM, BROAD_PORTS_HIGH)
        if severity is None:
            continue
        alerts.append(
            Alert(
                detector="broad_port_usage",
                severity=severity,
                title="Unusually broad port usage",
                evidence=(
                    f"{src_ip} contacted {count} distinct destination ports across the "
                    f"capture -- unusually broad port usage ({severity.value})."
                ),
                src_ip=src_ip,
                metric_value=count,
                threshold=BROAD_PORTS_LOW,
                timestamp=last_seen_by_src[src_ip],
            )
        )
    return alerts


def detect_high_connection_rate(packets: List[PacketRecord]) -> List[Alert]:
    """Flag a host that opens an unusually large number of new TCP connections
    (pure SYNs) within a short window.

    False positives: load-testing tools, crawlers, media-heavy pages that
    open many parallel connections, or NAT gateways representing many users.
    """
    alerts: List[Alert] = []
    syns_by_src: Dict[str, List[float]] = defaultdict(list)
    for pkt in packets:
        if pkt.proto == "TCP" and "S" in pkt.flags and "A" not in pkt.flags:
            syns_by_src[pkt.src_ip].append(pkt.timestamp)

    for src_ip, timestamps in syns_by_src.items():
        count, start, end = _max_count_in_window(timestamps, CONN_RATE_WINDOW_SECONDS)
        severity = _severity_for(count, CONN_RATE_LOW, CONN_RATE_MEDIUM, CONN_RATE_HIGH)
        if severity is None:
            continue
        alerts.append(
            Alert(
                detector="high_connection_rate",
                severity=severity,
                title="Abnormally high connection rate",
                evidence=(
                    f"{src_ip} initiated {count} new TCP connections within "
                    f"{CONN_RATE_WINDOW_SECONDS} seconds -- abnormally high connection rate, "
                    f"possible scan or flood ({severity.value})."
                ),
                src_ip=src_ip,
                metric_value=count,
                threshold=CONN_RATE_LOW,
                window_seconds=CONN_RATE_WINDOW_SECONDS,
                timestamp=end,
            )
        )
    return alerts


def detect_suspicious_dns(dns_queries: List[DNSQuery]) -> List[Alert]:
    """Flag repetitive DNS querying (many lookups of the same domain from one
    host) and abnormally high DNS query rates from one host -- both are
    patterns associated with beaconing or DNS tunneling, though each can also
    occur legitimately.

    False positives: health-check/service-discovery traffic, CDN or ad-network
    lookups, browser prefetching, or a LAN resolver forwarding many real
    users' queries under one source IP.
    """
    alerts: List[Alert] = []

    repeat_counts: Counter = Counter((q.src_ip, q.query_name) for q in dns_queries)
    last_seen_by_pair: Dict[Tuple[str, str], float] = {}
    for q in dns_queries:
        key = (q.src_ip, q.query_name)
        last_seen_by_pair[key] = max(last_seen_by_pair.get(key, q.timestamp), q.timestamp)
    for (src_ip, query_name), count in repeat_counts.items():
        severity = _severity_for(count, DNS_REPEAT_LOW, DNS_REPEAT_MEDIUM, DNS_REPEAT_HIGH)
        if severity is None:
            continue
        alerts.append(
            Alert(
                detector="dns_repetitive",
                severity=severity,
                title="Repetitive DNS querying",
                evidence=(
                    f"{src_ip} issued {count} DNS queries for '{query_name}' -- repetitive "
                    f"querying consistent with beaconing, but also seen in legitimate "
                    f"health-check or retry traffic ({severity.value})."
                ),
                src_ip=src_ip,
                metric_value=count,
                threshold=DNS_REPEAT_LOW,
                timestamp=last_seen_by_pair[(src_ip, query_name)],
            )
        )

    timestamps_by_src: Dict[str, List[float]] = defaultdict(list)
    for q in dns_queries:
        timestamps_by_src[q.src_ip].append(q.timestamp)

    for src_ip, timestamps in timestamps_by_src.items():
        count, start, end = _max_count_in_window(timestamps, DNS_RATE_WINDOW_SECONDS)
        severity = _severity_for(count, DNS_RATE_LOW, DNS_RATE_MEDIUM, DNS_RATE_HIGH)
        if severity is None:
            continue
        alerts.append(
            Alert(
                detector="dns_high_rate",
                severity=severity,
                title="High-rate DNS querying",
                evidence=(
                    f"{src_ip} issued {count} DNS queries within {DNS_RATE_WINDOW_SECONDS} "
                    f"seconds -- unusually high DNS query rate ({severity.value})."
                ),
                src_ip=src_ip,
                metric_value=count,
                threshold=DNS_RATE_LOW,
                window_seconds=DNS_RATE_WINDOW_SECONDS,
                timestamp=end,
            )
        )

    return alerts


def detect_long_dns_labels(dns_queries: List[DNSQuery]) -> List[Alert]:
    """Flag DNS queries containing an unusually long subdomain label.

    DNS tunneling tools often encode payload data into a subdomain label, so
    labels approaching the protocol's 63-character maximum are worth a look.
    A 63-character label is valid DNS -- it is flagged for being unusual, not
    for violating the protocol. This is only an indicator: long labels also
    occur in legitimate traffic (CDN/object-storage hostnames, SPF/DKIM
    tokens), so this alone is not proof of tunneling.

    Each distinct (source, query name) pair is only alerted once, even if
    queried repeatedly -- repetition itself is covered separately by
    `detect_suspicious_dns`.
    """
    alerts: List[Alert] = []
    seen = set()
    for q in dns_queries:
        if (q.src_ip, q.query_name) in seen:
            continue
        seen.add((q.src_ip, q.query_name))
        labels = [label for label in q.query_name.strip(".").split(".") if label]
        if not labels:
            continue
        longest = max(labels, key=len)
        length = len(longest)
        severity = _severity_for(length, DNS_LABEL_LOW, DNS_LABEL_MEDIUM, DNS_LABEL_MAX)
        if severity is None:
            continue
        at_max = " (at the maximum length allowed by the DNS protocol)" if length == DNS_LABEL_MAX else ""
        alerts.append(
            Alert(
                detector="long_dns_label",
                severity=severity,
                title="Abnormally long DNS subdomain label",
                evidence=(
                    f"DNS query '{q.query_name}' from {q.src_ip} contains a {length}-character "
                    f"subdomain label{at_max} -- unusual and worth investigating as a possible "
                    f"indicator of DNS tunneling, not confirmation of it ({severity.value})."
                ),
                src_ip=q.src_ip,
                metric_value=length,
                threshold=DNS_LABEL_LOW,
                timestamp=q.timestamp,
            )
        )
    return alerts


def run_all_detectors(packets: List[PacketRecord], dns_queries: List[DNSQuery]) -> List[Alert]:
    """Run every detector and return all resulting alerts, sorted by severity
    (HIGH first). Alerts from different detectors are reported independently --
    there is no combined risk score, by design, to keep each finding simple
    and explainable on its own.
    """
    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    alerts = (
        detect_port_scan(packets)
        + detect_broad_port_usage(packets)
        + detect_high_connection_rate(packets)
        + detect_suspicious_dns(dns_queries)
        + detect_long_dns_labels(dns_queries)
    )
    return sorted(alerts, key=lambda a: severity_order[a.severity])
