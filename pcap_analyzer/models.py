"""Shared data structures used across the parser, statistics, detectors, and reporting layers.

Keeping these as plain dataclasses (rather than tying every module to Scapy's packet
objects) is what lets stats.py and detectors.py be tested with hand-built Python
objects instead of real capture files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Alert severity. Ordered low to high for sorting/display purposes."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class PacketRecord:
    """A minimal per-packet summary extracted from a capture."""

    timestamp: float
    src_ip: str
    dst_ip: str
    proto: str  # "TCP" | "UDP" | "OTHER"
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: str = ""  # TCP flag string, e.g. "S", "SA"; empty for non-TCP


@dataclass(frozen=True)
class DNSQuery:
    """A single DNS query observed in the capture."""

    timestamp: float
    src_ip: str
    query_name: str
    query_type: str = "A"


@dataclass(frozen=True)
class FlowKey:
    """Identifies a unidirectional flow by its 5-tuple."""

    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str


@dataclass
class Flow:
    """Aggregated traffic for a single FlowKey."""

    key: FlowKey
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    syn_count: int = 0


@dataclass
class StatsSummary:
    """Capture-wide traffic statistics."""

    total_packets: int
    total_bytes: int
    duration_seconds: float
    protocol_counts: dict = field(default_factory=dict)
    top_src_ips: list = field(default_factory=list)  # list[tuple[str, int]]
    top_dst_ips: list = field(default_factory=list)  # list[tuple[str, int]]
    top_dst_ports: list = field(default_factory=list)  # list[tuple[int, int]]
    top_flows: list = field(default_factory=list)  # list[Flow]
    unique_hosts: int = 0
    dns_query_count: int = 0


@dataclass
class Alert:
    """A single security finding produced by a detector.

    `evidence` is the human-readable explanation required by design: it must state
    the metric observed and use hedged language ("possible", "suspicious") rather
    than asserting confirmed malicious activity.
    """

    detector: str
    severity: Severity
    title: str
    evidence: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    metric_value: float = 0
    threshold: float = 0
    window_seconds: Optional[float] = None
    timestamp: Optional[float] = None
