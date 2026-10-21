"""Packet Parsing Engine.

Decodes network packets using Scapy, extracting layer-specific metadata for IPv4,
IPv6, TCP, UDP, ICMP, and DNS protocols.

Byte Count Semantics:
---------------------
- frame_len: Captured L2 frame length (total raw wire bytes captured).
- ip_len: Total IP packet length (IP header + payload). This represents the
  standard network layer octet count (RFC 7011 / IPFIX octetDeltaCount) and is
  used as the canonical byte metric for bidirectional network flows.
- payload_len: L4 transport payload length (excluding TCP/UDP headers).
"""

from dataclasses import dataclass, field
from typing import Optional, Iterator
from pathlib import Path

import scapy.all as scapy
from scapy.utils import PcapReader, PcapNgReader, Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS


@dataclass
class ParsedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, DNS
    ip_version: int  # 4 or 6
    frame_len: int  # Total captured frame length
    ip_len: int  # IP packet length (canonical flow byte metric)
    payload_len: int  # Transport payload length
    tcp_flags: str = ""  # Flags string representation e.g. "S", "SA", "FA", "R"
    dns_query_name: Optional[str] = None
    dns_is_response: Optional[bool] = None


def get_pcap_reader(filepath: str | Path) -> Iterator:
    """Return an appropriate Scapy streaming reader for PCAP or PCAPNG files.

    Detects the file format by checking the magic number header.
    Raises Scapy_Exception or ValueError if the file cannot be read.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Capture file not found: {filepath}")

    if path.stat().st_size == 0:
        raise Scapy_Exception("File is empty (0 bytes).")

    with open(path, "rb") as f:
        magic = f.read(4)

    # PCAPNG files start with Section Header Block magic: 0x0A0D0D0A (\n\r\r\n)
    if magic == b"\x0a\x0d\x0d\x0a":
        return PcapNgReader(str(path))
    
    # Standard PCAP magic numbers (microsecond or nanosecond, big or little endian)
    pcap_magics = [
        b"\xa1\xb2\xc3\xd4",
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x4d\x3c\xb2\xa1",
    ]
    if magic in pcap_magics:
        return PcapReader(str(path))

    # Attempt standard PcapReader as fallback (letting Scapy validate)
    return PcapReader(str(path))


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """Parse a raw Scapy packet into a structured ParsedPacket object.

    Extracts IPv4/IPv6, TCP, UDP, ICMP, and DNS metadata.
    Returns None for non-IP packets, malformed headers, or unsupported link types.
    """
    try:
        # Require IP or IPv6 layer
        has_ip = pkt.haslayer(IP)
        has_ipv6 = pkt.haslayer(IPv6)

        if not has_ip and not has_ipv6:
            # Non-IP packet (e.g. ARP, STP, raw ethernet broadcast)
            return None

        # Timestamp
        pkt_time = float(pkt.time)

        # Captured frame length
        try:
            frame_len = len(bytes(pkt))
        except Exception:
            frame_len = len(pkt)

        # IP Layer extraction
        if has_ip:
            ip_layer = pkt[IP]
            ip_version = 4
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            # Use parsed IP layer length (fallback to wire length if corrupted)
            try:
                ip_len = len(ip_layer)
            except Exception:
                ip_len = frame_len
        else:
            ip_layer = pkt[IPv6]
            ip_version = 6
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            try:
                ip_len = len(ip_layer)
            except Exception:
                ip_len = frame_len

        # Transport & Application layers
        protocol = "UNKNOWN"
        src_port = 0
        dst_port = 0
        payload_len = 0
        tcp_flags = ""
        dns_query_name = None
        dns_is_response = None

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
            try:
                payload_len = len(tcp_layer.payload)
            except Exception:
                payload_len = 0

            # Check if DNS over TCP
            if pkt.haslayer(DNS):
                protocol = "DNS"
                dns_layer = pkt[DNS]
                dns_is_response = bool(dns_layer.qr == 1)
                try:
                    qd = dns_layer.qd
                    if qd:
                        first_q = qd[0] if isinstance(qd, list) else qd
                        if hasattr(first_q, "qname") and first_q.qname:
                            dns_query_name = first_q.qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    pass

        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            try:
                payload_len = len(udp_layer.payload)
            except Exception:
                payload_len = 0

            # Check if DNS over UDP
            if pkt.haslayer(DNS):
                protocol = "DNS"
                dns_layer = pkt[DNS]
                dns_is_response = bool(dns_layer.qr == 1)
                try:
                    qd = dns_layer.qd
                    if qd:
                        first_q = qd[0] if isinstance(qd, list) else qd
                        if hasattr(first_q, "qname") and first_q.qname:
                            dns_query_name = first_q.qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    pass

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_layer = pkt[ICMP]
            src_port = 0
            dst_port = 0
            try:
                payload_len = len(icmp_layer.payload)
            except Exception:
                payload_len = 0

        else:
            # Check for ICMPv6
            layer_names = [l.__name__ for l in pkt.layers()]
            if any(name.startswith("ICMPv6") for name in layer_names):
                protocol = "ICMP"
                src_port = 0
                dst_port = 0
                payload_len = 0
            else:
                # Other IP protocol (e.g., IGMP, GRE, ESP, OSPF)
                protocol = f"IP_{ip_layer.proto}" if has_ip else "IPv6_NH"
                src_port = 0
                dst_port = 0
                payload_len = 0

        return ParsedPacket(
            timestamp=pkt_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            ip_version=ip_version,
            frame_len=frame_len,
            ip_len=ip_len,
            payload_len=payload_len,
            tcp_flags=tcp_flags,
            dns_query_name=dns_query_name,
            dns_is_response=dns_is_response,
        )

    except Exception:
        # Graceful handling of malformed or corrupted packets
        return None
