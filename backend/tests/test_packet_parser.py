"""Unit tests for the Scapy packet parsing engine."""

import time
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ARP
from scapy.layers.inet6 import ICMPv6EchoRequest
from backend.app.pipeline.parser import parse_packet, ParsedPacket


def test_parse_ipv4_tcp_packet():
    # Build TCP SYN packet with payload
    pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=443, flags="S") / Raw(load=b"HELLO")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert isinstance(parsed, ParsedPacket)
    assert parsed.ip_version == 4
    assert parsed.src_ip == "192.168.1.10"
    assert parsed.dst_ip == "10.0.0.1"
    assert parsed.src_port == 54321
    assert parsed.dst_port == 443
    assert parsed.protocol == "TCP"
    assert parsed.tcp_flags == "S"
    assert parsed.payload_len == 5
    # Assert byte count semantics
    assert parsed.frame_len > parsed.ip_len
    assert parsed.ip_len > parsed.payload_len


def test_parse_ipv6_packet():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=8080, dport=80, flags="A")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.ip_version == 6
    assert parsed.src_ip == "2001:db8::1"
    assert parsed.dst_ip == "2001:db8::2"
    assert parsed.src_port == 8080
    assert parsed.dst_port == 80
    assert parsed.protocol == "TCP"
    assert parsed.tcp_flags == "A"


def test_parse_udp_packet():
    pkt = Ether() / IP(src="172.16.0.5", dst="172.16.0.1") / UDP(sport=5000, dport=5001) / Raw(load=b"DATA")
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "UDP"
    assert parsed.src_ip == "172.16.0.5"
    assert parsed.dst_ip == "172.16.0.1"
    assert parsed.src_port == 5000
    assert parsed.dst_port == 5001
    assert parsed.payload_len == 4
    assert parsed.tcp_flags == ""


def test_parse_icmp_ipv4():
    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.254") / ICMP(type=8, code=0)
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.src_ip == "192.168.1.1"
    assert parsed.dst_ip == "192.168.1.254"
    assert parsed.src_port == 0
    assert parsed.dst_port == 0


def test_parse_icmpv6():
    pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest()
    parsed = parse_packet(pkt)

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.ip_version == 6
    assert parsed.src_ip == "fe80::1"
    assert parsed.dst_ip == "fe80::2"
    assert parsed.src_port == 0
    assert parsed.dst_port == 0


def test_parse_dns_query_and_response():
    # DNS Query
    query = Ether() / IP(src="10.0.0.50", dst="8.8.8.8") / UDP(sport=43210, dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious-domain.test"))
    parsed_q = parse_packet(query)

    assert parsed_q is not None
    assert parsed_q.protocol == "DNS"
    assert parsed_q.dns_query_name == "malicious-domain.test"
    assert parsed_q.dns_is_response is False

    # DNS Response
    response = Ether() / IP(src="8.8.8.8", dst="10.0.0.50") / UDP(sport=53, dport=43210) / DNS(qr=1, qd=DNSQR(qname="malicious-domain.test"), an=DNSRR(rrname="malicious-domain.test", rdata="1.2.3.4"))
    parsed_r = parse_packet(response)

    assert parsed_r is not None
    assert parsed_r.protocol == "DNS"
    assert parsed_r.dns_query_name == "malicious-domain.test"
    assert parsed_r.dns_is_response is True


def test_non_ip_packet_ignored():
    arp_pkt = Ether() / ARP(pdst="192.168.1.1")
    parsed = parse_packet(arp_pkt)
    assert parsed is None


def test_malformed_packet_handled_gracefully():
    # Corrupted raw packet
    corrupted_pkt = Ether() / Raw(load=b"\x00\xff\xee\xdd\xcc\xbb")
    parsed = parse_packet(corrupted_pkt)
    assert parsed is None
