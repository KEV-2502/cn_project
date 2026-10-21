#!/usr/bin/env python3
"""Synthetic Bidirectional TCP Conversation PCAP Generator.

Generates a realistic, single-stream TCP conversation between a client and server:
1. TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)
2. Bidirectional Application Data Transfer (Client Request -> Server Response)
3. TCP Connection Teardown (FIN-ACK -> FIN-ACK -> ACK)

All packets share the same bidirectional 5-tuple and contain realistic, sequential
timestamps and consistent sequence/acknowledgement numbers.
"""

from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUTPUT_PCAP_PATH = Path(__file__).resolve().parent / "test_bidirectional.pcap"


def generate_bidirectional_packets(
    client_ip: str = "192.168.1.100",
    server_ip: str = "10.0.0.5",
    client_port: int = 54321,
    server_port: int = 80,
    base_time: float = 1766100000.0,
):
    """Construct a synthetic list of 9 Scapy packets representing a full TCP session."""
    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"

    client_isn = 100000
    server_isn = 500000

    request_payload = b"GET /index.html HTTP/1.1\r\nHost: test-server.local\r\n\r\n"
    response_payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!"

    req_len = len(request_payload)
    resp_len = len(response_payload)

    # 1. SYN (Client -> Server)
    p1 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=client_isn)
    )
    p1.time = base_time + 0.0

    # 2. SYN-ACK (Server -> Client)
    p2 = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=server_isn, ack=client_isn + 1)
    )
    p2.time = base_time + 0.05

    # 3. Handshake ACK (Client -> Server)
    p3 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=client_isn + 1, ack=server_isn + 1)
    )
    p3.time = base_time + 0.10

    # 4. Client Request Data (Client -> Server, PSH-ACK)
    p4 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=client_isn + 1, ack=server_isn + 1)
        / Raw(load=request_payload)
    )
    p4.time = base_time + 0.20

    # 5. Server Response Data (Server -> Client, PSH-ACK)
    p5 = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=server_isn + 1, ack=client_isn + 1 + req_len)
        / Raw(load=response_payload)
    )
    p5.time = base_time + 0.35

    # 6. Client Acknowledges Response Data (Client -> Server, ACK)
    p6 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=client_isn + 1 + req_len, ack=server_isn + 1 + resp_len)
    )
    p6.time = base_time + 0.45

    # 7. Client Initiates Teardown (Client -> Server, FIN-ACK)
    p7 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="FA", seq=client_isn + 1 + req_len, ack=server_isn + 1 + resp_len)
    )
    p7.time = base_time + 0.60

    # 8. Server Acknowledges and Closes (Server -> Client, FIN-ACK)
    p8 = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="FA", seq=server_isn + 1 + resp_len, ack=client_isn + 1 + req_len + 1)
    )
    p8.time = base_time + 0.70

    # 9. Client Final ACK (Client -> Server, ACK)
    p9 = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=client_isn + 1 + req_len + 1, ack=server_isn + 1 + resp_len + 1)
    )
    p9.time = base_time + 0.80

    return [p1, p2, p3, p4, p5, p6, p7, p8, p9]


def write_bidirectional_pcap(output_path: Path = OUTPUT_PCAP_PATH):
    packets = generate_bidirectional_packets()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    print(f"Generated bidirectional TCP PCAP with {len(packets)} packets at: {output_path}")
    return packets


if __name__ == "__main__":
    write_bidirectional_pcap()
