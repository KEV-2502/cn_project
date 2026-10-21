from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

packets = []
t = 1766000000.0

# Three synthetic DNS queries
for i, domain in enumerate(
    ["example.com", "python.org", "wikipedia.org"]
):
    packet = (
        Ether()
        / IP(src="192.168.1.20", dst="8.8.8.8")
        / UDP(sport=53000 + i, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
    packet.time = t + i * 0.2
    packets.append(packet)

# Eighteen synthetic TCP SYN probes
for i, port in enumerate(range(20, 38)):
    packet = (
        Ether()
        / IP(src="192.168.1.50", dst="10.0.0.10")
        / TCP(sport=40000 + i, dport=port, flags="S")
    )
    packet.time = t + 2 + i * 0.1
    packets.append(packet)

wrpcap("data/test_port_scan.pcap", packets)

print(f"Created PCAP with {len(packets)} packets")
print("Expected: 3 DNS queries and 18 TCP SYN probes.")
