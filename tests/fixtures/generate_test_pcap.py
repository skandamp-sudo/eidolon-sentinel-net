"""
Generate a test PCAP file for ingestion tests.
"""
import time
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap

def generate_test_pcap(output_path: Path):
    packets = []
    base_time = time.time()
    
    # 5 TCP SYN packets (192.168.1.100:12345 -> 10.0.0.1:80)
    for i in range(5):
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        pkt.time = base_time + i * 0.1
        packets.append(pkt)
        
    # 3 TCP SYN-ACK packets (10.0.0.1:80 -> 192.168.1.100:12345)
    for i in range(3):
        pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=12345, flags="SA")
        pkt.time = base_time + 0.5 + i * 0.1
        packets.append(pkt)
        
    # 10 TCP data packets with known payload sizes
    for i in range(10):
        payload = b"A" * (10 + i * 10)  # Payload sizes: 10, 20, 30...
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="PA") / payload
        pkt.time = base_time + 1.0 + i * 0.1
        packets.append(pkt)
        
    # 2 UDP packets (192.168.1.100:54321 -> 8.8.8.8:53) with DNS-like payload
    for i in range(2):
        # Fake DNS query payload
        payload = b"\\x00\\x00\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01"
        pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=54321, dport=53) / payload
        pkt.time = base_time + 2.0 + i * 0.1
        packets.append(pkt)
        
    # 1 ICMP echo request
    pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / ICMP(type=8) / b"PingPayload"
    pkt.time = base_time + 2.5
    packets.append(pkt)
    
    # 1 ARP packet (should be skipped by parser)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    pkt.time = base_time + 2.6
    packets.append(pkt)
    
    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    
    print(f"Generated {len(packets)} packets in {output_path}")
    print(f" - TCP SYN: 5")
    print(f" - TCP SYN-ACK: 3")
    print(f" - TCP Data: 10")
    print(f" - UDP DNS: 2")
    print(f" - ICMP: 1")
    print(f" - ARP: 1")
    
if __name__ == "__main__":
    output_file = Path(__file__).parent / "test_traffic.pcap"
    generate_test_pcap(output_file)
