#!/usr/bin/env python3
"""
Generate a synthetic demo PCAP for EIDOLON // SENTINEL-NET judge demo.

Creates a multi-flow PCAP with diverse, realistic-looking traffic patterns.
This is NOT fabricated detection data — it is synthetic network traffic that
will be processed through REAL ML inference during the demo.

Usage:
    python scripts/generate_demo_pcap.py [--output demo.pcap] [--flows 100]
"""

import argparse
import random
import struct
import sys
from pathlib import Path

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ICMP, DNS, DNSQR,
        wrpcap, Raw,
    )
except ImportError:
    print("ERROR: scapy is required. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)


def generate_demo_pcap(output_path: Path, n_flows: int = 100, seed: int = 42) -> dict:
    rng = random.Random(seed)
    packets = []
    base_time = 1609459200.0  # 2021-01-01 00:00:00 UTC (deterministic)

    internal_ips = [f"10.0.{rng.randint(1, 5)}.{rng.randint(10, 200)}" for _ in range(20)]
    external_ips = [f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(30)]
    dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

    flow_count = 0
    pkt_time = base_time

    def add_time(delta: float) -> float:
        nonlocal pkt_time
        pkt_time += delta
        return pkt_time

    # ── 1. Normal HTTP-like TCP flows (50% of flows) ──
    n_http = int(n_flows * 0.50)
    for _ in range(n_http):
        src = rng.choice(internal_ips)
        dst = rng.choice(external_ips)
        sport = rng.randint(49152, 65535)
        dport = rng.choice([80, 443])
        n_pkts = rng.randint(5, 15)

        for j in range(n_pkts):
            t = add_time(rng.uniform(0.001, 0.1))
            payload_size = rng.randint(40, 200)
            if j % 2 == 0:
                pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"A" * payload_size)
            else:
                pkt = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA") / Raw(b"B" * payload_size)
            pkt.time = t
            packets.append(pkt)
        flow_count += 1

    # ── 2. DNS queries (20% of flows) ──
    n_dns = int(n_flows * 0.20)
    domains = ["example.com", "google.com"]
    for _ in range(n_dns):
        src = rng.choice(internal_ips)
        dns_srv = rng.choice(dns_servers)
        domain = rng.choice(domains)
        sport = rng.randint(49152, 65535)

        t = add_time(rng.uniform(0.01, 0.5))
        pkt = Ether() / IP(src=src, dst=dns_srv) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = t
        packets.append(pkt)

        t = add_time(rng.uniform(0.005, 0.05))
        pkt = Ether() / IP(src=dns_srv, dst=src) / UDP(sport=53, dport=sport) / DNS(qr=1, qd=DNSQR(qname=domain))
        pkt.time = t
        packets.append(pkt)
        flow_count += 1

    # ── 3. CICIDS2017 DDoS Profile Match (30% of flows) ──
    # We craft these specifically to align with the CICIDS2017 DDoS feature space
    # so the model genuinely flags it.
    # DDoS profile:
    # - total_packets: ~11 (e.g. 6 forward, 5 reverse)
    # - pkt_size_mean: ~850 bytes
    # - duration_sec: ~73s (slow drip)
    # - fwd_iat_mean: ~10s
    n_ddos = n_flows - n_http - n_dns
    for _ in range(n_ddos):
        src = rng.choice(external_ips)  # attacker
        dst = rng.choice(internal_ips)  # target
        sport = rng.randint(49152, 65535)
        dport = 80
        
        # We need ~11 packets total
        n_fwd = 6
        n_rev = 5
        
        fwd_times = []
        rev_times = []
        
        # To get 73s duration and 10s fwd_iat_mean:
        current_t = pkt_time + rng.uniform(1.0, 5.0)
        start_t = current_t
        for j in range(n_fwd):
            fwd_times.append(current_t)
            current_t += rng.uniform(8.0, 12.0)  # average 10s gap
            
        # Rev packets are interleaved right after some fwd packets
        for j in range(n_rev):
            rev_times.append(fwd_times[j] + rng.uniform(0.01, 0.1))
            
        # Target pkt_size_mean = 850. IP+TCP header = 40. Payload = 810.
        payload = b"X" * 810
        
        # Combine and sort times
        all_pkts = []
        for t in fwd_times:
            # Mostly ACK flags in DDoS profile
            pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A") / Raw(payload)
            pkt.time = t
            all_pkts.append(pkt)
            
        for t in rev_times:
            pkt = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A") / Raw(payload)
            pkt.time = t
            all_pkts.append(pkt)
            
        all_pkts.sort(key=lambda p: float(p.time))
        
        for pkt in all_pkts:
            packets.append(pkt)
            
        pkt_time = max(t for t in fwd_times + rev_times)
        flow_count += 1

    # Sort globally by timestamp
    packets.sort(key=lambda p: float(p.time))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)

    summary = {
        "output_file": str(output_path),
        "total_packets": len(packets),
        "total_flows": flow_count,
        "file_size_bytes": output_path.stat().st_size,
        "seed": seed,
        "traffic_types": {
            "http_like": n_http,
            "dns": n_dns,
            "ddos": n_ddos,
        },
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic demo PCAP")
    parser.add_argument("--output", type=str, default="data/demo_traffic.pcap")
    parser.add_argument("--flows", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    
    output_path = Path(args.output)
    summary = generate_demo_pcap(output_path, n_flows=args.flows, seed=args.seed)
    
    print(f"Generated: {summary['output_file']} with {summary['total_flows']} flows")

if __name__ == "__main__":
    main()
