"""Offline metadata fixtures. Never sends traffic or selects ML feature values."""
from pathlib import Path
import hashlib
import json
import random
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
from scripts.f5_fixtures import client_hello, server_hello, quic_initial

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / 'data/judge-demo/judge-demo.pcap'


def packets():
    result = []
    def add(t, transport, payload=b'', src='192.0.2.10', dst='198.51.100.10'):
        p = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst, id=1) / transport
        if payload:
            p /= Raw(payload)
        p.time = 1700000000 + t
        result.append(p)
    # Ordinary bidirectional UDP, no intended threat assertion.
    add(0, UDP(sport=41000, dport=9000), b'offline-demo')
    add(.01, UDP(sport=9000, dport=41000), b'ack', src='198.51.100.10', dst='192.0.2.10')
    # Sixty distinct destination ports: existing default fan-out threshold.
    for i in range(60):
        add(1+i*.02, TCP(sport=42000+i, dport=1000+i, flags='S'), src='192.0.2.20')
        add(1+i*.02+.001, TCP(sport=42000+i, dport=1000+i, flags='R'), src='192.0.2.20')
    # Eight regularly spaced short sessions: contextual periodicity only.
    for i in range(8):
        add(3+i*2, TCP(sport=43000+i, dport=8443, flags='S'), src='192.0.2.30')
        add(3+i*2+.01, TCP(sport=43000+i, dport=8443, flags='R'), src='192.0.2.30')
    # High-diversity synthetic labels, TXT questions and paired NXDOMAINs.
    for i in range(24):
        rng = random.Random(i)
        label = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(48))
        q = f'{label}.service.test'
        add(20+i*.1, UDP(sport=44000, dport=53), bytes(DNS(id=i, qd=DNSQR(qname=q, qtype=16))), src='192.0.2.40', dst='198.51.100.53')
        add(20+i*.1+.01, UDP(sport=53, dport=44000), bytes(DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname=q, qtype=16))), src='198.51.100.53', dst='192.0.2.40')
    # Split ClientHello plus ServerHello: deterministic protocol fixtures.
    hello = client_hello(sni='judge.example.test')
    add(24, TCP(sport=45000,dport=443,flags='PA',seq=1000), hello[:40],src='192.0.2.50')
    add(24.01,TCP(sport=45000,dport=443,flags='PA',seq=1040),hello[40:],src='192.0.2.50')
    add(24.02,TCP(sport=443,dport=45000,flags='PA',seq=2000),server_hello(),src='198.51.100.10',dst='192.0.2.50')
    add(24.03,TCP(sport=45000,dport=443,flags='R',seq=1000+len(hello)),src='192.0.2.50')
    # Visible QUIC header with inert placeholder ciphertext; not a full session.
    add(25,UDP(sport=46000,dport=443),quic_initial(),src='192.0.2.60')
    return sorted(result, key=lambda p: p.time)


def generate(path=PCAP):
    values = packets()
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), values)
    return {'filename': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'packet_count': len(values)}


if __name__ == '__main__':
    print(json.dumps(generate(), indent=2))
