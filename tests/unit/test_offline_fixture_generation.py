"""RF-1: file serialization must never resolve neighbors or access a network."""
import hashlib
import socket
from contextlib import contextmanager

import pytest
from scapy import all as scapy_all, arch, sendrecv
from scapy.config import conf
from scapy.layers import inet, l2
from scapy.utils import rdpcap

from tests.fixtures import generate_test_pcap as generator


@contextmanager
def deny_network(monkeypatch):
    """Guard implementation globals and public aliases; do not suppress warnings."""
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        # pytest.fail raises BaseException, escaping Scapy's Exception fallback.
        pytest.fail('Fixture attempted network/resolver/interface operation')

    with monkeypatch.context() as guard:
        for module in (scapy_all, l2, inet, sendrecv, arch):
            for name in ('getmacbyip', 'srp1', 'srp', 'sr1', 'sr', 'send', 'sendp',
                         'get_if_hwaddr', 'resolve_iface', 'sniff', 'AsyncSniffer'):
                if hasattr(module, name):
                    guard.setattr(module, name, forbidden)
        guard.setattr(conf.neighbor, 'resolve', forbidden)
        guard.setattr(conf.route, 'route', forbidden)
        guard.setattr(conf.route6, 'route', forbidden)
        guard.setattr(conf, 'L2socket', forbidden)
        guard.setattr(conf, 'L2listen', forbidden)
        guard.setattr(conf, 'L3socket', forbidden)
        for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex',
                     'gethostbyaddr', 'create_connection', 'socket'):
            guard.setattr(socket, name, forbidden)
        yield
        assert not calls, 'A forbidden operation was swallowed during serialization'


def test_generation_offline_and_deterministic_at_same_epoch(tmp_path, monkeypatch):
    paths = [tmp_path/'first/input.pcap', tmp_path/'second/input.pcap']
    with deny_network(monkeypatch):
        # Control the pre-existing wall clock only in the regression.
        with monkeypatch.context() as clock:
            clock.setattr(generator.time, 'time', lambda: 1700000000.0)
            for path in paths:
                generator.generate_test_pcap(path)
        assert paths[0].read_bytes() == paths[1].read_bytes()
        assert hashlib.sha256(paths[0].read_bytes()).digest() == hashlib.sha256(paths[1].read_bytes()).digest()
        packets = rdpcap(str(paths[0]))
        assert len(packets) == 22
        assert [float(p.time) - 1700000000 for p in packets] == pytest.approx(
            [i*.1 for i in range(5)] + [.5+i*.1 for i in range(3)]
            + [1+i*.1 for i in range(10)] + [2, 2.1, 2.5, 2.6])
        for p in packets[:5] + packets[8:18]:
            assert (p.src, p.dst) == (generator.CLIENT_MAC, generator.TCP_PEER_MAC)
        for p in packets[5:8]:
            assert (p.src, p.dst) == (generator.TCP_PEER_MAC, generator.CLIENT_MAC)
        for p in packets[18:21]:
            assert (p.src, p.dst) == (generator.CLIENT_MAC, generator.UDP_ICMP_PEER_MAC)
        arp = packets[-1]
        assert (arp.src, arp.dst) == (generator.CLIENT_MAC, 'ff:ff:ff:ff:ff:ff')
        assert (arp[l2.ARP].hwsrc, arp[l2.ARP].hwdst) == (generator.CLIENT_MAC, '00:00:00:00:00:00')
        assert (arp[l2.ARP].psrc, arp[l2.ARP].pdst, arp[l2.ARP].op) == ('192.168.1.100', '192.168.1.1', 1)


def test_existing_wall_clock_only_changes_record_timestamps(tmp_path, monkeypatch):
    frames = []
    for index, epoch in enumerate((1700000000.0, 1700000100.0)):
        path = tmp_path/f'{index}.pcap'
        with deny_network(monkeypatch), monkeypatch.context() as clock:
            clock.setattr(generator.time, 'time', lambda: epoch)
            generator.generate_test_pcap(path)
            frames.append(rdpcap(str(path)))
    assert (tmp_path/'0.pcap').stat().st_size == (tmp_path/'1.pcap').stat().st_size
    assert (tmp_path/'0.pcap').read_bytes() != (tmp_path/'1.pcap').read_bytes()
    assert [bytes(p) for p in frames[0]] == [bytes(p) for p in frames[1]]
    assert all(float(b.time-a.time) == 100 for a,b in zip(*frames))


def test_guard_detects_missing_destination_mac_before_resolution(monkeypatch):
    # Negative control proves the old missing-MAC path cannot silently pass.
    with pytest.raises(pytest.fail.Exception, match='network/resolver'):
        with deny_network(monkeypatch):
            frame = l2.Ether(src=generator.CLIENT_MAC) / inet.IP(
                src='192.0.2.1', dst='198.51.100.1')
            bytes(frame)
