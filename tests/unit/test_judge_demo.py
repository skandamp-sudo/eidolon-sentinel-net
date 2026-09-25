"""Judge fixture safety, reproducibility and launcher failure boundaries."""
import hashlib
import ipaddress
import socket

import pytest
from scapy.all import IP, DNS, rdpcap
from scripts.generate_judge_demo import generate
from scripts.judge_demo import PCAP_SHA, port_available, preflight
from scripts.verify_judge_demo import stable


def test_fixture_reproduces_reviewed_bytes_and_reserved_addresses(tmp_path):
    a,b=tmp_path/'a.pcap',tmp_path/'b.pcap'
    assert generate(a)['packet_count']==191
    generate(b)
    assert a.read_bytes()==b.read_bytes()
    assert hashlib.sha256(a.read_bytes()).hexdigest()==PCAP_SHA
    allowed=[ipaddress.ip_network('192.0.2.0/24'),ipaddress.ip_network('198.51.100.0/24')]
    for packet in rdpcap(str(a)):
        for address in (packet[IP].src,packet[IP].dst):
            assert any(ipaddress.ip_address(address) in network for network in allowed)
        if DNS in packet:
            assert packet[DNS].qd[0].qname.endswith(b'.test.')


def test_preflight_missing_key_and_model_fail_closed(monkeypatch,capsys,tmp_path):
    monkeypatch.delenv('SENTINEL_API_KEY',raising=False)
    assert not preflight(tmp_path,0)
    assert capsys.readouterr().out.endswith('DEMO NOT READY\n')


def test_preflight_never_prints_key(monkeypatch,capsys,tmp_path):
    secret='private-demo-key-not-for-output'
    monkeypatch.setenv('SENTINEL_API_KEY',secret)
    assert not preflight(tmp_path,0)
    assert secret not in capsys.readouterr().out


def test_port_collision_is_not_ignored():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        with pytest.raises(OSError):port_available(listener.getsockname()[1])


def test_normalizer_preserves_scores_capture_time_and_membership():
    e={'id':'uuid','flow_id':'flow','src_ip':'192.0.2.1','dst_ip':'198.51.100.1','src_port':1,'dst_port':2,'protocol':'TCP','event_schema_version':'2.0.0','timestamp':5,'created_at':5,'classification_score':.3,'dns_observation':{'timestamp':12}}
    changed={**e,'id':'other','flow_id':'other-flow','timestamp':6,'created_at':6}
    assert stable([e],[e])==stable([changed],[changed])
    assert stable([e],[e])!=stable([{**e,'classification_score':.4}],[e])
    assert stable([e],[e])!=stable([{**e,'dns_observation':{'timestamp':13}}],[e])
    assert stable([{'contributing_event_ids':['uuid']}],[e])!=stable([{'contributing_event_ids':[]}],[e])


def test_unreviewed_pcap_rejected_before_model_load(tmp_path,monkeypatch):
    import scripts.judge_demo as demo
    packet=tmp_path/'invalid.pcap';packet.write_bytes(b'invalid')
    monkeypatch.setattr(demo,'PCAP',packet)
    with pytest.raises(ValueError,match='PCAP checksum'):demo.verify_assets(tmp_path)


def test_unreviewed_checksum_ledger_rejected_before_deserialization(tmp_path,monkeypatch):
    import scripts.judge_demo as demo
    bundle=tmp_path/demo.MODEL;bundle.mkdir(parents=True)
    manifest=b'locally trusted test manifest'
    (bundle/'manifest.json').write_bytes(manifest)
    (bundle/'checksums.json').write_bytes(b'forged')
    monkeypatch.setattr(demo,'MODEL_SHA',hashlib.sha256(manifest).hexdigest())
    with pytest.raises(ValueError,match='checksum ledger'):demo.verify_assets(tmp_path)
