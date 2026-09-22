"""Safe passive metadata fixtures; protocol validation, not malware samples."""

import hashlib
import random
from types import SimpleNamespace

import pytest
from scapy.all import IP, TCP, UDP, Ether, IPv6, Raw

from scripts.f5_fixtures import client_hello, quic_initial, record, server_hello, vector
from sentinel_net.encrypted.config import EncryptedConfig
from sentinel_net.encrypted.engine import EncryptedIntelligence
from sentinel_net.encrypted.quic import parse_quic, varint
from sentinel_net.encrypted.reassembly import Direction
from sentinel_net.encrypted.tls import GREASE, fingerprint, parse_records
from sentinel_net.encrypted.wire import Invalid
from sentinel_net.ingestion.parser import extract_raw_packet, parse_packet
from sentinel_net.models.types import FlowKey
from sentinel_net.sensor.metrics import SensorMetrics


def packet(
    payload=None,
    *,
    seq=1000,
    timestamp=1000,
    reverse=False,
    udp=False,
    sport=42000,
    flags="PA",
    ipv6=False,
):
    src, dst = ("192.0.2.1", "198.51.100.1") if not ipv6 else ("2001:db8::1", "2001:db8::2")
    ports = (sport, 443)
    if reverse:
        src, dst = dst, src
        ports = ports[::-1]
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / (
        IPv6(src=src, dst=dst) if ipv6 else IP(src=src, dst=dst)
    )
    p = (
        p
        / (
            UDP(sport=ports[0], dport=ports[1])
            if udp
            else TCP(sport=ports[0], dport=ports[1], seq=seq, flags=flags)
        )
        / Raw(client_hello() if payload is None else payload)
    )
    p.time = timestamp
    return parse_packet(extract_raw_packet(p))


def engine(**kwargs):
    return EncryptedIntelligence(EncryptedConfig(**kwargs), SensorMetrics())


def event_for(e, p, start=1000):
    event = SimpleNamespace(
        metadata={"behavioral_evidence": [{"kept": True}], "dns_evidence": [{"kept": True}]},
        severity="info",
        classification_score=0.3,
        anomaly_score=0.2,
    )
    flow = SimpleNamespace(
        flow_key=FlowKey(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol),
        start_time=start,
        end_time=p.timestamp,
    )
    e.enrich(event, flow)
    return event


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"sni": None},
        {"sni": "API.Example.Test"},
        {"alpn": ("h2",)},
        {"alpn": ("http/1.1",)},
        {"tls13": False},
        {"version": 769, "tls13": False},
        {"ciphers": (47, 53, 49199, 4865)},
        {"extensions": []},
    ],
)
def test_legitimate_client_profiles(kwargs):
    result = parse_records(client_hello(**kwargs))
    assert result["status"] == "COMPLETE"
    hello = result["hello"]
    assert hello["handshake_type"] == 1 and hello["fingerprint"]["family"] == "JA3"
    assert "malware conclusion" in hello["fingerprint"]["semantics"]
    assert "random" not in hello and "session_id" not in hello


def test_offered_versions_not_legacy_version_and_sni_normalization():
    h = parse_records(client_hello(sni="API.Example.Test"))["hello"]
    assert (
        h["legacy_version"] == 771
        and h["supported_versions"] == [772, 771]
        and h["selected_version"] is None
    )
    assert h["sni"] == "api.example.test" and h["alpn"][0] == {"value": "h2", "encoding": "ascii"}


def test_standard_ja3_published_vector_and_grease():
    ciphers = (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4)
    extensions = [
        (0, vector(b"\0" + vector(b"example.test"))),
        (10, vector(b"\0\x17\0\x18\0\x19")),
        (11, b"\1\0"),
    ]
    h = parse_records(client_hello(version=769, ciphers=ciphers, extensions=extensions))["hello"]
    assert (
        h["fingerprint"]["canonical"]
        == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    )
    assert h["fingerprint"]["digest"] == "ada70206e40642a3e4461f35503241d5"
    h["cipher_suites"] = [*GREASE, *h["cipher_suites"]]
    h["extension_ids"] = [*GREASE, *h["extension_ids"]]
    h["supported_groups"] = [*GREASE, *h["supported_groups"]]
    assert fingerprint(h)["digest"] == "ada70206e40642a3e4461f35503241d5"


def test_standard_ja3_empty_extensions_published_vector():
    result = parse_records(
        client_hello(version=769, ciphers=(4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99), extensions=[])
    )
    assert result["hello"]["fingerprint"]["digest"] == "de350869b8c85de67a350c8d186f11e6"


def test_ja3s_canonicalization_and_selected_version():
    h = parse_records(server_hello())["hello"]
    assert h["selected_version"] == 772 and h["selected_cipher_suite"] == 4865
    assert h["fingerprint"]["canonical"] == "771,4865,43-51"
    assert h["fingerprint"]["digest"] == "f4febc55ea12b31ae17cfb7e614afda8"


@pytest.mark.parametrize("mode", ["client", "server", "both"])
def test_one_way_visibility_and_unchanged_scores(mode):
    e = engine()
    packets = []
    if mode != "server":
        packets.append(packet())
    if mode != "client":
        packets.append(packet(server_hello(), reverse=True, timestamp=1000.1))
    for p in packets:
        e.observe_packet(p)
    event = event_for(e, p)
    assert event.metadata["tls_status"] == "COMPLETE"
    assert (
        event.metadata["tls_observation"]["visibility"]
        == {"client": "CLIENT_ONLY", "server": "SERVER_ONLY", "both": "BOTH"}[mode]
    )
    assert (
        event.classification_score == 0.3
        and event.anomaly_score == 0.2
        and event.severity == "info"
    )
    assert event.metadata["dns_evidence"] == [{"kept": True}]
    assert all(
        s["reference_threshold"] is None and "No malware verdict" in s["confidence_semantics"]
        for s in event.metadata["tls_evidence"]
    )
    assert e.metrics.tls_client_hello == (mode != "server")


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 0, 1), (1, 0, 2), (0, 0, 1, 2)])
def test_split_reordered_retransmitted_handshake(order):
    data = client_hello()
    cuts = (0, 17, 50, len(data))
    e = engine()
    for i in order:
        p = packet(
            data[cuts[i] : cuts[i + 1]], seq=1000 + cuts[i], timestamp=1000 + len(order) * 0.01
        )
        e.observe_packet(p)
    assert event_for(e, p).metadata["tls_status"] == "COMPLETE"
    assert e.metrics.tls_client_hello == 1 and e.metrics.tls_reassembly_bytes == 0
    assert e.metrics.tls_reassembly_bytes_peak == 2 * 32768


def test_handshake_spans_records_and_sequence_wrap():
    data = client_hello()[5:]
    split = record(data[:30]) + record(data[30:])
    assert parse_records(split)["status"] == "COMPLETE"
    d = Direction(1000)
    d.feed(0xFFFFFFF0, split[:30], 32768)
    assert d.feed(14, split[30:], 32768)["status"] == "COMPLETE"


def test_conflicting_overlap_discards_without_fake_metadata():
    data = client_hello()
    d = Direction(1000)
    d.feed(10, data[:30], 32768)
    result = d.feed(20, b"xxxxxxxx", 32768)
    assert result["status"] == "MALFORMED" and "hello" not in result and not d.data


def test_identical_partial_overlap_is_accepted():
    data = client_hello()
    d = Direction(1000)
    d.feed(10, data[:35], 32768)
    assert d.feed(30, data[20:], 32768)["status"] == "COMPLETE"
    assert d.retransmitted_bytes == 15


def test_ciphertext_header_never_becomes_hello():
    r = parse_records(record(b"secret ciphertext", content=23))
    assert r["status"] == "ENCRYPTED_APPLICATION_DATA" and "hello" not in r
    assert "secret" not in str(r)
    assert parse_records(b"\x17\x03\x03\x40\x80")["status"] == "ENCRYPTED_APPLICATION_DATA"


@pytest.mark.parametrize(
    "extension_value",
    [
        (0, b"\0\x05\0\0\x03ab"),
        (0, vector(b"\0" + vector(b"bad..test"))),
        (0, vector(b"\0" + vector(b"bad\x00.test"))),
        (16, b"\0\x03\x04ab"),
        (16, b"\0\x01\0"),
        (10, b"\0\x03abc"),
        (43, b"\x03abc"),
        (11, b"\x02\0"),
    ],
)
def test_malformed_nested_extensions(extension_value):
    r = parse_records(client_hello(extensions=[extension_value]))
    assert r["status"] == "MALFORMED" and "hello" not in r


@pytest.mark.parametrize(
    "data,status",
    [
        (b"\x16\x03\x03\xff\xff", "MALFORMED"),
        (b"\x16\x03\x03\0\0", "MALFORMED"),
        (record(b"\x01\xff\xff\xff"), "MALFORMED"),
        (record(b"\x01\0\0\x01x"), "MALFORMED"),
        (client_hello()[:-1], "INCOMPLETE"),
        (client_hello(ciphers=tuple(range(257))), "UNSUPPORTED"),
        (client_hello(extensions=[(100 + i, b"") for i in range(65)]), "UNSUPPORTED"),
        (client_hello(extensions=[(100, b"x" * 4097)]), "UNSUPPORTED"),
        (client_hello(extensions=[(100, b""), (100, b"")]), "MALFORMED"),
    ],
)
def test_tls_length_caps(data, status):
    assert parse_records(data)["status"] == status


def test_ech_and_opaque_alpn_are_honest():
    h = parse_records(
        client_hello(extensions=[(0xFE0D, b"opaque"), (16, vector(vector(b"\0\xff", 1)))])
    )["hello"]
    assert h["sni"] is None and h["sni_status"] == "unavailable_ech_extension_observed"
    assert h["alpn"] == [{"value": "00ff", "encoding": "hex"}]
    assert h["ja4_status"] == "NOT_IMPLEMENTED"


@pytest.mark.parametrize("kind", [0, 1, 2, 3])
def test_quic_v1_visible_header_types(kind):
    data = quic_initial(packet_type=kind)
    r = parse_quic(data)
    assert r["status"] == "COMPLETE" and r["version"] == 1 and r["long_header"]
    assert (
        r["destination_cid_length"] == 8
        and r["destination_cid_sha256"] == hashlib.sha256(b"client01").hexdigest()
    )
    assert "client01" not in str(r) and r["payload_inspected"] is False


def test_quic_version_negotiation_and_unknown_version():
    r = parse_quic(quic_initial(version=0))
    assert r["supported_versions"] == [1, 0x6B3343CF]
    r = parse_quic(quic_initial(version=0x6B3343CF))
    assert r["status"] == "UNSUPPORTED" and r["packet_type"] == "UNKNOWN_VERSION"
    assert "token_length" not in r and "declared_packet_length" not in r


@pytest.mark.parametrize(
    "data,status",
    [
        (b"", "TRUNCATED"),
        (b"\xc0\0", "TRUNCATED"),
        (b"\xc0\0\0\0\1\x15", "MALFORMED"),
        (b"\x40random", "UNSUPPORTED"),
        (b"random UDP payload", "UNSUPPORTED"),
        (quic_initial()[:-1], "TRUNCATED"),
        (quic_initial()[:23] + b"\xc0", "TRUNCATED"),
        (quic_initial()[:24] + b"\0", "MALFORMED"),
        (quic_initial(version=0)[:-1], "MALFORMED"),
    ],
)
def test_quic_bad_lengths(data, status):
    assert parse_quic(data)["status"] == status


@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_varint_widths_and_truncation(width):
    value = (5).to_bytes(width, "big")
    value = bytes([value[0] | ({1: 0, 2: 64, 4: 128, 8: 192}[width])]) + value[1:]
    assert varint(value, 0) == (5, width)
    with pytest.raises(Invalid):
        varint(value[:-1], 0)


def test_state_byte_caps_expiry_and_no_missing_peer_failure():
    e = engine(max_connections=2, max_direction_bytes=1024, max_samples=4)
    for i in range(5):
        e.observe_packet(packet(client_hello()[:20], sport=42000 + i))
    assert len(e.connections) == 2 and e.metrics.tls_reassembly_evictions == 3
    assert e.metrics.tls_reassembly_bytes <= 2 * 2 * 1024
    e.advance(1011)
    assert e.metrics.tls_reassembly_bytes == 0 and e.metrics.tls_truncated == 2
    for c in e.connections.values():
        assert all(d.result["status"] == "TRUNCATED" for d in c.directions.values())
    e.advance(1061)
    assert not e.connections
    e.close()
    assert e.metrics.encrypted_metadata_state == 0


def test_excessive_reassembly_span_and_old_capture_exclusion():
    d = Direction(1000)
    d.feed(100, client_hello()[:20], 1024)
    assert d.feed(2000, b"x", 1024)["status"] == "TRUNCATED" and not d.data
    e = engine()
    e.observe_packet(packet(timestamp=1100))
    e.observe_packet(packet(timestamp=1000, sport=49000))
    assert len(e.connections) == 1 and e.metrics.encrypted_metadata_late_observations == 1


def test_timing_capped_samples_not_secret_model():
    e = engine(max_samples=4)
    for i in range(10):
        e.observe_packet(
            packet(timestamp=1000 + i, payload=client_hello() if i == 0 else b"", seq=1000 + i)
        )
    p = packet(timestamp=1009)
    event = event_for(e, p)
    timing = event.metadata["tls_observation"]["timing"]
    assert (
        timing["sample_count"] == 4
        and timing["samples_capped"]
        and timing["inter_packet_mean_sec"] == 1
    )
    assert "ENCRYPTED_SESSION_PACKET_TIMING" in {
        x["signal_type"] for x in event.metadata["tls_evidence"]
    }


def test_reused_tuple_and_syn_epoch_do_not_inherit_old_metadata():
    e = engine()
    e.observe_packet(packet())
    p = packet(b"", seq=5000, timestamp=1005, flags="S")
    e.observe_packet(p)
    assert event_for(e, p, start=1005).metadata["tls_status"] == "UNAVAILABLE"
    assert event_for(e, p, start=1006).metadata["tls_status"] == "UNAVAILABLE"


def test_quic_one_direction_and_ipv6():
    e = engine()
    p = packet(quic_initial(), udp=True, ipv6=True)
    e.observe_packet(p)
    event = event_for(e, p)
    assert event.metadata["quic_status"] == "COMPLETE"
    assert event.metadata["quic_observation"]["visibility"] == "ONE_DIRECTION_OBSERVED"
    assert event.metadata["quic_observation"]["timing"]["inter_packet_mean_sec"] is None


def test_random_inputs_never_crash():
    rng = random.Random(42)
    for i in range(300):
        data = rng.randbytes(i * 7)
        assert parse_records(data)["status"] != "COMPLETE"
        assert parse_quic(data)["status"] in ("UNSUPPORTED", "MALFORMED", "TRUNCATED", "COMPLETE")


def test_no_active_network_or_decryption(monkeypatch):
    import socket
    import ssl

    import scapy.all

    def forbidden(*a, **k):
        raise AssertionError("active or TLS operation")

    for n in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, n, forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    for n in ("send", "sendp", "sr", "sr1", "srp"):
        monkeypatch.setattr(scapy.all, n, forbidden)
    e = engine()
    p = packet()
    e.observe_packet(p)
    assert event_for(e, p).metadata["tls_status"] == "COMPLETE"


@pytest.mark.parametrize(
    "config",
    [
        {"max_connections": 0},
        {"tls_ports": tuple(range(20))},
        {"max_direction_bytes": 0},
        {"handshake_ttl_sec": 20, "connection_ttl_sec": 10},
    ],
)
def test_invalid_configuration(config):
    with pytest.raises(ValueError):
        EncryptedConfig(**config)


def test_repeated_fingerprints_stay_contextual_and_new_syn_after_close_resets():
    e = engine()
    p = packet(flags="S")
    e.observe_packet(p)
    p = packet(b"", flags="R", seq=2000, timestamp=1001)
    e.observe_packet(p)
    p = packet(flags="S", seq=1000, timestamp=1002)
    e.observe_packet(p)
    event = event_for(e, p, start=1002)
    assert event.metadata["tls_status"] == "COMPLETE"
    assert e.metrics.tls_client_hello == 2
    assert all("MALWARE" not in s["signal_type"] for s in event.metadata["tls_evidence"])


def test_multiple_alpn_items_and_sni_count_limits():
    assert (
        parse_records(client_hello(alpn=tuple(f"p{i}" for i in range(17))))["status"]
        == "UNSUPPORTED"
    )
    value = vector(b"\0" + vector(b"one.test") + b"\0" + vector(b"two.test"))
    assert parse_records(client_hello(extensions=[(0, value)]))["status"] == "UNSUPPORTED"


def test_protocol_data_never_persisted():
    # Client random/session/key-share/token/ciphertext bytes are transient only.
    data = bytearray(client_hello())
    data[11:43] = b"private-transient-random-marker!"
    result = parse_records(bytes(data))
    assert result["status"] == "COMPLETE"
    assert "private-transient" not in str(result)
    q = parse_quic(quic_initial(packet_type=3))
    assert "token" not in str(q).replace("token_length", "")


def test_ccs_boundary_never_interprets_following_bytes_as_plaintext_hello():
    result = parse_records(record(b'\x01', content=20) + client_hello())
    assert result['status'] == 'UNAVAILABLE' and 'hello' not in result
    assert 'ChangeCipherSpec' in result['reason']


def test_quic_initial_metadata_survives_later_short_header():
    e = engine()
    e.observe_packet(packet(quic_initial(), udp=True))
    p = packet(b'\x40opaque-protected-short-header', udp=True, timestamp=1001)
    e.observe_packet(p)
    observation = event_for(e, p).metadata['quic_observation']['directions'][0]
    assert observation['version'] == 1 and observation['timestamp'] == 1000
    assert observation['latest_packet_status'] == 'UNSUPPORTED'
    assert observation['last_packet_timestamp'] == 1001
    assert observation['payload_inspected'] is False


def test_late_first_segment_cannot_bypass_handshake_deadline():
    e = engine()
    e.advance(1020)
    p = packet(client_hello(), timestamp=1000)
    e.observe_packet(p)
    assert event_for(e, p).metadata['tls_status'] == 'TRUNCATED'
    assert e.metrics.tls_client_hello == 0
    assert e.metrics.tls_reassembly_bytes == 0
