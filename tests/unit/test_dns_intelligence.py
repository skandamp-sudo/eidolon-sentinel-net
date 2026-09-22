"""Deterministic synthetic passive DNS fixtures; no resolver/network calls."""

import math
import random
import struct
from types import SimpleNamespace

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, IPv6, IPv6ExtHdrFragment, Raw

from sentinel_net.dns.config import DNSConfig
from sentinel_net.dns.engine import DNSIntelligence, lexical
from sentinel_net.dns.parser import ParseIssue, name, observe_packet, parse_message
from sentinel_net.ingestion.parser import extract_raw_packet, parse_packet
from sentinel_net.models.types import FlowKey
from sentinel_net.sensor.metrics import SensorMetrics


def wire(qname="example.test", qtype=1, *, response=False, rcode=0, txid=1):
    return bytes(DNS(id=txid, qr=int(response), rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype)))


def packet(
    data=None,
    *,
    timestamp=1000,
    response=False,
    tcp=False,
    sport=42000,
    src="192.0.2.1",
    dst="198.51.100.53",
):
    data = wire(response=response) if data is None else data
    a, b = (53, sport) if response else (sport, 53)
    if response:
        src, dst = dst, src
    transport = TCP(sport=a, dport=b, flags="PA") if tcp else UDP(sport=a, dport=b)
    p = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src, dst=dst)
        / transport
        / Raw(data)
    )
    p.time = timestamp
    return parse_packet(extract_raw_packet(p))


def engine(**kwargs):
    return DNSIntelligence(DNSConfig(**kwargs), SensorMetrics())


def event_for(e, p, start=1000):
    event = SimpleNamespace(
        metadata={"behavioral_evidence": [{"untouched": True}]},
        severity="info",
        classification_score=0.4,
        anomaly_score=0.2,
    )
    flow = SimpleNamespace(
        flow_key=FlowKey(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol),
        start_time=start,
        end_time=p.timestamp,
    )
    e.enrich(event, flow)
    return event


def signals(e, p):
    return {s["signal_type"] for s in event_for(e, p).metadata["dns_evidence"]}


def random_label(i, length=48):
    rng = random.Random(i)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length))


@pytest.mark.parametrize("qtype", [1, 28, 16, 2, 5, 15, 12, 33, 65535])
def test_question_types_normalization(qtype):
    msg = parse_message(wire("ExAmPle.TeSt.", qtype))
    assert msg["status"] == "PARSED"
    assert msg["questions"][0]["name"] == "example.test"
    assert msg["questions"][0]["qtype"] == qtype
    assert msg["questions"][0]["qclass"] == 1


@pytest.mark.parametrize(
    "data,status",
    [
        (b"", "TRUNCATED"),
        (b"random bytes", "UNSUPPORTED"),
        (struct.pack("!6H", 1, 0, 5, 0, 0, 0), "UNSUPPORTED"),
        (struct.pack("!6H", 1, 0, 0, 65, 0, 0), "UNSUPPORTED"),
        (struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01", "MALFORMED"),
        (struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xff\xff\x00\x01\x00\x01", "MALFORMED"),
        (struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\x03ab", "TRUNCATED"),
        (struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\x40", "UNSUPPORTED"),
        (struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\x01\xff\x00\x00\x01\x00\x01", "UNSUPPORTED"),
        (wire(".".join(["a"] * 33)), "UNSUPPORTED"),
        (wire(".".join(["a" * 63] * 4)), "MALFORMED"),
        (wire() + b"junk", "MALFORMED"),
        (b"x" * 4097, "UNSUPPORTED"),
    ],
)
def test_malformed_safety(data, status):
    assert parse_message(data)["status"] == status


def test_pointer_depth_is_bounded():
    data = b"".join(struct.pack("!H", 0xC000 | (i + 1) * 2) for i in range(18)) + b"\x00"
    with pytest.raises(ParseIssue) as error:
        name(data, 0)
    assert error.value.status == "UNSUPPORTED"


def test_compressed_answer_and_dnssec_rdata_not_retained():
    data = wire(response=True)
    data = (
        data[:6]
        + b"\x00\x01"
        + data[8:]
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 46, 1, 30, 1024)
        + b"s" * 1024
    )
    result = parse_message(data)
    assert result["status"] == "PARSED" and result["response_record_types"] == [46]
    assert "ssss" not in str(result)
    assert parse_message(data[:-1])["status"] == "TRUNCATED"


def test_tc_flag_never_becomes_behavior():
    data = bytearray(wire())
    data[2] |= 2
    e = engine()
    p = packet(bytes(data))
    e.observe_packet(p)
    assert event_for(e, p).metadata["dns_status"] == "TRUNCATED"
    assert not signals(e, p) and not e.window.keys


@pytest.mark.parametrize(
    "prefix,status",
    [
        (b"\x00\x00", "MALFORMED"),
        (b"\x00", "TRUNCATED"),
        (b"\xff\xff", "UNSUPPORTED"),
        (b"\x00\x20short", "TRUNCATED"),
    ],
)
def test_tcp_bad_framing(prefix, status):
    assert observe_packet(packet(prefix, tcp=True))[0]["status"] == status


def test_tcp_complete_coalesced_split_and_message_cap():
    data = wire()
    framed = struct.pack("!H", len(data)) + data
    assert len(observe_packet(packet(framed * 4, tcp=True))) == 4
    assert observe_packet(packet(framed * 5, tcp=True))[0]["status"] == "UNSUPPORTED"
    assert observe_packet(packet(framed + framed[:5], tcp=True))[0]["status"] == "TRUNCATED"
    assert observe_packet(packet(b"", tcp=True)) == []


def test_ipv4_fragment_and_missing_raw_unavailable():
    p = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="198.51.100.53", flags="MF")
        / UDP(sport=42000, dport=53)
        / Raw(wire())
    )
    parsed = parse_packet(extract_raw_packet(p))
    assert observe_packet(parsed)[0]["status"] == "ENCRYPTED_OR_UNAVAILABLE"
    parsed.raw_packet = None
    assert observe_packet(parsed)[0]["status"] == "ENCRYPTED_OR_UNAVAILABLE"


def test_ipv6_udp_and_fragment():
    p = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=42000, dport=53)
        / Raw(wire())
    )
    assert observe_packet(parse_packet(extract_raw_packet(p)))[0]["status"] == "PARSED"
    p = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrFragment(m=1)
        / UDP(sport=42000, dport=53)
        / Raw(wire())
    )
    assert (
        observe_packet(parse_packet(extract_raw_packet(p)))[0]["status"]
        == "ENCRYPTED_OR_UNAVAILABLE"
    )


def test_encrypted_candidate_not_decoded():
    p = packet()
    p.dst_port = 853
    assert observe_packet(p)[0]["status"] == "ENCRYPTED_OR_UNAVAILABLE"
    p.dst_port = 443
    assert observe_packet(p) == []  # Cannot identify DoH from encrypted bytes.


def test_random_bytes_bounded_and_no_fabricated_evidence():
    rng = random.Random(77)
    e = engine()
    for i in range(120):
        data = rng.randbytes(i * 31)
        assert parse_message(data)["status"] != "PARSED"
        p = packet(data, timestamp=1000 + i / 100)
        e.observe_packet(p)
        assert not signals(e, p)
    assert not e.window.keys


def test_entropy_math_and_normalized_scope():
    stats = lexical("aabb.0011.test")
    text = "aabb0011test"
    expected = -sum(
        (text.count(c) / len(text)) * math.log2(text.count(c) / len(text)) for c in set(text)
    )
    assert stats["character_entropy"] == pytest.approx(expected)
    assert stats["qname_length"] == 14 and stats["longest_label"] == 4
    assert lexical("")["character_entropy"] == 0


@pytest.mark.parametrize("mode", ["query", "response", "paired", "reverse_pair"])
def test_one_way_and_pairing(mode):
    e = engine()
    query = packet(timestamp=1000)
    response = packet(wire(response=True, rcode=3), response=True, timestamp=1000.1)
    sequence = {
        "query": [query],
        "response": [response],
        "paired": [query, response],
        "reverse_pair": [response, query],
    }[mode]
    for p in sequence:
        e.observe_packet(p)
    # Out-of-order arrival still uses capture timestamps, not arrival time.
    p = max(sequence, key=lambda p: p.timestamp)
    record = next(iter(e.observations.values()))
    assert (
        record["visibility"]
        == {
            "query": "QUERY_ONLY",
            "response": "RESPONSE_ONLY",
            "paired": "PAIRED",
            "reverse_pair": "PAIRED",
        }[mode]
    )
    source = e.summary(("client", "192.0.2.1"))
    assert source["questions"] == (0 if mode == "response" else 1)
    assert source["nxdomain_ratio"] == (None if mode == "query" else 1)
    assert source["paired_responses"] == int("pair" in mode)


def test_transaction_reuse_port_question_and_expiry():
    e = engine()
    e.observe_packet(packet(wire("a.test")))
    e.observe_packet(packet(wire("b.test", response=True), response=True, timestamp=1001))
    assert next(reversed(e.observations.values()))["visibility"] == "RESPONSE_ONLY"
    e.observe_packet(
        packet(wire("a.test", response=True), response=True, sport=42001, timestamp=1002)
    )
    assert next(reversed(e.observations.values()))["visibility"] == "RESPONSE_ONLY"
    e.observe_packet(packet(wire("a.test", response=True), response=True, timestamp=1011))
    assert next(reversed(e.observations.values()))["visibility"] == "RESPONSE_ONLY"
    assert e.summary(("client", "192.0.2.1"))["paired_responses"] == 0


def test_diverse_dga_and_repeated_parent_tunnel_combinations():
    for kind in ("dga", "tunnel"):
        e = engine()
        for i in range(24):
            domain = f"{random_label(i)}.{('d' + str(i)) if kind == 'dga' else 'service'}.test"
            p = packet(wire(domain, txid=i), timestamp=1000 + i * 0.1)
            e.observe_packet(p)
        found = signals(e, p)
        assert ("DGA_LIKE_BEHAVIOR" if kind == "dga" else "DNS_TUNNELLING_LIKE_BEHAVIOR") in found
        assert (
            "DNS_TUNNELLING_LIKE_BEHAVIOR" if kind == "dga" else "DGA_LIKE_BEHAVIOR"
        ) not in found
        ev = event_for(e, p)
        assert ev.severity == "info" and ev.classification_score == 0.4
        assert ev.metadata["behavioral_evidence"] == [{"untouched": True}]
        assert all(
            "not attack probability" in s["confidence_semantics"]
            for s in ev.metadata["dns_evidence"]
        )


def test_single_long_entropy_label_not_dga_or_tunnel():
    e = engine()
    p = packet(wire(random_label(42) + ".cloud.test"))
    e.observe_packet(p)
    assert signals(e, p) == {"DNS_LEXICAL_ANOMALY", "DNS_HIGH_ENTROPY_LABEL"}


@pytest.mark.parametrize(
    "domain,qtype",
    [
        ("cdn-0123456789abcdef.assets.test", 1),
        ("very-long-but-meaningful-service-deployment-name.cluster.test", 28),
        ("_dmarc.mail.test", 16),
        ("_sip._tcp.service.test", 33),
        ("host-7f42ea892ca8.cloud.test", 1),
        ("telemetry.collector.test", 1),
        ("selector._domainkey.mail.test", 16),
    ],
)
def test_legitimate_repeated_controls(domain, qtype):
    e = engine()
    for i in range(30):
        p = packet(wire(domain, qtype, txid=i), timestamp=1000 + i)
        e.observe_packet(p)
    found = signals(e, p)
    assert not {"DGA_LIKE_BEHAVIOR", "DNS_TUNNELLING_LIKE_BEHAVIOR"} & found
    if qtype == 16:
        assert "DNS_QTYPE_PATTERN" in found  # Context only.
    summary = e.summary(("client", "192.0.2.1"))
    assert summary["repeated_questions_lower_bound"] == 29
    assert summary["nxdomain_ratio"] is None


def test_many_legitimate_subdomains_and_response_only_nxdomain():
    e = engine()
    for i in range(30):
        p = packet(wire(f"service-{i}.company.test", txid=i), timestamp=1000 + i * 0.1)
        e.observe_packet(p)
    assert "DNS_UNIQUE_DOMAIN_RATE" in signals(e, p)
    assert "DNS_TUNNELLING_LIKE_BEHAVIOR" not in signals(e, p)
    e = engine()
    for i in range(15):
        p = packet(
            wire(f"missing{i}.test", response=True, rcode=3, txid=i),
            response=True,
            timestamp=1000 + i * 0.1,
        )
        e.observe_packet(p)
    assert signals(e, p) == {"DNS_NXDOMAIN_PATTERN"}
    assert event_for(e, p).metadata["dns_observation"]["source_window"]["questions"] == 0


def test_bounds_expiry_late_and_cleanup():
    e = engine(max_keys=6, max_members=16, max_transactions=4, max_observations=3)
    for i in range(180):
        p = packet(
            wire(f"s{i}.parent.test", txid=i),
            timestamp=1000 + i * 0.4,
            sport=42000 + i,
            src=f"192.0.2.{i % 20 + 1}",
        )
        e.observe_packet(p)
        assert len(e.window.keys) <= 6 and len(e.transactions) <= 4 and len(e.observations) <= 3
        for state in e.window.keys.values():
            assert len(state.buckets) <= 60
            assert all(len(m) <= 16 for m in state.members.values())
    assert e.metrics.dns_evictions > 0
    e.observe_packet(packet(timestamp=1200))
    assert e.metrics.dns_expirations > 0
    before = len(e.observations)
    e.observe_packet(packet(timestamp=1000))
    assert e.metrics.dns_late_observations > 0 and len(e.observations) == before
    e.close()
    assert not e.window.keys and not e.transactions and not e.observations


def test_membership_censoring_and_window_boundary():
    e = engine(max_members=16)
    for i in range(50):
        p = packet(wire(f"name{i}.parent.test"), timestamp=1000 + i * 0.1)
        e.observe_packet(p)
    summary = e.summary(("client", "192.0.2.1"))
    assert summary["unique_domains"] == 16 and summary["identity_counts_are_lower_bounds"]
    e.observe_packet(packet(timestamp=1064))
    summary = e.summary(("client", "192.0.2.1"))
    assert summary["unique_domains"] == 1 and summary["questions"] == 1


def test_disabled_and_legacy_records():
    from sentinel_net.models.event_record import EventRecord

    e = engine(enabled=False)
    p = packet()
    e.observe_packet(p)
    assert event_for(e, p).metadata["dns_status"] == "disabled"
    assert not e.window.keys
    record = EventRecord(id="a", event_id="a", timestamp=1, created_at=1, severity="info")
    assert record.dns_status == "not_recorded" and record.dns_evidence == []


@pytest.mark.parametrize(
    "config",
    [
        {"entropy_bits": float("nan")},
        {"window_sec": 121},
        {"max_transactions": 0},
        {"max_members": 8},
    ],
)
def test_config_rejects_invalid_bounds(config):
    with pytest.raises(ValueError):
        DNSConfig(**config)


def test_dga_paired_failed_response_branch_and_missing_response_control():
    for respond in (False, True):
        e = engine()
        for i in range(24):
            domain = f"{random_label(i, 24)}.parent{i}.test"
            p = packet(wire(domain, txid=i), timestamp=1000 + i * 0.1)
            e.observe_packet(p)
            if respond:
                p = packet(
                    wire(domain, response=True, rcode=3, txid=i),
                    response=True,
                    timestamp=1000 + i * 0.1 + 0.01,
                )
                e.observe_packet(p)
        found = signals(e, p)
        assert ("DGA_LIKE_BEHAVIOR" in found) == respond
        assert e.summary(("client", "192.0.2.1"))["paired_responses"] == (24 if respond else 0)


def test_edns_extended_rcode_not_mislabeled_nxdomain():
    from scapy.layers.dns import DNSRROPT

    data = bytes(DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname="example.test"), ar=DNSRROPT(extrcode=1)))
    result = parse_message(data)
    assert result["status"] == "PARSED" and result["rcode"] == 19
    e = engine()
    p = packet(data, response=True)
    e.observe_packet(p)
    assert e.summary(("client", "192.0.2.1"))["nxdomain_count"] == 0


def test_old_flow_cannot_inherit_reused_tuple_observation():
    e = engine()
    p = packet(timestamp=1002)
    e.observe_packet(p)
    p.timestamp = 1000
    assert event_for(e, p).metadata["dns_status"] == "unavailable_or_not_observed"
    p.timestamp = 1005
    assert event_for(e, p, start=1003).metadata["dns_status"] == "unavailable_or_not_observed"


def test_late_arrival_does_not_replace_latest_message():
    e = engine()
    e.observe_packet(packet(wire("latest.test"), timestamp=1002))
    e.observe_packet(packet(wire("older.test"), timestamp=1001))
    assert next(iter(e.observations.values()))["message"]["questions"][0]["name"] == "latest.test"


def test_fully_sliding_membership_remains_bounded():
    e = engine(max_members=16)
    for i in range(160):
        for j in range(3):
            e.observe_packet(packet(wire(f"host{i}-{j}.parent.test"), timestamp=1000 + i))
        for state in e.window.keys.values():
            assert len(state.buckets) <= 60
            assert all(len(values) <= 16 for values in state.members.values())
    assert e.metrics.dns_member_overflows > 0
    assert e.metrics.dns_buckets_per_key_peak == 60


def test_no_resolver_or_transmission_calls(monkeypatch):
    import socket

    import scapy.all

    def forbidden(*args, **kwargs):
        raise AssertionError("active network operation")

    for attr in ("getaddrinfo", "gethostbyname", "gethostbyaddr"):
        monkeypatch.setattr(socket, attr, forbidden)
    for attr in ("send", "sendp", "sr", "sr1", "srp", "srp1"):
        monkeypatch.setattr(scapy.all, attr, forbidden)
    e = engine()
    p = packet(wire(random_label(42) + ".safe.test"))
    e.observe_packet(p)
    assert event_for(e, p).metadata["dns_status"] == "PARSED"


def test_parent_message_rate_and_multiquestion_response_counts():
    e = engine()
    questions = [DNSQR(qname="one.parent.test"), DNSQR(qname="two.parent.test")]
    query = packet(bytes(DNS(id=1, qd=questions)))
    response = packet(
        bytes(DNS(id=1, qr=1, rcode=3, qd=questions)), response=True, timestamp=1000.1
    )
    e.observe_packet(query)
    e.observe_packet(response)
    parent = e.summary(("parent", "192.0.2.1", "parent.test"))
    assert parent["questions"] == 2
    assert parent["query_messages"] == 1 and parent["query_rate"] == pytest.approx(1 / 60)
    assert parent["observed_responses"] == 1 and parent["nxdomain_ratio"] == 1
    assert parent["paired_responses"] == 1
    assert event_for(e, response).metadata["dns_observation"]["parent_window"] == parent


def test_transaction_key_includes_server_port_for_unusual_orientation():
    e = engine()
    # Correlator is conservative even for a syntactically valid QR/port mismatch.
    query = packet()
    response = packet(wire(response=True), response=True)
    message = parse_message(wire())
    e._advance(1000)
    assert e._correlate(query, message, "192.0.2.1", "198.51.100.53", 42000)[0] == "QUERY_ONLY"
    response.src_port = 1053
    assert (
        e._correlate(
            response, parse_message(wire(response=True)), "192.0.2.1", "198.51.100.53", 42000
        )[0]
        == "RESPONSE_ONLY"
    )
