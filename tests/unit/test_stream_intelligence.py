"""Deterministic operational evidence tests, without packet transmission."""

import json

import pytest

from sentinel_net.intelligence.config import IntelligenceConfig
from sentinel_net.intelligence.engine import StreamingIntelligence
from sentinel_net.models.types import DetectionEvent, FlowKey, ObservedFlow, ParsedPacket
from sentinel_net.sensor.metrics import SensorMetrics


def packet(t=1000, src="192.0.2.1", dst="192.0.2.2", port=443, protocol=6, flags=2):
    return ParsedPacket(
        timestamp=t,
        src_ip=src,
        dst_ip=dst,
        src_port=10000,
        dst_port=port,
        protocol=protocol,
        protocol_name="TCP" if protocol == 6 else "UDP",
        ip_version=4,
        ttl=64,
        ip_total_length=100,
        tcp_flags=flags,
        tcp_window=1024,
        tcp_seq=0,
        tcp_ack_num=0,
        payload_size=60,
        payload_entropy=0,
    )


def flow(p, forward=100, reverse=100):
    return ObservedFlow(
        flow_key=FlowKey(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol),
        direction="bidirectional",
        start_time=p.timestamp,
        end_time=p.timestamp,
        duration_sec=0,
        packet_count=2,
        byte_count=forward + reverse,
        payload_byte_count=0,
        forward_bytes=forward,
        reverse_bytes=reverse,
    )


def engine(**kwargs):
    defaults = {
        'window_sec': 60,
        'syn_rate': 0.1,
        'udp_rate': 0.1,
        'udp_flow_rate': 0.1,
        'flow_rate': 0.1,
        'packet_rate': 0.1,
        'unique_sources': 4,
        'entropy_bits': 1,
        'min_entropy_observations': 4,
        'port_fanout': 4,
        'host_fanout': 4,
        'directional_bytes': 1000,
    }
    defaults.update(kwargs)
    return StreamingIntelligence(IntelligenceConfig(**defaults), SensorMetrics())


def signals(e, p):
    return {s["signal_type"]: s for s in e.evidence_for_flow(flow(p))}


@pytest.mark.parametrize("protocol,expected", [(6, "SYN_RATE"), (17, "UDP_RATE")])
@pytest.mark.parametrize("count,positive", [(2, False), (10, True)])
def test_rate_controls(protocol, expected, count, positive):
    e = engine()
    for i in range(count):
        p = packet(1000 + i * 0.01, protocol=protocol)
        e.observe_packet(p, new_flow=True)
    observed = signals(e, p)
    assert (expected in observed) is positive
    assert ("FLOW_RATE" in observed) is positive
    assert ("DESTINATION_PACKET_RATE" in observed) is positive
    if protocol == 17:
        assert ("UDP_FLOW_RATE" in observed) is positive


def test_exact_packet_weighted_entropy_diversity_and_no_spoofing_claim():
    e = engine()
    for i in range(8):
        p = packet(1000 + i * 0.01, src=f"192.0.2.{i + 10}")
        e.observe_packet(p)
    ev = signals(e, p)
    assert ev["SOURCE_DISTRIBUTION_ENTROPY"]["observed_value"] == 3
    assert ev["UNIQUE_SOURCE_COUNT"]["observed_value"] == 8
    assert (
        "not evidence of spoofing"
        in ev["SOURCE_DISTRIBUTION_ENTROPY"]["supporting_context"]["definition"]
    )
    assert "confirmed" not in json.dumps(ev).lower()


def test_entropy_suppressed_on_membership_loss_counts_lower_bound():
    e = engine(max_members=4, max_keys=100)
    for i in range(8):
        p = packet(1000, src=f"192.0.2.{i + 10}")
        e.observe_packet(p)
    ev = signals(e, p)
    assert "SOURCE_DISTRIBUTION_ENTROPY" not in ev
    assert ev["UNIQUE_SOURCE_COUNT"]["supporting_context"]["count_is_lower_bound"]
    assert e.metrics.intelligence_member_overflows == 4


@pytest.mark.parametrize(
    "times,positive",
    [
        ([0, 8, 16, 24, 32, 40], True),
        ([0, 1, 4, 11, 25, 48], False),
        ([0, 8, 16], False),
        ([0, 0, 0, 0, 0, 0], False),
    ],
)
def test_periodicity_controls(times, positive):
    e = engine()
    for t in times:
        p = packet(1000 + t)
        e.observe_packet(p, True)
    ev = signals(e, p)
    assert ("C2_PERIODICITY_EVIDENCE" in ev) is positive
    if positive:
        context = ev["C2_PERIODICITY_EVIDENCE"]["supporting_context"]
        assert context["interval_count"] == 5 and context["interval_mean_sec"] == 8
        assert context["interval_variance_sec2"] == 0 and context["interval_stddev_sec"] == 0
        assert "scheduled polling" in context["alternative_explanations"]
        assert "BOTNET_C2_CONFIRMED" not in json.dumps(ev)


def test_multiple_destinations_do_not_imply_concentration_or_periodicity():
    e = engine()
    for i in range(6):
        for dst in ["192.0.2.2", "192.0.2.3"]:
            p = packet(1000 + i * 8, dst=dst)
            e.observe_packet(p, True)
    ev = signals(e, p)
    assert "DESTINATION_CONCENTRATION" not in ev
    assert "C2_PERIODICITY_EVIDENCE" not in ev


def test_concentration_has_distribution_and_session_counts():
    e = engine()
    for i in range(6):
        p = packet(1000 + i * 8)
        e.observe_packet(p, True)
    ev = signals(e, p)["DESTINATION_CONCENTRATION"]
    assert ev["observed_value"] == 1
    assert ev["supporting_context"]["destination_frequencies"] == {"192.0.2.2": 6}
    assert ev["supporting_context"]["distinct_destinations"] == 1


@pytest.mark.parametrize("kind", ["ports", "hosts"])
@pytest.mark.parametrize("gap,positive", [(1, True), (8, True), (70, False)])
def test_fanout_and_slow_scan_outside_horizon(kind, gap, positive):
    e = engine()
    for i in range(6):
        p = packet(
            1000 + i * gap,
            port=100 + i if kind == "ports" else 443,
            dst=f"192.0.2.{i + 10}" if kind == "hosts" else "192.0.2.2",
        )
        e.observe_packet(p, True)
    ev = signals(e, p)
    name = "PORT_FANOUT" if kind == "ports" else "HOST_FANOUT"
    assert (name in ev) is positive
    if positive:
        assert "proxies" in ev[name]["supporting_context"]["alternative_explanations"]


@pytest.mark.parametrize(
    "forward,reverse,count,positive",
    [(1000, 1000, 4, False), (1000, 1, 4, True), (1, 1000, 4, True), (10000000, 1, 1, False)],
)
def test_directional_asymmetry_and_legitimate_large_transfer(forward, reverse, count, positive):
    e = engine()
    for i in range(count):
        p = packet(1000 + i)
        e.observe_packet(p, True)
        ev = {v["signal_type"]: v for v in e.evidence_for_flow(flow(p, forward, reverse))}
    assert ("DIRECTIONAL_ASYMMETRY" in ev) is positive
    if positive:
        assert ev["DIRECTIONAL_ASYMMETRY"]["supporting_context"]["direction"] in (
            "initiator_to_responder",
            "responder_to_initiator",
        )
        assert (
            "initiator is not assumed outbound"
            in ev["DIRECTIONAL_ASYMMETRY"]["supporting_context"]["orientation"]
        )
        assert "exfiltration" not in ev["DIRECTIONAL_ASYMMETRY"]["interpretation"].lower()


def test_state_caps_expiry_late_data_and_clean_stop():
    e = engine(max_keys=9, max_members=4, max_sessions=6)
    for i in range(1000):
        p = packet(1000 + i * 0.001, src=f"192.0.2.{i % 200 + 1}", port=100 + i % 100)
        e.observe_packet(p, True)
        assert len(e.window.keys) <= 9
        for state in e.window.keys.values():
            assert len(state.buckets) <= 60 and len(state.sessions) <= 6
            assert all(len(m) <= 4 for m in state.members.values())
    assert e.metrics.intelligence_evictions > 0
    e.observe_packet(packet(2000))
    assert e.metrics.intelligence_expirations > 0
    before = len(e.window.keys)
    e.observe_packet(packet(1))
    assert len(e.window.keys) == before and e.metrics.intelligence_late_observations == 1
    e.close()
    assert e.metrics.intelligence_keys == 0 and not e.window.keys
    e.observe_packet(packet(3000))
    assert not e.window.keys


def test_session_samples_bounded_and_late_within_window_sorted():
    e = engine(max_sessions=6)
    for i in list(range(12)) + [5]:
        e.observe_packet(packet(1000 + i), True)
    _, state = e._state(("source", "192.0.2.1"))
    assert state.counts["sessions"] == 13
    key = e.session_key("192.0.2.1", "192.0.2.2", 6, 443)
    assert e.window.keys[key].sessions == [1006, 1007, 1008, 1009, 1010, 1011]
    assert e.metrics.intelligence_session_truncations == 7


@pytest.mark.parametrize("mode", ["informational", "enrich_ml", "behavioral_alert"])
def test_policy_provenance_and_no_ml_score_or_severity_mutation(mode):
    e = engine(policy_mode=mode)
    for i in range(10):
        p = packet(1000 + i * 0.1)
        e.observe_packet(p, True)
    f = flow(p)
    event = DetectionEvent(
        id="e",
        timestamp=p.timestamp,
        flow_key=f.flow_key,
        observed_flow=f,
        severity="info",
        metadata={
            "source": {"source_mode": "REPLAY"},
            "deployment_model": {
                "model_name": "frozen",
                "model_version": "1",
                "manifest_sha256": "a" * 64,
            },
        },
    )
    before = event.to_dict()
    e.enrich(event, f)
    after = event.to_dict()
    for k in [
        "severity",
        "classification_score",
        "anomaly_score",
        "model_name",
        "model_manifest_sha256",
        "source_mode",
    ]:
        assert before[k] == after[k]
    assert after["classification_score"] is None
    assert "stream_ddos" in after["detection_source"]
    assert after["behavioral_policy"]["behavioral_alert"] == (mode == "behavioral_alert")
    assert all(m["qualification"] == "possible" for m in after["behavioral_attack_context"])
    assert all(m["technique_id"] in ("T1498", "T1046") for m in after["behavioral_attack_context"])


def test_config_and_nonfinite_time_rejected():
    with pytest.raises(ValueError):
        IntelligenceConfig(window_sec=3600, bucket_sec=1)
    with pytest.raises(ValueError):
        IntelligenceConfig(max_sessions=6, min_sessions=10)
    with pytest.raises(ValueError):
        engine().observe_packet(packet(float("nan")))


def test_disabled_owner_keeps_no_state():
    e = engine(enabled=False)
    p = packet()
    e.observe_packet(p, True)
    assert not e.window.keys and not signals(e, p)


def test_bucket_boundaries_and_capture_time_ignore_runtime_clock(monkeypatch):
    import time
    a,b=engine(window_sec=10),engine(window_sec=10)
    for instance,date in [(a,1),(b,9999999999)]:
        monkeypatch.setattr(time,'time',lambda date=date:date)
        instance.observe_packet(packet(1000),True)
        instance.observe_packet(packet(1009),True)
        assert instance.window.interval['start']==1000
        assert sum(v.counts['packets'] for v in instance.window.keys[('destination','192.0.2.2')].buckets.values())==2
        instance.observe_packet(packet(1010),True)
        assert instance.window.interval['start']==1001
        assert sum(v.counts['packets'] for v in instance.window.keys[('destination','192.0.2.2')].buckets.values())==2
    assert signals(a,packet(1010))==signals(b,packet(1010))


def test_syn_ack_and_normal_repeated_service_are_not_syn_or_fanout():
    e=engine(syn_rate=.01)
    for i in range(10):
        p=packet(1000+i*.1,flags=18);e.observe_packet(p,True)
    result=signals(e,p)
    assert 'SYN_RATE' not in result and 'PORT_FANOUT' not in result and 'HOST_FANOUT' not in result


def test_legacy_and_disabled_evidence_missingness():
    p=packet();f=flow(p)
    event=DetectionEvent(id='legacy',timestamp=p.timestamp,flow_key=f.flow_key,observed_flow=f,severity='info')
    assert event.to_dict()['behavioral_evidence_status']=='not_recorded'
    e=engine(enabled=False);e.enrich(event,f)
    assert event.to_dict()['behavioral_evidence_status']=='disabled'


def test_all_buckets_fill_and_slide_without_growing_identity_history():
    e=engine(max_members=4)
    for t in range(1000,1250):
        for source in range(8):
            e.observe_packet(packet(t,src=f'192.0.2.{source+10}'))
        state=e.window.keys[('destination','192.0.2.2')]
        assert len(state.buckets)<=60
        assert len(state.members['sources'])<=4
        assert all(len(b.sources)<=4 for b in state.buckets.values())
    assert e.metrics.intelligence_buckets_per_key_peak==60
    assert e.metrics.intelligence_members_per_dimension_peak==4
    assert len(state.buckets)==60
    assert min(state.buckets)==1190 and max(state.buckets)==1249
    assert sum(b.counts['packets'] for b in state.buckets.values())==480
    assert 'SOURCE_DISTRIBUTION_ENTROPY' not in signals(e,packet(1249))
