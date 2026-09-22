"""One bounded TLS/QUIC owner; protocol context never mutates scientific scores."""

import math
import time
from collections import OrderedDict, deque
from copy import deepcopy
from dataclasses import dataclass, field
from itertools import pairwise

from sentinel_net.encrypted.quic import parse_quic
from sentinel_net.encrypted.reassembly import Direction
from sentinel_net.encrypted.wire import Invalid, transport_payload


def key_for(src, dst, sport, dport, protocol):
    return (tuple(sorted(((src, sport or 0), (dst, dport or 0)))), protocol)


@dataclass
class Connection:
    started: float
    last: float
    directions: dict = field(default_factory=dict)
    quic: dict = field(default_factory=dict)
    samples: deque = field(default_factory=deque)
    packets: int = 0
    syn: tuple | None = None
    closed: bool = False


class EncryptedIntelligence:
    def __init__(self, config, metrics):
        self.config, self.metrics = config, metrics
        self.connections = OrderedDict()
        self.watermark = float("-inf")

    def _gauges(self):
        self.metrics.set_gauge("encrypted_metadata_state", len(self.connections))
        self.metrics.observe_peak("encrypted_metadata_state_peak", len(self.connections))
        allocated = sum(
            len(d.data) + len(d.present)
            for c in self.connections.values()
            for d in c.directions.values()
        )
        self.metrics.set_gauge("tls_reassembly_bytes", allocated)
        self.metrics.observe_peak("tls_reassembly_bytes_peak", allocated)

    def advance(self, timestamp):
        if not math.isfinite(timestamp):
            raise ValueError("Nonfinite capture time")
        self.watermark = max(self.watermark, timestamp)
        for key, c in list(self.connections.items()):
            for d in c.directions.values():
                if self.watermark - d.started > self.config.handshake_ttl_sec and d.expire():
                    self.metrics.increment("tls_truncated")
            if self.watermark - c.last > self.config.connection_ttl_sec:
                del self.connections[key]
                self.metrics.increment("encrypted_metadata_expirations")
        self._gauges()

    def observe_packet(self, p):
        if not self.config.enabled:
            return
        started = time.monotonic()
        self.advance(p.timestamp)
        ports = (p.src_port, p.dst_port)
        family = (
            "tls"
            if p.protocol == 6 and any(v in self.config.tls_ports for v in ports)
            else "quic"
            if p.protocol == 17 and any(v in self.config.quic_ports for v in ports)
            else None
        )
        if not family:
            return
        try:
            self._observe(p, family)
        finally:
            self.metrics.observe_latency(
                family + "_metadata_processing", time.monotonic() - started
            )

    def _observe(self, p, family):
        cfg = self.config
        if p.timestamp < self.watermark - cfg.connection_ttl_sec:
            self.metrics.increment("encrypted_metadata_late_observations")
            return
        key = key_for(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol)
        direction = (p.src_ip, p.src_port or 0)
        syn = (
            (direction, p.tcp_seq)
            if family == "tls" and (p.tcp_flags or 0) & 2 and not (p.tcp_flags or 0) & 16
            else None
        )
        c = self.connections.get(key)
        if c and syn and (c.syn != syn or c.closed) and p.timestamp >= c.last:
            del self.connections[key]
            c = None
        if c is None:
            if len(self.connections) >= cfg.max_connections:
                _, old = self.connections.popitem(last=False)
                self.metrics.increment("encrypted_metadata_evictions")
                if old.directions:
                    self.metrics.increment("tls_reassembly_evictions")
            c = Connection(p.timestamp, p.timestamp, samples=deque(maxlen=cfg.max_samples), syn=syn)
            self.connections[key] = c
        self.connections.move_to_end(key)
        c.last = max(c.last, p.timestamp)
        c.started = min(c.started, p.timestamp)
        if family == "tls" and (p.tcp_flags or 0) & 5:
            c.closed = True
        c.packets += 1
        c.samples.append((p.timestamp, p.ip_total_length, direction))
        self.metrics.observe_peak("encrypted_metadata_samples_per_connection_peak", len(c.samples))
        try:
            payload = transport_payload(p, cfg.max_direction_bytes if family == "tls" else 65535)
        except Invalid as exc:
            result = {"status": exc.status, "reason": exc.reason}
            if family == "quic":
                c.quic[direction] = {"timestamp": p.timestamp, **result}
            else:
                d = c.directions.setdefault(direction, Direction(p.timestamp))
                d.result = result
                d.release()
            self.metrics.increment(
                family + "_truncated"
                if exc.status == "TRUNCATED"
                else family + "_malformed"
                if exc.status == "MALFORMED"
                else family + "_unavailable"
            )
            self._gauges()
            return
        if family == "quic":
            self.metrics.increment("quic_packets_observed")
            result = parse_quic(payload)
            if result.get("long_header"):
                self.metrics.increment("quic_long_headers")
            if result.get("packet_type") == "UNKNOWN_VERSION":
                self.metrics.increment("quic_unknown_versions")
            if result["status"] in ("MALFORMED", "TRUNCATED"):
                self.metrics.increment("quic_" + result["status"].lower())
            old = c.quic.get(direction)
            if not old or old.get("last_packet_timestamp", old["timestamp"]) <= p.timestamp:
                if old and old.get("long_header") and not result.get("long_header"):
                    old["last_packet_timestamp"] = p.timestamp
                    old["latest_packet_status"] = result["status"]
                    old["latest_packet_reason"] = result.get("reason")
                else:
                    c.quic[direction] = {"timestamp": p.timestamp, **result}
        elif payload:
            d = c.directions.setdefault(direction, Direction(p.timestamp))
            if self.watermark - d.started > cfg.handshake_ttl_sec and d.expire():
                self.metrics.increment("tls_truncated")
            previous = d.result["status"]
            seq = ((p.tcp_seq or 0) + (1 if (p.tcp_flags or 0) & 2 else 0)) % (1 << 32)
            allocated = sum(
                len(x.data) + len(x.present)
                for owner in self.connections.values()
                for x in owner.directions.values()
            )
            self.metrics.observe_peak(
                "tls_reassembly_bytes_peak",
                allocated
                + (
                    2 * cfg.max_direction_bytes
                    if not d.data and d.result["status"] == "INCOMPLETE"
                    else 0
                ),
            )
            result = d.feed(seq, payload, cfg.max_direction_bytes)
            count = result.get("record_count", 0)
            if count > d.records_counted:
                self.metrics.increment("tls_records_observed", count - d.records_counted)
                d.records_counted = count
            if previous == "INCOMPLETE" and result["status"] != "INCOMPLETE":
                if result["status"] == "COMPLETE":
                    self.metrics.increment(
                        "tls_client_hello"
                        if result["hello"]["handshake_type"] == 1
                        else "tls_server_hello"
                    )
                elif result["status"] in ("MALFORMED", "TRUNCATED"):
                    self.metrics.increment("tls_" + result["status"].lower())
                elif result["status"] != "ENCRYPTED_APPLICATION_DATA":
                    self.metrics.increment("tls_unavailable")
        self._gauges()

    @staticmethod
    def timing(c):
        samples = sorted(c.samples, key=lambda v: v[0])
        sizes = [v[1] for v in samples]
        gaps = [b[0] - a[0] for a, b in pairwise(samples)]
        return {
            "sample_count": len(samples),
            "total_observed_packets": c.packets,
            "samples_capped": c.packets > len(samples),
            "scope": "latest bounded transport packet samples, including retransmissions; sorted by capture time",
            "packet_size_min": min(sizes) if sizes else None,
            "packet_size_max": max(sizes) if sizes else None,
            "packet_size_mean": sum(sizes) / len(sizes) if sizes else None,
            "inter_packet_mean_sec": sum(gaps) / len(gaps) if gaps else None,
            "inter_packet_min_sec": min(gaps) if gaps else None,
            "inter_packet_max_sec": max(gaps) if gaps else None,
            "direction_count": len({v[2] for v in samples}),
            "clock": "capture_event_time",
        }

    def enrich(self, event, flow):
        for family in ("tls", "quic"):
            event.metadata[family + "_status"] = (
                "disabled" if not self.config.enabled else "UNAVAILABLE"
            )
            event.metadata[family + "_evidence"] = []
        if not self.config.enabled:
            return
        self.advance(flow.end_time)
        f = flow.flow_key
        c = self.connections.get(key_for(f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol))
        if not c or c.last < flow.start_time or c.started > flow.end_time:
            return
        # A reused tuple or observations outside the finalized canonical flow are not attributed to it.
        if c.started < flow.start_time or c.last > flow.end_time:
            return
        window = {
            "start": c.started,
            "end": c.last,
            "duration_sec": max(0, c.last - c.started),
            "clock": "capture_event_time",
            "alignment": "retained connection observation interval; not a negotiated session",
        }

        def emit(family, kind, value, unit, context, detector=None):
            event.metadata[family + "_evidence"].append(
                {
                    "signal_type": kind,
                    "detector": detector or family + "_metadata",
                    "observed_value": value,
                    "unit": unit,
                    "reference_threshold": None,
                    "comparison": "observed",
                    "observation_window": window,
                    "supporting_context": context,
                    "interpretation": "Contextual metadata; legitimate browsers, services and libraries share these values.",
                    "confidence_semantics": "No malware verdict, attribution or attack probability.",
                }
            )

        timing = self.timing(c)
        if f.protocol == 6:
            observations = []
            roles = set()
            for direction, d in sorted(c.directions.items()):
                item = {
                    "source_ip": direction[0],
                    "source_port": direction[1],
                    "started_at": d.started,
                    **deepcopy(d.result),
                    "retransmitted_bytes_while_buffering": d.retransmitted_bytes,
                    "out_of_order_segments": d.out_of_order_segments,
                }
                observations.append(item)
                if d.result["status"] == "COMPLETE":
                    h = d.result["hello"]
                    role = "CLIENT" if h["handshake_type"] == 1 else "SERVER"
                    roles.add(role)
                    emit("tls", "TLS_" + role + "_HELLO_OBSERVED", 1, "hello", {"role": role})
                    emit(
                        "tls",
                        "TLS_VERSION_CONTEXT",
                        h["legacy_version"],
                        "wire legacy version",
                        {
                            "supported_versions": h["supported_versions"],
                            "selected_version": h["selected_version"],
                            "note": "TLS 1.3 uses a legacy hello version; offered values do not establish negotiation.",
                        },
                    )
                    emit(
                        "tls",
                        "TLS_CIPHER_PROFILE",
                        len(h["cipher_suites"]),
                        "observed cipher suites",
                        {"cipher_suites": h["cipher_suites"]},
                    )
                    emit(
                        "tls",
                        "TLS_EXTENSION_PROFILE",
                        len(h["extension_ids"]),
                        "observed extensions",
                        {"extension_ids": h["extension_ids"]},
                    )
                    emit("tls", "TLS_FINGERPRINT", 1, "metadata identifier", h["fingerprint"])
                    if h["sni"]:
                        emit(
                            "tls",
                            "TLS_SNI_CONTEXT",
                            1,
                            "visible name",
                            {"sni": h["sni"], "visibility": h["sni_status"]},
                        )
                    if h["alpn"]:
                        emit(
                            "tls",
                            "TLS_ALPN_CONTEXT",
                            len(h["alpn"]),
                            "visible protocol identifiers",
                            {"alpn": h["alpn"]},
                        )
            statuses = [o["status"] for o in observations]
            status = (
                "COMPLETE"
                if roles
                else next(
                    (
                        s
                        for s in (
                            "MALFORMED",
                            "TRUNCATED",
                            "ENCRYPTED_APPLICATION_DATA",
                            "UNSUPPORTED",
                            "INCOMPLETE",
                        )
                        if s in statuses
                    ),
                    "UNAVAILABLE",
                )
            )
            event.metadata["tls_status"] = status
            event.metadata["tls_observation"] = {
                "visibility": "BOTH"
                if len(roles) == 2
                else next(iter(roles)) + "_ONLY"
                if roles
                else "INCOMPLETE",
                "directions": observations,
                "timing": timing,
                "observation_window": window,
                "application_payload": "NOT_DECRYPTED_OR_INSPECTED",
                "ja4_status": "NOT_IMPLEMENTED",
                "limits": "First supported hello per direction only; missing peer hello is unobserved, not failure. ECH outer metadata cannot reveal the inner name.",
            }
            if roles or status == "ENCRYPTED_APPLICATION_DATA":
                emit(
                    "tls",
                    "ENCRYPTED_SESSION_PACKET_TIMING",
                    timing["sample_count"],
                    "retained transport samples",
                    timing,
                    "encrypted_session_behavior",
                )
        elif f.protocol == 17:
            observations = [
                {"source_ip": d[0], "source_port": d[1], **deepcopy(v)}
                for d, v in sorted(c.quic.items())
            ]
            event.metadata["quic_status"] = (
                "COMPLETE"
                if any(o["status"] == "COMPLETE" for o in observations)
                else observations[-1]["status"]
                if observations
                else "UNAVAILABLE"
            )
            event.metadata["quic_observation"] = {
                "visibility": "BOTH_DIRECTIONS_OBSERVED"
                if len(c.quic) == 2
                else "ONE_DIRECTION_OBSERVED",
                "directions": observations,
                "timing": timing,
                "observation_window": window,
                "encrypted_payload": "NOT_DECRYPTED_OR_INSPECTED",
                "limits": "Only first long-header packet per datagram; no migration/session correlation or integrity authentication.",
            }
            for o in observations:
                if o.get("long_header"):
                    emit("quic", "QUIC_LONG_HEADER_OBSERVED", 1, "visible header", o)
                    emit(
                        "quic",
                        "QUIC_VERSION_CONTEXT",
                        o["version"],
                        "wire version",
                        {"version_hex": o["version_hex"], "packet_type": o["packet_type"]},
                    )
                    emit(
                        "quic",
                        "QUIC_CONNECTION_ID_CONTEXT",
                        o["destination_cid_length"],
                        "CID bytes",
                        {
                            "destination_sha256": o["destination_cid_sha256"],
                            "source_sha256": o["source_cid_sha256"],
                            "source_length": o["source_cid_length"],
                        },
                    )
                    if o["version"] == 0:
                        emit(
                            "quic",
                            "QUIC_VERSION_NEGOTIATION",
                            len(o["supported_versions"]),
                            "advertised versions",
                            {"versions": o["supported_versions"], "authenticated": False},
                        )
            if event.metadata["quic_evidence"]:
                emit(
                    "quic",
                    "QUIC_PACKET_SIZE_PATTERN",
                    timing["sample_count"],
                    "retained transport samples",
                    timing,
                    "encrypted_session_behavior",
                )
        for family in ("tls", "quic"):
            self.metrics.increment(
                family + "_evidence_generated", len(event.metadata[family + "_evidence"])
            )

    def close(self):
        self.connections.clear()
        self._gauges()
