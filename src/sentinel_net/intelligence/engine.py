"""One passive cross-flow evidence owner. No network I/O or ML mutations."""

import math
import statistics
from itertools import pairwise

from sentinel_net.explainability.attack_mapping import ATTACKMapper
from sentinel_net.intelligence.policy import EvidencePolicy
from sentinel_net.intelligence.window import BoundedWindow, Bucket


class StreamingIntelligence:
    def __init__(self, config, metrics):
        self.config = config
        self.metrics = metrics
        self.window = BoundedWindow(config, metrics)
        self.policy = EvidencePolicy(config)
        self.closed = False

    @staticmethod
    def session_key(src, dst, protocol, port):
        return ("session", src, dst, protocol, port)

    def observe_packet(self, packet, new_flow=False):
        if self.closed or not self.config.enabled:
            return
        tick = self.window.advance(packet.timestamp)
        if tick is None:
            return
        dest, db = self.window.get(("destination", packet.dst_ip), tick)
        db.counts["packets"] += 1
        db.counts["syn"] += int(
            packet.protocol == 6
            and bool((packet.tcp_flags or 0) & 2)
            and not bool((packet.tcp_flags or 0) & 16)
        )
        db.counts["udp"] += int(packet.protocol == 17)
        self.window.member(dest, db, "sources", packet.src_ip)
        if new_flow:
            db.counts["flows"] += 1
            db.counts["udp_flows"] += int(packet.protocol == 17)
            src, sb = self.window.get(("source", packet.src_ip), tick)
            sb.counts["sessions"] += 1
            self.window.member(src, sb, "destinations", packet.dst_ip)
            if packet.dst_port is not None:
                self.window.member(src, sb, "ports", packet.dst_port)
            key = self.session_key(packet.src_ip, packet.dst_ip, packet.protocol, packet.dst_port)
            session, _ = self.window.get(key, tick)
            session.sessions.append(packet.timestamp)
            session.sessions.sort()
            if len(session.sessions) > self.config.max_sessions:
                del session.sessions[0]
                session.session_truncated = True
                self.metrics.increment("intelligence_session_truncations")
            self.metrics.observe_peak("intelligence_session_samples_peak", len(session.sessions))

    def _state(self, key):
        state = self.window.keys.get(key)
        return state, state.totals() if state else Bucket()

    def evidence_for_flow(self, flow):
        if self.closed or not self.config.enabled or self.window.tick is None:
            return []
        key = flow.flow_key
        # A completed flow is attributed to its recorded end-time bucket. Old
        # finalizations do not move the watermark backwards or invent arrivals.
        tick = self.window.advance(flow.end_time)
        if tick is None:
            return []
        pair_key = self.session_key(key.src_ip, key.dst_ip, key.protocol, key.dst_port)
        pair, bucket = self.window.get(pair_key, tick)
        forward, reverse = flow.forward_bytes, flow.reverse_bytes
        bucket.counts["forward_bytes"] += forward
        bucket.counts["reverse_bytes"] += reverse
        if max(forward, reverse) / max(min(forward, reverse), 1) >= self.config.directional_ratio:
            bucket.counts["heavy_forward" if forward >= reverse else "heavy_reverse"] += 1
        _, dest = self._state(("destination", key.dst_ip))
        _, source = self._state(("source", key.src_ip))
        pair, pair_totals = self._state(pair_key)
        cfg = self.config
        evidence = []
        common = {
            "scope_source": key.src_ip,
            "scope_destination": key.dst_ip,
            "key_evictions_total": self.metrics.intelligence_evictions,
            "membership_overflow_observations": dest.overflow + source.overflow,
            "window_observation_semantics": "Retained event-time observations; key eviction can reduce coverage.",
        }

        def emit(signal, value, threshold, unit, source_name, context, comparison=">="):
            evidence.append(
                {
                    "signal_type": signal,
                    "observed_value": value,
                    "unit": unit,
                    "reference_threshold": threshold,
                    "comparison": comparison,
                    "threshold_semantics": "operational_policy_threshold",
                    "observation_window": dict(self.window.interval),
                    "supporting_context": dict(common, **context),
                    "detector": source_name,
                    "detector_version": "sih-f3/1.0",
                    "confidence_semantics": "No probability or confidence is assigned.",
                    "interpretation": "Passive behavioral evidence; legitimate activity remains possible.",
                }
            )

        for signal, counter, threshold in [
            ("SYN_RATE", "syn", cfg.syn_rate),
            ("UDP_RATE", "udp", cfg.udp_rate),
            ("UDP_FLOW_RATE", "udp_flows", cfg.udp_flow_rate),
            ("FLOW_RATE", "flows", cfg.flow_rate),
            ("DESTINATION_PACKET_RATE", "packets", cfg.packet_rate),
        ]:
            value = dest.counts[counter] / cfg.window_sec
            if value >= threshold:
                emit(
                    signal,
                    value,
                    threshold,
                    "observations/s",
                    "stream_ddos",
                    {"observations": dest.counts[counter], "denominator_sec": cfg.window_sec},
                )
        sources = len(dest.sources)
        if sources >= cfg.unique_sources:
            emit(
                "UNIQUE_SOURCE_COUNT",
                sources,
                cfg.unique_sources,
                "sources",
                "stream_ddos",
                {
                    "observations": dest.counts["packets"],
                    "count_is_lower_bound": bool(dest.overflow),
                },
            )
        if dest.counts["packets"] >= cfg.min_entropy_observations and not dest.overflow:
            total = sum(dest.sources.values())
            entropy = (
                -sum((n / total) * math.log2(n / total) for n in dest.sources.values())
                if total
                else 0
            )
            if entropy >= cfg.entropy_bits:
                emit(
                    "SOURCE_DISTRIBUTION_ENTROPY",
                    entropy,
                    cfg.entropy_bits,
                    "bits",
                    "stream_ddos",
                    {
                        "observations": total,
                        "unique_sources": sources,
                        "definition": "Shannon H=-sum(p_i*log2(p_i)), packet-weighted source-address distribution; not evidence of spoofing.",
                    },
                )
        sessions = source.counts["sessions"]
        concentration = source.destinations.get(key.dst_ip, 0) / sessions if sessions else 0
        distribution = dict(sorted(source.destinations.items()))
        if sessions >= cfg.min_sessions and concentration >= cfg.concentration_ratio:
            emit(
                "DESTINATION_CONCENTRATION",
                concentration,
                cfg.concentration_ratio,
                "fraction of observed sessions",
                "stream_c2",
                {
                    "sessions": sessions,
                    "distinct_destinations": len(distribution),
                    "destination_frequencies": distribution,
                    "ratio_is_lower_bound": bool(source.overflow),
                },
            )
        times = pair.sessions if pair else []
        if len(times) >= cfg.min_sessions:
            intervals = [b - a for a, b in pairwise(times)]
            mean = statistics.mean(intervals)
            variance = statistics.pvariance(intervals)
            stddev = math.sqrt(variance)
            cv = stddev / mean if mean > 0 else None
            if (
                cv is not None
                and cv <= cfg.periodicity_cv
                and concentration >= cfg.concentration_ratio
            ):
                emit(
                    "C2_PERIODICITY_EVIDENCE",
                    cv,
                    cfg.periodicity_cv,
                    "coefficient of variation",
                    "stream_c2",
                    {
                        "sessions": len(times),
                        "interval_count": len(intervals),
                        "intervals_sec": intervals,
                        "interval_mean_sec": mean,
                        "interval_variance_sec2": variance,
                        "interval_stddev_sec": stddev,
                        "destination_concentration": concentration,
                        "session_history_truncated": pair.session_truncated,
                        "session_definition": "canonical flow creations, including capacity/idle segmentation; not verified application sessions",
                        "alternative_explanations": [
                            "scheduled polling",
                            "monitoring",
                            "application keepalives",
                        ],
                    },
                    "<=",
                )
        for signal, values, threshold in [
            ("PORT_FANOUT", source.ports, cfg.port_fanout),
            ("HOST_FANOUT", source.destinations, cfg.host_fanout),
        ]:
            if len(values) >= threshold:
                emit(
                    signal,
                    len(values),
                    threshold,
                    "distinct observed values",
                    "stream_recon",
                    {
                        "sessions": sessions,
                        "flow_rate": sessions / cfg.window_sec,
                        "count_is_lower_bound": bool(source.overflow),
                        "alternative_explanations": [
                            "monitoring",
                            "service discovery",
                            "proxies",
                            "distributed applications",
                        ],
                    },
                )
        for direction, numerator, denominator, heavy in [
            ("initiator_to_responder", "forward_bytes", "reverse_bytes", "heavy_forward"),
            ("responder_to_initiator", "reverse_bytes", "forward_bytes", "heavy_reverse"),
        ]:
            dominant = pair_totals.counts[numerator]
            opposing = pair_totals.counts[denominator]
            ratio = dominant / max(opposing, 1)
            if (
                dominant >= cfg.directional_bytes
                and ratio >= cfg.directional_ratio
                and pair_totals.counts[heavy] >= cfg.min_directional_flows
            ):
                emit(
                    "DIRECTIONAL_ASYMMETRY",
                    ratio,
                    cfg.directional_ratio,
                    "bytes / max(opposing bytes, 1)",
                    "stream_asymmetry",
                    {
                        "direction": direction,
                        "forward_bytes": pair_totals.counts["forward_bytes"],
                        "reverse_bytes": pair_totals.counts["reverse_bytes"],
                        "volume_threshold_bytes": cfg.directional_bytes,
                        "directional_flows": pair_totals.counts[heavy],
                        "minimum_directional_flows": cfg.min_directional_flows,
                        "orientation": "Network boundary not configured; initiator is not assumed outbound.",
                        "volume_attribution": "Completed-flow totals attributed at capture end; a flow may span beyond the window.",
                        "alternative_explanations": ["backups", "uploads", "content transfer"],
                    },
                )
        return evidence

    def enrich(self, event, flow):
        evidence = self.evidence_for_flow(flow)
        event.metadata["behavioral_evidence_status"] = (
            "available" if self.config.enabled else "disabled"
        )
        event.metadata["behavioral_evidence"] = evidence
        event.metadata["behavioral_policy"] = self.policy.decide(evidence)
        # Reuse only applicable existing mappings. Periodicity alone establishes
        # neither an application-layer protocol nor encryption/C2 channels.
        allowed = {"stream_ddos": ("ddos", "T1498"), "stream_recon": ("reconnaissance", "T1046")}
        mappings = []
        for detector in sorted({e["detector"] for e in evidence}):
            if detector in allowed:
                label, technique = allowed[detector]
                for mapping in ATTACKMapper().map(label):
                    if mapping.technique_id == technique:
                        item = mapping.to_dict()
                        item["rationale"] = (
                            "Context only: observed streaming behavior can also be legitimate; no intent or attribution is established."
                        )
                        item["source"] = detector
                        mappings.append(item)
        event.metadata["behavioral_attack_context"] = mappings
        self.metrics.increment("intelligence_evidence_generated", len(evidence))

    def close(self):
        self.window.close()
        self.closed = True
