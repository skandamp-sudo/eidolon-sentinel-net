"""
Deterministic human-readable rationale generator.

Generates structured natural-language explanations from Evidence[]
using template-based generation. Never claims "confirmed attack" —
uses "possible", "suspicious", "model classified" as appropriate.

Always appends a limitation disclaimer about encrypted payload.

SECURITY: No network I/O. No payload inspection. Pure string generation.
"""

from __future__ import annotations

from sentinel_net.explainability.evidence import Evidence, EvidenceCollection
from sentinel_net.explainability.attack_mapping import ATTACKMapping


class RationaleGenerator:
    """Generates deterministic human-readable rationale from evidence.

    Template structure:
        THREAT → ANOMALY SCORE → MODEL → EVIDENCE → LIMITATION
    """

    # Feature name → human-readable description
    _FEATURE_DESCRIPTIONS: dict[str, str] = {
        "duration_sec": "flow duration",
        "total_packets": "total packet count",
        "total_bytes": "total byte volume",
        "packets_per_sec": "packet rate",
        "bytes_per_sec": "byte rate",
        "forward_packets": "forward packet count",
        "reverse_packets": "reverse packet count",
        "fwd_rev_packet_ratio": "forward/reverse packet ratio",
        "fwd_rev_byte_ratio": "forward/reverse byte ratio",
        "pkt_size_mean": "average packet size",
        "pkt_size_std": "packet size variability",
        "pkt_size_min": "minimum packet size",
        "pkt_size_max": "maximum packet size",
        "iat_mean": "average inter-arrival time",
        "iat_std": "inter-arrival time variability",
        "iat_min": "minimum inter-arrival time",
        "iat_max": "maximum inter-arrival time",
        "syn_count": "SYN flag count",
        "syn_ratio": "SYN flag ratio",
        "ack_count": "ACK flag count",
        "fin_count": "FIN flag count",
        "rst_count": "RST flag count",
        "rst_ratio": "RST flag ratio",
        "psh_count": "PSH flag count",
        "payload_bytes_total": "total payload bytes",
        "forward_payload_bytes": "forward payload bytes",
        "reverse_payload_bytes": "reverse payload bytes",
        "payload_ratio": "payload ratio",
    }

    _LIMITATION = (
        "Classification is based on observable network metadata only. "
        "Encrypted payload contents are not inspected. "
        "This is a model classification, not a confirmed attack."
    )

    def generate(
        self,
        threat_label: str,
        anomaly_score: float,
        model_name: str,
        evidence: EvidenceCollection,
        attack_mappings: list[ATTACKMapping] | None = None,
        confidence: float | None = None,
    ) -> str:
        """Generate a structured rationale string.

        Args:
            threat_label: The predicted threat type.
            anomaly_score: Anomaly score [0, 1].
            model_name: Name of the classifier.
            evidence: Collection of evidence items.
            attack_mappings: Optional ATT&CK technique mappings.
            confidence: Optional model confidence score.

        Returns:
            Multi-line human-readable rationale string.
        """
        lines: list[str] = []

        # THREAT
        threat_display = self._format_threat(threat_label)
        lines.append(f"THREAT: {threat_display}")
        lines.append("")

        # ANOMALY SCORE
        lines.append(f"ANOMALY SCORE: {anomaly_score:.2f}")
        lines.append("")

        # MODEL
        model_line = f"MODEL: {model_name}"
        if confidence is not None:
            model_line += f" (confidence: {confidence:.2f})"
        lines.append(model_line)
        lines.append("")

        # EVIDENCE
        lines.append("EVIDENCE:")
        if evidence.explanation_available and evidence.items:
            top = evidence.top_k
            for e in top:
                desc = self._describe_evidence(e)
                lines.append(f"  - {desc}")
        elif not evidence.explanation_available:
            lines.append(f"  - Explanation unavailable: {evidence.unavailable_reason}")
        else:
            lines.append("  - No significant evidence identified")
        lines.append("")

        # ATT&CK MAPPING (if available)
        if attack_mappings:
            lines.append("POTENTIAL ATT&CK TECHNIQUES:")
            for mapping in attack_mappings:
                lines.append(
                    f"  - {mapping.technique_id} {mapping.technique_name} "
                    f"({mapping.tactic}) — {mapping.qualification}"
                )
            lines.append("")

        # LIMITATION
        lines.append(f"LIMITATION: {self._LIMITATION}")

        return "\n".join(lines)

    def _format_threat(self, threat_label: str) -> str:
        """Format threat label for display."""
        display_map = {
            "benign": "Benign Traffic",
            "ddos": "Possible DDoS Attack",
            "c2": "Possible C2 Beaconing",
            "reconnaissance": "Possible Reconnaissance",
            "scan": "Possible Network Scanning",
            "exfiltration": "Possible Data Exfiltration",
            "brute_force": "Possible Brute Force",
            "dns_tunneling": "Possible DNS Tunneling",
            "unknown": "Unclassified Traffic",
            "other": "Suspicious Activity",
        }
        return display_map.get(threat_label, f"Model classified: {threat_label}")

    def _describe_evidence(self, e: Evidence) -> str:
        """Create human-readable description of a single evidence item."""
        feat_desc = self._FEATURE_DESCRIPTIONS.get(e.feature_name, e.feature_name)

        if e.evidence_type == "model":
            direction_word = "elevated" if e.direction == "increase" else "reduced"
            desc = f"{direction_word} {feat_desc} (contribution: {e.contribution:.3f})"
        elif e.evidence_type == "statistical":
            direction_word = "above" if e.direction == "increase" else "below"
            desc = f"{feat_desc} significantly {direction_word} baseline"
            if e.reference_value is not None:
                desc += f" (observed: {e.observed_value:.2f}, baseline: {e.reference_value:.2f})"
            desc += f" (z-score: {e.contribution:.1f})"
        else:  # heuristic
            desc = f"{feat_desc}: {e.observed_value:.2f}"

        return desc
