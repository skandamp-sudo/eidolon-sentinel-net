"""
MITRE ATT&CK mapping layer.

Maps threat classifications to potential ATT&CK techniques with
explicit qualification. Does NOT infer confirmed techniques solely
from a classifier label.

Clearly distinguishes:
- MODEL CLASSIFICATION (what the ML model predicted)
- ATT&CK MAPPING (which techniques are potentially applicable)

SECURITY: No network I/O. Static mapping table. No external API calls.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ATTACKMapping:
    """A potential MITRE ATT&CK technique mapping.

    Attributes:
        technique_id: ATT&CK technique ID (e.g., "T1071").
        technique_name: Human-readable name (e.g., "Application Layer Protocol").
        tactic: ATT&CK tactic (e.g., "Command and Control").
        rationale: Why this mapping is suggested.
        applicability: How applicable this technique is given the evidence.
        qualification: Certainty level — "possible", "likely", "observed indicators consistent with".
    """

    technique_id: str
    technique_name: str
    tactic: str
    rationale: str
    applicability: str  # "high" | "medium" | "low"
    qualification: str  # "possible" | "likely" | "observed indicators consistent with"

    def __post_init__(self) -> None:
        if self.qualification not in (
            "possible",
            "likely",
            "observed indicators consistent with",
        ):
            raise ValueError(
                f"qualification must be 'possible', 'likely', or "
                f"'observed indicators consistent with', got '{self.qualification}'"
            )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ATTACKMapping:
        return cls(**d)


# ── Static mapping table ───────────────────────────────────────────────
# Maps canonical ThreatType values to potential ATT&CK techniques.
# This is a research-grade starting point, not an exhaustive mapping.

_THREAT_TO_ATTACK: dict[str, list[dict[str, str]]] = {
    "ddos": [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "rationale": "High packet rate or volume directed at target",
            "applicability": "high",
        },
        {
            "technique_id": "T1499",
            "technique_name": "Endpoint Denial of Service",
            "tactic": "Impact",
            "rationale": "Connection flooding or resource exhaustion patterns",
            "applicability": "medium",
        },
    ],
    "c2": [
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "rationale": "Periodic beaconing or structured communication patterns",
            "applicability": "high",
        },
        {
            "technique_id": "T1573",
            "technique_name": "Encrypted Channel",
            "tactic": "Command and Control",
            "rationale": "Encrypted traffic with beaconing characteristics",
            "applicability": "medium",
        },
    ],
    "reconnaissance": [
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery",
            "rationale": "Systematic connection attempts across ports or hosts",
            "applicability": "high",
        },
        {
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "tactic": "Reconnaissance",
            "rationale": "Scanning patterns detected in flow metadata",
            "applicability": "medium",
        },
    ],
    "scan": [
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery",
            "rationale": "Port or service enumeration patterns",
            "applicability": "high",
        },
    ],
    "exfiltration": [
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "rationale": "Unusual outbound data volume or transfer patterns",
            "applicability": "medium",
        },
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "rationale": "Data transfer via non-standard protocols",
            "applicability": "low",
        },
    ],
    "brute_force": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "rationale": "Repeated authentication attempts with varying credentials",
            "applicability": "high",
        },
    ],
    "dns_tunneling": [
        {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control",
            "rationale": "DNS traffic with unusual query patterns or payload sizes",
            "applicability": "high",
        },
    ],
}


class ATTACKMapper:
    """Maps threat classifications to potential MITRE ATT&CK techniques.

    All mappings are qualified — never claims confirmed ATT&CK technique
    from classifier output alone.
    """

    def __init__(
        self,
        mapping_table: dict[str, list[dict[str, str]]] | None = None,
        default_qualification: str = "possible",
    ) -> None:
        self._mapping_table = mapping_table or _THREAT_TO_ATTACK
        self._default_qualification = default_qualification

    def map(
        self,
        threat_type: str,
        confidence: float = 0.0,
    ) -> list[ATTACKMapping]:
        """Map a threat classification to potential ATT&CK techniques.

        Args:
            threat_type: Canonical threat type (e.g., "ddos", "c2").
            confidence: Model confidence score (used for qualification).

        Returns:
            List of ATTACKMapping objects. Empty if no mapping exists.
        """
        if threat_type in ("benign", "unknown", "unsupported"):
            return []

        entries = self._mapping_table.get(threat_type, [])
        if not entries:
            return []

        # Determine qualification based on confidence
        if confidence >= 0.8:
            qualification = "likely"
        elif confidence >= 0.5:
            qualification = "observed indicators consistent with"
        else:
            qualification = self._default_qualification

        return [
            ATTACKMapping(
                technique_id=entry["technique_id"],
                technique_name=entry["technique_name"],
                tactic=entry["tactic"],
                rationale=entry["rationale"],
                applicability=entry["applicability"],
                qualification=qualification,
            )
            for entry in entries
        ]

    @property
    def supported_threat_types(self) -> list[str]:
        return list(self._mapping_table.keys())
