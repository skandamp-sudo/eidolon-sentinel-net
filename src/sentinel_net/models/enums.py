from enum import Enum

class Severity(str, Enum):
    """Severity levels for detection events."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(str, Enum):
    """Known threat classifications."""
    BENIGN = "benign"
    DDOS = "ddos"
    SCAN = "scan"
    RECONNAISSANCE = "reconnaissance"
    EXFILTRATION = "exfiltration"
    C2 = "c2"
    DNS_TUNNELING = "dns_tunneling"
    BRUTE_FORCE = "brute_force"
    OTHER = "other"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"

class Direction(str, Enum):
    """Direction of traffic flow."""
    FORWARD = "forward"
    REVERSE = "reverse"
    UNKNOWN = "unknown"

class Protocol(int, Enum):
    """Common IP protocol numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17
    ICMPv6 = 58
