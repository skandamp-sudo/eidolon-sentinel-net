"""
Threshold configuration for Sentinel-Net.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class ThresholdConfig:
    """
    Configuration for anomaly and classification thresholds.
    Initial defaults — should be tuned on validation data.
    """
    anomaly_threshold: float = 0.5
    min_confidence: float = 0.3
    severity_thresholds: Dict[str, float] = field(
        default_factory=lambda: {'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9}
    )
    
    def get_severity(self, anomaly_score: float) -> str:
        """Returns severity level based on thresholds."""
        if anomaly_score >= self.severity_thresholds.get('critical', 0.9):
            return 'critical'
        elif anomaly_score >= self.severity_thresholds.get('high', 0.7):
            return 'high'
        elif anomaly_score >= self.severity_thresholds.get('medium', 0.5):
            return 'medium'
        elif anomaly_score >= self.severity_thresholds.get('low', 0.3):
            return 'low'
        else:
            return 'info'
            
    def is_anomalous(self, score: float) -> bool:
        """Returns true if score is greater than or equal to anomaly_threshold."""
        return score >= self.anomaly_threshold
        
    def to_dict(self) -> Dict[str, Any]:
        """Serializes the configuration to a dictionary."""
        return {
            "anomaly_threshold": self.anomaly_threshold,
            "min_confidence": self.min_confidence,
            "severity_thresholds": self.severity_thresholds.copy()
        }
        
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThresholdConfig":
        """Creates a configuration from a dictionary."""
        return cls(
            anomaly_threshold=d.get("anomaly_threshold", 0.5),
            min_confidence=d.get("min_confidence", 0.3),
            severity_thresholds=d.get("severity_thresholds", {'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9})
        )
