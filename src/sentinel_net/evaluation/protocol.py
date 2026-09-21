"""
Evaluation Protocol and Experiment Manifest management.
"""

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from sentinel_net.detection.dataset import DatasetSplit
from sentinel_net.features.schema import FEATURE_SCHEMA_VERSION, FEATURE_COUNT

@dataclass
class ExperimentManifest:
    """Records all configuration for reproducibility."""
    experiment_id: str
    experiment_type: str  # e.g., 'model_comparison', 'feature_ablation'
    dataset_id: str
    dataset_hash: str | None  # SHA-256 of dataset file if available
    split_strategy: str
    train_scenarios: list[str]
    val_scenarios: list[str]
    test_scenarios: list[str]
    random_seed: int
    model_name: str
    model_version: str
    hyperparameters: dict[str, Any]
    feature_schema_version: str
    feature_count: int
    preprocessing_config: dict[str, Any]
    threshold_config: dict[str, Any]
    threshold_source: str  # 'default' or 'validation_optimized'
    timestamp: str  # ISO 8601
    code_version: str
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=4)


class EvaluationProtocol:
    """Manages the locked evaluation protocol.
    
    State machine: OPEN → THRESHOLD_LOCKED → FINAL_EVALUATED
    
    Once FINAL_EVALUATED, no further changes are permitted.
    """
    
    # States
    OPEN = 'open'
    THRESHOLD_LOCKED = 'threshold_locked'
    FINAL_EVALUATED = 'final_evaluated'
    
    def __init__(self, protocol_id: str, random_seed: int = 42):
        self.protocol_id = protocol_id
        self.random_seed = random_seed
        self.state = self.OPEN
        self.split: DatasetSplit | None = None
        self.threshold: float | None = None
        self.threshold_source: str | None = None
        self.final_metrics: dict | None = None
    
    def register_split(self, split: DatasetSplit) -> None:
        """Register the dataset split. Only in OPEN state."""
        if self.state != self.OPEN:
            raise RuntimeError("Cannot register split unless protocol is in OPEN state.")
        self.split = split
    
    def lock_threshold(self, threshold: float, source: str) -> None:
        """Lock the anomaly threshold. Transitions OPEN → THRESHOLD_LOCKED.
        source must be 'default' or 'validation_optimized'."""
        if self.state != self.OPEN:
            raise RuntimeError("Cannot lock threshold unless protocol is in OPEN state.")
        if source not in ('default', 'validation_optimized'):
            raise ValueError("source must be 'default' or 'validation_optimized'.")
        self.threshold = threshold
        self.threshold_source = source
        self.state = self.THRESHOLD_LOCKED
    
    def record_final_evaluation(self, metrics: dict) -> None:
        """Record final test metrics. Transitions → FINAL_EVALUATED.
        After this, no configuration changes are permitted."""
        if self.state != self.THRESHOLD_LOCKED:
            raise RuntimeError("Must be in THRESHOLD_LOCKED state to record final evaluation.")
        self.final_metrics = metrics
        self.state = self.FINAL_EVALUATED
    
    def verify_split_integrity(self) -> bool:
        """Verify train/val/test are disjoint by both samples AND scenario IDs."""
        if not self.split:
            return False
        
        # Verify samples
        if not self.split.validate():
            return False
            
        # Verify scenario IDs if present
        if self.split.train_scenario_ids and self.split.val_scenario_ids:
            train_scen = set(self.split.train_scenario_ids)
            val_scen = set(self.split.val_scenario_ids)
            if not train_scen.isdisjoint(val_scen):
                return False
                
            if self.split.test_scenario_ids:
                test_scen = set(self.split.test_scenario_ids)
                if not train_scen.isdisjoint(test_scen):
                    return False
                if not val_scen.isdisjoint(test_scen):
                    return False
                    
        return True
    
    def create_manifest(
        self,
        experiment_id: str,
        experiment_type: str,
        dataset_id: str,
        model_name: str,
        model_version: str,
        hyperparameters: dict[str, Any],
        preprocessing_config: dict[str, Any],
        threshold_config: dict[str, Any],
        timestamp: str,
        code_version: str,
        notes: str,
        dataset_hash: str | None = None,
    ) -> ExperimentManifest:
        """Create an ExperimentManifest based on the current state."""
        train_scenarios = self.split.train_scenario_ids if self.split and self.split.train_scenario_ids else []
        val_scenarios = self.split.val_scenario_ids if self.split and self.split.val_scenario_ids else []
        test_scenarios = self.split.test_scenario_ids if self.split and self.split.test_scenario_ids else []
        
        return ExperimentManifest(
            experiment_id=experiment_id,
            experiment_type=experiment_type,
            dataset_id=dataset_id,
            dataset_hash=dataset_hash,
            split_strategy=self.split.split_strategy if self.split else "unknown",
            train_scenarios=train_scenarios,
            val_scenarios=val_scenarios,
            test_scenarios=test_scenarios,
            random_seed=self.random_seed,
            model_name=model_name,
            model_version=model_version,
            hyperparameters=hyperparameters,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_count=FEATURE_COUNT,
            preprocessing_config=preprocessing_config,
            threshold_config=threshold_config,
            threshold_source=self.threshold_source if self.threshold_source else "unknown",
            timestamp=timestamp,
            code_version=code_version,
            notes=notes
        )
