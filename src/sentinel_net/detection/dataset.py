"""
Dataset pipeline for Sentinel-Net detection module.
"""

import hashlib
import json
from copy import deepcopy
import numpy as np
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple, Any
from sentinel_net.models.types import FeatureVector
from sentinel_net.features.schema import FEATURE_SCHEMA


@dataclass
class DatasetSplit:
    """Represents a split of a dataset into train/val/test sets."""
    X_train: np.ndarray  # (n_train, n_features)
    y_train: np.ndarray  # (n_train,) string labels
    X_val: Optional[np.ndarray] = None
    y_val: Optional[np.ndarray] = None
    X_test: Optional[np.ndarray] = None
    y_test: Optional[np.ndarray] = None
    feature_names: List[str] = None
    split_strategy: str = "unknown"
    provenance: Dict[str, Any] = None
    train_scenario_ids: Optional[List[str]] = None
    val_scenario_ids: Optional[List[str]] = None
    test_scenario_ids: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.feature_names is None:
            self.feature_names = []
        if self.provenance is None:
            self.provenance = {}

    def validate(self) -> bool:
        """Verifies shapes and checks for sample overlap by hashing rows."""
        if len(self.X_train.shape) != 2:
            return False
        if self.X_train.shape[0] != self.y_train.shape[0]:
            return False
            
        def hash_rows(arr):
            return {hashlib.sha256(row.tobytes()).hexdigest() for row in arr}
            
        train_hashes = hash_rows(self.X_train)
        
        if self.X_val is not None:
            if self.X_val.shape[0] != self.y_val.shape[0]:
                return False
            val_hashes = hash_rows(self.X_val)
            if not train_hashes.isdisjoint(val_hashes):
                return False
                
        if self.X_test is not None:
            if self.X_test.shape[0] != self.y_test.shape[0]:
                return False
            test_hashes = hash_rows(self.X_test)
            if not train_hashes.isdisjoint(test_hashes):
                return False
            if self.X_val is not None and not val_hashes.isdisjoint(test_hashes):
                return False
                
        if self.train_scenario_ids and self.val_scenario_ids:
            train_scen = set(self.train_scenario_ids)
            val_scen = set(self.val_scenario_ids)
            if not train_scen.isdisjoint(val_scen):
                return False
            
            if self.test_scenario_ids:
                test_scen = set(self.test_scenario_ids)
                if not train_scen.isdisjoint(test_scen):
                    return False
                if not val_scen.isdisjoint(test_scen):
                    return False

        return True


class LabelMapper:
    """Maps dataset-specific labels to canonical ThreatType values."""
    
    def __init__(self, mapping: Dict[str, str]):
        self.mapping = mapping
        
    def map(self, label: str) -> str:
        """Returns mapped label, or 'unknown' if unmapped."""
        return self.mapping.get(label, 'unknown')
        
    def map_array(self, labels: np.ndarray) -> np.ndarray:
        """Vectorized mapping."""
        return np.array([self.map(lbl) for lbl in labels])
        
    @property
    def supported_classes(self) -> List[str]:
        """Returns unique canonical labels in the mapping."""
        return list(set(self.mapping.values()))
        
    @classmethod
    def for_cicids2017(cls) -> "LabelMapper":
        """Pre-configured LabelMapper for CIC-IDS2017 dataset.
        
        Handles both the original CSV labels and the Kaggle parquet labels,
        which may have different casing ('BENIGN' vs 'Benign') and encoding
        of special characters in Web Attack labels (en-dash, em-dash, 
        Windows-1252 \x96, or replacement character \ufffd).
        """
        mapping = {
            # Original CICIDS2017 CSV labels (uppercase BENIGN)
            "BENIGN": "benign",
            # Kaggle parquet variant (title case Benign)
            "Benign": "benign",
            # DoS variants
            "DoS Hulk": "ddos",
            "DoS GoldenEye": "ddos",
            "DoS Slowhttptest": "ddos",
            "DoS slowloris": "ddos",
            "Heartbleed": "ddos",
            # Brute force
            "FTP-Patator": "brute_force",
            "SSH-Patator": "brute_force",
            # Recon
            "PortScan": "reconnaissance",
            # C2
            "Bot": "c2",
            # Web attacks — hyphen separator (original CSV)
            "Web Attack - Brute Force": "other",
            "Web Attack - XSS": "other",
            "Web Attack - Sql Injection": "other",
            # Web attacks — en-dash separator (some CSV encodings)
            "Web Attack \u2013 Brute Force": "other",
            "Web Attack \u2013 XSS": "other",
            "Web Attack \u2013 Sql Injection": "other",
            # Web attacks — replacement character (mojibake in Kaggle parquet)
            "Web Attack \ufffd Brute Force": "other",
            "Web Attack \ufffd XSS": "other",
            "Web Attack \ufffd Sql Injection": "other",
            # DDoS (distinct from DoS variants)
            "DDoS": "ddos",
            # Infiltration
            "Infiltration": "exfiltration",
        }
        return cls(mapping)
        
    @classmethod
    def for_unsw_nb15(cls) -> "LabelMapper":
        """Pre-configured LabelMapper for UNSW-NB15 dataset."""
        mapping = {
            "Normal": "benign",
            "DoS": "ddos",
            "Exploits": "other",
            "Fuzzers": "other",
            "Generic": "other",
            "Reconnaissance": "reconnaissance",
            "Shellcode": "c2",
            "Worms": "other",
            "Backdoor": "c2",
            "Backdoors": "c2",
            "Analysis": "reconnaissance"
        }
        return cls(mapping)


class DatasetBuilder:
    """Dataset builder pipeline."""
    
    def __init__(self, feature_names: Optional[List[str]] = None):
        if feature_names is None:
            self.feature_names = list(FEATURE_SCHEMA)
        else:
            self.feature_names = feature_names
            
    def from_feature_vectors(self, vectors: List[FeatureVector], labels: List[str], 
                             source: str = 'unknown', 
                             scenarios: Optional[List[str]] = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Extracts numerical features from FeatureVectors into a float64 matrix."""
        X = []
        for vec in vectors:
            X.append(vec.values)
            
        if scenarios is None:
            scenarios = ["default"] * len(vectors)
            
        return np.array(X, dtype=np.float64), np.array(labels), scenarios
        
    def scenario_aware_split(self, X: np.ndarray, y: np.ndarray, scenarios: List[str], 
                             train_ratio: float = 0.7, val_ratio: float = 0.15, 
                             test_ratio: float = 0.15, random_state: int = 42,
                             dataset_identity: Optional[Dict[str, Any]] = None) -> DatasetSplit:
        """Splits by unique scenario groups, not individual samples.

        Ensures that all flows from a single scenario stay in the same
        partition, preventing data leakage between train/val/test.
        """
        scenarios_arr = np.array(scenarios)
        unique_scenarios = sorted(set(scenarios))
        rng = np.random.RandomState(random_state)
        rng.shuffle(unique_scenarios)

        n_scenarios = len(unique_scenarios)
        n_train = max(1, int(n_scenarios * train_ratio))
        n_val = max(0, int(n_scenarios * val_ratio)) if val_ratio > 0 else 0
        # Ensure at least 1 scenario for test if test_ratio > 0
        if test_ratio > 0 and n_train + n_val >= n_scenarios:
            n_val = max(0, n_scenarios - n_train - 1)

        train_scenarios = set(unique_scenarios[:n_train])
        val_scenarios = set(unique_scenarios[n_train:n_train + n_val])
        test_scenarios = set(unique_scenarios[n_train + n_val:])

        train_mask = np.array([s in train_scenarios for s in scenarios])
        val_mask = np.array([s in val_scenarios for s in scenarios])
        test_mask = np.array([s in test_scenarios for s in scenarios])

        X_train, y_train = X[train_mask], y[train_mask]
        X_val = X[val_mask] if val_mask.any() else None
        y_val = y[val_mask] if val_mask.any() else None
        X_test = X[test_mask] if test_mask.any() else None
        y_test = y[test_mask] if test_mask.any() else None

        return DatasetSplit(
            X_train=X_train, y_train=y_train,
            X_val=X_val, y_val=y_val,
            X_test=X_test, y_test=y_test,
            feature_names=self.feature_names,
            split_strategy='scenario_aware',
            provenance={
                'source': 'scenario_split',
                'partition_origin': 'GENERATED_DETERMINISTIC',
                'split_method_version': 'scenario-sorted-shuffle-v1',
                'dataset_identity': deepcopy(dataset_identity),
                'row_counts': {'train': len(X_train),
                               'validation': int(val_mask.sum()),
                               'test': int(test_mask.sum())},
                'n_scenarios': n_scenarios,
                'train_scenarios': sorted(train_scenarios),
                'val_scenarios': sorted(val_scenarios),
                'test_scenarios': sorted(test_scenarios),
                'random_state': random_state,
            }
        )
        
    def explicit_manifest_split(
        self, X: np.ndarray, y: np.ndarray, scenarios: List[str],
        manifest: Dict[str, Any], *,
        dataset_identity: Optional[Dict[str, Any]] = None,
        required_partitions: Tuple[str, ...] = ('train', 'validation', 'test'),
    ) -> DatasetSplit:
        """Apply an explicit assignment without shuffling or changing row order.

        Dataset identity is caller-supplied metadata (e.g. verified file hashes),
        not a hash inferred from the feature matrix. A bound manifest requires
        an exactly matching observed identity. Expected row counts are optional.
        """
        keys = ('train', 'validation', 'test')
        if X.ndim != 2 or y.ndim != 1 or len(X) != len(y) or len(X) != len(scenarios):
            raise ValueError('Feature, label and scenario row counts must agree')
        if not all(isinstance(s, str) and s for s in scenarios):
            raise ValueError('Scenario IDs must be non-empty strings')
        if not isinstance(manifest, dict) or manifest.get('version') != 1:
            raise ValueError('Explicit partition manifest version 1 required')
        partitions = manifest.get('partitions')
        if not isinstance(partitions, dict) or set(partitions) != set(keys):
            raise ValueError('Exactly train/validation/test partition keys required')
        if not set(required_partitions) <= set(keys):
            raise ValueError('Unknown required partition')
        assigned = []
        for key in keys:
            ids = partitions[key]
            if not isinstance(ids, list) or not all(isinstance(s, str) and s for s in ids):
                raise ValueError('Partition scenarios must be lists of non-empty strings')
            if key in required_partitions and not ids:
                raise ValueError('Required partition is empty')
            assigned.extend(ids)
        if len(assigned) != len(set(assigned)):
            raise ValueError('Scenario assigned more than once')
        if set(assigned) != set(scenarios):
            raise ValueError('Assignment must cover exactly the observed scenarios')
        bound_identity = manifest.get('dataset_identity')
        if bound_identity is not None and bound_identity != dataset_identity:
            raise ValueError('Observed dataset identity does not match manifest')
        masks = {k: np.isin(scenarios, partitions[k]) for k in keys}
        counts = {k: int(masks[k].sum()) for k in keys}
        expected = manifest.get('expected_row_counts')
        if expected is not None and (
            not isinstance(expected, dict) or set(expected) != set(keys)
            or any(type(expected[k]) is not int or expected[k] < 0 for k in keys)
            or expected != counts
        ):
            raise ValueError('Observed partition row counts do not match manifest')
        canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False)
        return DatasetSplit(
            X_train=X[masks['train']], y_train=y[masks['train']],
            X_val=X[masks['validation']] if counts['validation'] else None,
            y_val=y[masks['validation']] if counts['validation'] else None,
            X_test=X[masks['test']] if counts['test'] else None,
            y_test=y[masks['test']] if counts['test'] else None,
            feature_names=list(self.feature_names), split_strategy='explicit_manifest',
            train_scenario_ids=list(partitions['train']),
            val_scenario_ids=list(partitions['validation']),
            test_scenario_ids=list(partitions['test']),
            provenance={
                'source': 'explicit_manifest', 'partition_origin': 'EXPLICIT_MANIFEST',
                'split_method_version': 'explicit-scenario-manifest-v1',
                'manifest_sha256': hashlib.sha256(canonical.encode()).hexdigest(),
                'dataset_identity': deepcopy(dataset_identity), 'row_counts': counts,
                'train_scenarios': list(partitions['train']),
                'val_scenarios': list(partitions['validation']),
                'test_scenarios': list(partitions['test']),
                'random_state': None,
            },
        )

    def temporal_split(self, X: np.ndarray, y: np.ndarray, timestamps: List[float], 
                       train_ratio: float = 0.7, val_ratio: float = 0.15) -> DatasetSplit:
        """Splits by timestamp order."""
        idx = np.argsort(timestamps)
        X_sorted = X[idx]
        y_sorted = y[idx]
        
        n_samples = len(X)
        train_end = int(n_samples * train_ratio)
        val_end = train_end + int(n_samples * val_ratio)
        
        X_train = X_sorted[:train_end]
        y_train = y_sorted[:train_end]
        
        X_val = X_sorted[train_end:val_end] if val_ratio > 0 else None
        y_val = y_sorted[train_end:val_end] if val_ratio > 0 else None
        
        X_test = X_sorted[val_end:]
        y_test = y_sorted[val_end:]
        
        if len(X_test) == 0:
            X_test = None
            y_test = None
            
        return DatasetSplit(
            X_train=X_train, y_train=y_train,
            X_val=X_val, y_val=y_val,
            X_test=X_test, y_test=y_test,
            feature_names=self.feature_names,
            split_strategy='temporal',
            provenance={'source': 'temporal_split'}
        )
