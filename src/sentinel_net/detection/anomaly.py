import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

from sentinel_net.models.types import AnomalyResult

class AnomalyDetector:
    def __init__(
        self, 
        n_estimators: int = 100, 
        contamination: float | str = 'auto', 
        random_state: int = 42,
        model_name: str = 'isolation_forest',
        model_version: str = '1.0.0'
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model_name = model_name
        self.model_version = model_version
        
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state
        )
        self._is_trained = False
        
    def train(self, X_benign: np.ndarray) -> 'AnomalyDetector':
        self._model.fit(X_benign)
        self._is_trained = True
        return self
        
    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._is_trained:
            raise RuntimeError("Model must be trained before calling score")
            
        raw_score = self._model.decision_function(X)
        
        # This is a normalized anomaly score, NOT a calibrated probability. Values closer to 1 indicate more anomalous behavior.
        offset = self._model.offset_
        score = 0.5 - raw_score / (2 * abs(offset))
        score = np.clip(score, 0, 1)
        
        return score
        
    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        scores = self.score(X)
        return scores >= threshold
        
    def to_anomaly_results(
        self, 
        X: np.ndarray, 
        flow_keys: list, 
        timestamps: list[float], 
        threshold: float = 0.5
    ) -> list:
        scores = self.score(X)
        is_anomalous = scores >= threshold
        
        results = []
        for i in range(len(X)):
            result = AnomalyResult(
                flow_key=flow_keys[i],
                timestamp=timestamps[i],
                anomaly_score=float(scores[i]),
                is_anomalous=bool(is_anomalous[i]),
                model_name=self.model_name,
                model_version=self.model_version
            )
            results.append(result)
            
        return results
        
    def save(self, path: Path) -> None:
        if not self._is_trained:
            raise RuntimeError("Cannot save untrained model")
        joblib.dump(self, path)
        
    @classmethod
    def load(cls, path: Path) -> 'AnomalyDetector':
        return joblib.load(path)
        
    @property
    def is_trained(self) -> bool:
        return self._is_trained
