import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Type, TypeVar

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.models.types import ThreatClassification

T = TypeVar('T', bound='BaseClassifier')
logger = logging.getLogger(__name__)

class BaseClassifier(ABC):
    @abstractmethod
    def train(self: T, X: np.ndarray, y: np.ndarray) -> T:
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        pass

    @abstractmethod
    def predict_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        pass

    @abstractmethod
    def save(self, path: Path) -> None:
        pass

    @classmethod
    @abstractmethod
    def load(cls: Type[T], path: Path) -> T:
        pass

    @property
    @abstractmethod
    def is_trained(self) -> bool:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_version(self) -> str:
        pass

    @property
    @abstractmethod
    def supported_classes(self) -> List[str]:
        pass


class XGBoostClassifier(BaseClassifier):
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        random_state: int = 42,
        model_name: str = 'xgboost',
        model_version: str = '1.0.0'
    ):
        self._n_estimators = n_estimators
        self._max_depth = max_depth
        self._learning_rate = learning_rate
        self._random_state = random_state
        self._model_name = model_name
        self._model_version = model_version
        
        self._model = XGBClassifier(
            n_estimators=self._n_estimators,
            max_depth=self._max_depth,
            learning_rate=self._learning_rate,
            random_state=self._random_state,
        )
        self._label_encoder = LabelEncoder()
        self._classes: List[str] = []
        self._is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray) -> 'XGBoostClassifier':
        y_encoded = self._label_encoder.fit_transform(y)
        self._classes = list(self._label_encoder.classes_)
        n_classes = len(self._classes)

        if n_classes < 2:
            raise ValueError(
                f"Training requires at least 2 classes, got {n_classes}: {self._classes}"
            )

        # Reconfigure model for actual number of classes
        if n_classes == 2:
            self._model.set_params(objective='binary:logistic', eval_metric='logloss')
        else:
            self._model.set_params(
                objective='multi:softprob', eval_metric='mlogloss',
                num_class=n_classes,
            )

        self._model.fit(X, y_encoded)
        self._is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        y_pred_encoded = self._model.predict(X)
        return self._label_encoder.inverse_transform(y_pred_encoded)

    def predict_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Returns raw model scores, NOT calibrated probabilities.
        These are confidence scores from the model.
        """
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        scores = self._model.predict_proba(X)
        if scores.ndim == 1:
            # Binary case: XGBoost returns P(class=1)
            scores = np.column_stack([1.0 - scores, scores])
        return {cls_name: scores[:, i] for i, cls_name in enumerate(self._classes)}


    def save(self, path: Path) -> None:
        joblib.dump({
            'model': self._model,
            'label_encoder': self._label_encoder,
            'classes': self._classes,
            'params': {
                'n_estimators': self._n_estimators,
                'max_depth': self._max_depth,
                'learning_rate': self._learning_rate,
                'random_state': self._random_state,
                'model_name': self._model_name,
                'model_version': self._model_version
            }
        }, path)

    @classmethod
    def load(cls, path: Path) -> 'XGBoostClassifier':
        data = joblib.load(path)
        params = data['params']
        instance = cls(**params)
        instance._model = data['model']
        instance._label_encoder = data['label_encoder']
        instance._classes = data['classes']
        instance._is_trained = True
        return instance

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def supported_classes(self) -> List[str]:
        return self._classes


class RandomForestBaseline(BaseClassifier):
    def __init__(
        self,
        n_estimators: int = 100,
        random_state: int = 42,
        model_name: str = 'random_forest',
        model_version: str = '1.0.0'
    ):
        self._n_estimators = n_estimators
        self._random_state = random_state
        self._model_name = model_name
        self._model_version = model_version
        
        self._model = RandomForestClassifier(
            n_estimators=self._n_estimators,
            random_state=self._random_state
        )
        self._label_encoder = LabelEncoder()
        self._classes: List[str] = []
        self._is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray) -> 'RandomForestBaseline':
        y_encoded = self._label_encoder.fit_transform(y)
        self._classes = list(self._label_encoder.classes_)
        self._model.fit(X, y_encoded)
        self._is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        y_pred_encoded = self._model.predict(X)
        return self._label_encoder.inverse_transform(y_pred_encoded)

    def predict_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Returns raw model scores, NOT calibrated probabilities.
        These are confidence scores from the model.
        """
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        scores = self._model.predict_proba(X)
        return {cls_name: scores[:, i] for i, cls_name in enumerate(self._classes)}

    def save(self, path: Path) -> None:
        joblib.dump({
            'model': self._model,
            'label_encoder': self._label_encoder,
            'classes': self._classes,
            'params': {
                'n_estimators': self._n_estimators,
                'random_state': self._random_state,
                'model_name': self._model_name,
                'model_version': self._model_version
            }
        }, path)

    @classmethod
    def load(cls, path: Path) -> 'RandomForestBaseline':
        data = joblib.load(path)
        params = data['params']
        instance = cls(**params)
        instance._model = data['model']
        instance._label_encoder = data['label_encoder']
        instance._classes = data['classes']
        instance._is_trained = True
        return instance

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def supported_classes(self) -> List[str]:
        return self._classes


class LogisticRegressionBaseline(BaseClassifier):
    def __init__(
        self,
        max_iter: int = 1000,
        random_state: int = 42,
        model_name: str = 'logistic_regression',
        model_version: str = '1.0.0'
    ):
        self._max_iter = max_iter
        self._random_state = random_state
        self._model_name = model_name
        self._model_version = model_version
        
        self._model = LogisticRegression(
            max_iter=self._max_iter,
            random_state=self._random_state,
            solver='lbfgs'
        )
        self._label_encoder = LabelEncoder()
        self._classes: List[str] = []
        self._is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray) -> 'LogisticRegressionBaseline':
        y_encoded = self._label_encoder.fit_transform(y)
        self._classes = list(self._label_encoder.classes_)
        self._model.fit(X, y_encoded)
        self._is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        y_pred_encoded = self._model.predict(X)
        return self._label_encoder.inverse_transform(y_pred_encoded)

    def predict_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Returns raw model scores, NOT calibrated probabilities.
        These are confidence scores from the model.
        """
        if not self._is_trained:
            raise ValueError("Model is not trained.")
        scores = self._model.predict_proba(X)
        return {cls_name: scores[:, i] for i, cls_name in enumerate(self._classes)}

    def save(self, path: Path) -> None:
        joblib.dump({
            'model': self._model,
            'label_encoder': self._label_encoder,
            'classes': self._classes,
            'params': {
                'max_iter': self._max_iter,
                'random_state': self._random_state,
                'model_name': self._model_name,
                'model_version': self._model_version
            }
        }, path)

    @classmethod
    def load(cls, path: Path) -> 'LogisticRegressionBaseline':
        data = joblib.load(path)
        params = data['params']
        instance = cls(**params)
        instance._model = data['model']
        instance._label_encoder = data['label_encoder']
        instance._classes = data['classes']
        instance._is_trained = True
        return instance

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def supported_classes(self) -> List[str]:
        return self._classes
