import dataclasses
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, List, Tuple

import joblib

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class ModelManifest:
    model_name: str
    model_version: str
    training_timestamp: str
    feature_schema_version: str
    preprocessing_version: str
    dataset_id: str
    training_config: dict
    random_seed: int
    metrics: dict
    artifact_checksum: str
    python_version: str
    dependencies: dict

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'ModelManifest':
        return cls(**d)


class ModelRegistry:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _compute_checksum(path: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def save_model(self, model: Any, manifest: ModelManifest) -> Path:
        model_dir = self.base_dir / manifest.model_name / manifest.model_version
        model_dir.mkdir(parents=True, exist_ok=True)

        model_path = model_dir / "model.joblib"
        manifest_path = model_dir / "manifest.json"

        joblib.dump(model, model_path)
        
        checksum = self._compute_checksum(model_path)
        manifest.artifact_checksum = checksum
        
        with open(manifest_path, "w") as f:
            json.dump(manifest.to_dict(), f, indent=4)
            
        return model_dir

    def load_model(self, model_name: str, model_version: str) -> Tuple[Any, ModelManifest]:
        model_dir = self.base_dir / model_name / model_version
        model_path = model_dir / "model.joblib"
        manifest_path = model_dir / "manifest.json"

        if not manifest_path.exists():
            logger.warning(f"Manifest not found at {manifest_path}")
            raise FileNotFoundError(f"Missing manifest file at {manifest_path}")

        with open(manifest_path, "r") as f:
            manifest_data = json.load(f)
            manifest = ModelManifest.from_dict(manifest_data)

        if not model_path.exists():
            raise FileNotFoundError(f"Missing model file at {model_path}")

        current_checksum = self._compute_checksum(model_path)
        if current_checksum != manifest.artifact_checksum:
            raise ValueError(
                f"Checksum mismatch for {model_name} {model_version}. "
                f"Expected {manifest.artifact_checksum}, got {current_checksum}"
            )

        model = joblib.load(model_path)
        return model, manifest

    def list_models(self) -> List[ModelManifest]:
        manifests = []
        for manifest_path in self.base_dir.rglob("manifest.json"):
            try:
                with open(manifest_path, "r") as f:
                    data = json.load(f)
                    manifests.append(ModelManifest.from_dict(data))
            except Exception as e:
                logger.warning(f"Failed to load manifest at {manifest_path}: {e}")
        return manifests

    def get_manifest(self, model_name: str, model_version: str) -> ModelManifest:
        manifest_path = self.base_dir / model_name / model_version / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Missing manifest file at {manifest_path}")
        
        with open(manifest_path, "r") as f:
            return ModelManifest.from_dict(json.load(f))
