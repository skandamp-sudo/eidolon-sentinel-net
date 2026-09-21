"""Tests for model registry."""

import datetime
import tempfile
from pathlib import Path

import numpy as np
import pytest

from sentinel_net.detection.registry import ModelManifest, ModelRegistry


@pytest.fixture
def registry():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield ModelRegistry(Path(tmpdir) / "models")


@pytest.fixture
def sample_manifest():
    return ModelManifest(
        model_name="test_model",
        model_version="1.0.0",
        training_timestamp=datetime.datetime.now().isoformat(),
        feature_schema_version="2.0.0",
        preprocessing_version="1.0.0",
        dataset_id="synthetic_unit_test",
        training_config={"random_state": 42, "n_estimators": 10},
        random_seed=42,
        metrics={"f1_macro": 0.85, "accuracy": 0.90},
        artifact_checksum="",  # Will be computed on save
        python_version="3.12",
        dependencies={"scikit-learn": "1.5", "xgboost": "2.1"},
    )


class TestModelManifest:
    def test_to_dict(self, sample_manifest):
        d = sample_manifest.to_dict()
        assert isinstance(d, dict)
        assert d["model_name"] == "test_model"
        assert d["random_seed"] == 42

    def test_from_dict_roundtrip(self, sample_manifest):
        d = sample_manifest.to_dict()
        loaded = ModelManifest.from_dict(d)
        assert loaded.model_name == sample_manifest.model_name
        assert loaded.model_version == sample_manifest.model_version
        assert loaded.random_seed == sample_manifest.random_seed


class TestModelRegistry:
    def test_save_and_load(self, registry, sample_manifest):
        """Save + load must return identical model predictions."""
        from sentinel_net.detection.classifier import RandomForestBaseline
        from sentinel_net.features.schema import FEATURE_COUNT

        rng = np.random.RandomState(42)
        X = rng.randn(30, FEATURE_COUNT)
        y = np.array(["benign"] * 15 + ["ddos"] * 15)
        model = RandomForestBaseline(random_state=42)
        model.train(X, y)
        original_preds = model.predict(X[:5])

        registry.save_model(model, sample_manifest)
        loaded_model, loaded_manifest = registry.load_model("test_model", "1.0.0")

        result_preds = loaded_model.predict(X[:5])
        np.testing.assert_array_equal(original_preds, result_preds)

    def test_checksum_populated(self, registry, sample_manifest):
        """Checksum must be populated after save."""
        from sentinel_net.detection.classifier import RandomForestBaseline
        from sentinel_net.features.schema import FEATURE_COUNT

        rng = np.random.RandomState(42)
        model = RandomForestBaseline(random_state=42)
        model.train(rng.randn(20, FEATURE_COUNT),
                     np.array(["a"] * 10 + ["b"] * 10))
        registry.save_model(model, sample_manifest)

        _, manifest = registry.load_model("test_model", "1.0.0")
        assert len(manifest.artifact_checksum) == 64  # SHA-256 hex length

    def test_checksum_verification_on_load(self, registry, sample_manifest):
        """Corrupted model file must raise ValueError on load."""
        from sentinel_net.detection.classifier import RandomForestBaseline
        from sentinel_net.features.schema import FEATURE_COUNT

        rng = np.random.RandomState(42)
        model = RandomForestBaseline(random_state=42)
        model.train(rng.randn(20, FEATURE_COUNT),
                     np.array(["a"] * 10 + ["b"] * 10))
        registry.save_model(model, sample_manifest)

        # Corrupt the model file
        model_path = registry.base_dir / "test_model" / "1.0.0" / "model.joblib"
        with open(model_path, "ab") as f:
            f.write(b"CORRUPTED")

        with pytest.raises(ValueError, match="[Cc]hecksum"):
            registry.load_model("test_model", "1.0.0")

    def test_list_models(self, registry, sample_manifest):
        from sentinel_net.detection.classifier import RandomForestBaseline
        from sentinel_net.features.schema import FEATURE_COUNT

        rng = np.random.RandomState(42)
        model = RandomForestBaseline(random_state=42)
        model.train(rng.randn(20, FEATURE_COUNT),
                     np.array(["a"] * 10 + ["b"] * 10))
        registry.save_model(model, sample_manifest)
        models = registry.list_models()
        assert len(models) >= 1

    def test_missing_model_raises(self, registry):
        with pytest.raises((ValueError, FileNotFoundError)):
            registry.load_model("nonexistent", "1.0.0")
