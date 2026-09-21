"""Frozen bundle validation, publication and inference-only runtime contracts."""

import json
from pathlib import Path

import joblib
import pytest

from sentinel_net.deployment.bundle import (
    ModelLoadError,
    _seal,
    load_bundle,
    publish_candidate,
    write_candidate,
    versions,
)
from sentinel_net.sensor.runtime_model import load_runtime_model
from tests.unit.test_rw1_correctness import detector, detected


def save_pipeline(root, detector):
    candidate = write_candidate(
        detector,
        root.parent / (root.name + "-candidate"),
        name="runtime",
        version="1.0.0",
        training_seed=42,
    )
    publish_candidate(
        candidate,
        root,
        approved_by="test-operator",
        evaluation_reference="synthetic-contract-test-only",
    )
    return root / "runtime" / "1.0.0"


def load(path):
    return load_runtime_model("runtime/1.0.0", registry=path.parent.parent)


def reseal(path, **updates):
    data = json.loads((path / "manifest.json").read_text())
    data.update(updates)
    _seal(path, data)


def test_runtime_model_roundtrip_same_scores_and_thresholds(tmp_path, detector, monkeypatch):
    path = save_pipeline(tmp_path / "registry", detector)
    monkeypatch.setattr(
        type(detector.classifier), "train", lambda *_: pytest.fail("runtime training")
    )
    monkeypatch.setattr(
        type(detector.anomaly_detector), "train", lambda *_: pytest.fail("runtime training")
    )
    monkeypatch.setattr(
        type(detector.preprocessor), "fit", lambda *_: pytest.fail("runtime fitting")
    )
    loaded = load(path)
    before, after = detected(detector).to_dict(), detected(loaded).to_dict()
    for key in (
        "classification_score",
        "anomaly_score",
        "threat_class",
        "severity",
        "feature_schema_version",
    ):
        assert before[key] == after[key]
    assert vars(loaded.thresholds) == vars(detector.thresholds)
    assert loaded.deployment_identity["model_name"] == "runtime"
    assert loaded.deployment_identity["model_version"] == "1.0.0"


@pytest.mark.parametrize(
    "artifact",
    [
        "classifier.joblib",
        "anomaly.joblib",
        "preprocessor.joblib",
        "thresholds.json",
        "manifest.json",
    ],
)
def test_checksums_before_deserialization(tmp_path, detector, monkeypatch, artifact):
    path = save_pipeline(tmp_path / "registry", detector)
    with (path / artifact).open("ab") as f:
        f.write(b" ")
    monkeypatch.setattr(joblib, "load", lambda *_: pytest.fail("deserialized before checksum"))
    with pytest.raises(ModelLoadError, match="CHECKSUM_MISMATCH"):
        load(path)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"feature_schema_version": "wrong"}, "SCHEMA_MISMATCH"),
        ({"feature_count": 51}, "SCHEMA_MISMATCH"),
        ({"feature_hash": "bad"}, "SCHEMA_MISMATCH"),
        ({"preprocessing_features": ["unknown"]}, "PREPROCESSOR_INCOMPATIBLE"),
        ({"transformed_features": ["wrong"]}, "PREPROCESSOR_INCOMPATIBLE"),
        ({"class_labels": ["wrong"]}, "MODEL_DESERIALIZATION_FAILED"),
        ({"status": "candidate"}, "MANIFEST_INVALID"),
        ({"model_name": "another"}, "MANIFEST_INVALID"),
    ],
)
def test_incompatible_manifest_fails(tmp_path, detector, change, code):
    path = save_pipeline(tmp_path / "registry", detector)
    reseal(path, **change)
    with pytest.raises(ModelLoadError, match=code):
        load(path)


def test_wrong_feature_order_before_deserialization(tmp_path, detector, monkeypatch):
    path = save_pipeline(tmp_path / "registry", detector)
    data = json.loads((path / "manifest.json").read_text())
    data["feature_names"].reverse()
    _seal(path, data)
    monkeypatch.setattr(joblib, "load", lambda *_: pytest.fail("deserialized incompatible schema"))
    with pytest.raises(ModelLoadError, match="FEATURE_ORDER_MISMATCH"):
        load(path)


@pytest.mark.parametrize(
    "identity", [None, "missing/1", "../1", "/tmp/model", "https://example/model", "name/../../etc"]
)
def test_missing_or_unsafe_identity_has_no_fallback(tmp_path, identity, monkeypatch):
    monkeypatch.setattr(joblib, "load", lambda *_: pytest.fail("missing model deserialized"))
    with pytest.raises(ModelLoadError, match="MODEL_NOT_FOUND"):
        load_bundle(tmp_path, identity)


def test_invalid_manifest(tmp_path, detector):
    path = save_pipeline(tmp_path / "registry", detector)
    (path / "manifest.json").write_text("{}")
    with pytest.raises(ModelLoadError, match="MANIFEST_INVALID"):
        load(path)


def test_verified_corrupt_serialization(tmp_path, detector):
    path = save_pipeline(tmp_path / "registry", detector)
    (path / "classifier.joblib").write_bytes(b"corrupt")
    reseal(path)
    with pytest.raises(ModelLoadError, match="MODEL_DESERIALIZATION_FAILED"):
        load(path)


def test_threshold_configuration(tmp_path, detector):
    path = save_pipeline(tmp_path / "registry", detector)
    (path / "thresholds.json").write_text('{"anomaly_threshold": -1}')
    reseal(path)
    with pytest.raises(ModelLoadError, match="THRESHOLD_CONFIGURATION_INVALID"):
        load(path)


def test_dependency_policy(tmp_path, detector, caplog):
    path = save_pipeline(tmp_path / "registry", detector)
    deps = versions()
    deps["joblib"] = "1.999.1"
    reseal(path, dependencies=deps)
    load(path)
    assert "dependency difference" in caplog.text
    deps["scikit-learn"] = "0.0.0"
    reseal(path, dependencies=deps)
    with pytest.raises(ModelLoadError, match="DEPENDENCY_INCOMPATIBLE"):
        load(path)


def test_candidate_not_approved_and_publication_immutable(tmp_path, detector):
    candidate = write_candidate(detector, tmp_path / "candidate", name="runtime", version="1.0.0")
    registry = tmp_path / "registry"
    publish_candidate(
        candidate, registry, approved_by="operator", evaluation_reference="local-evaluation.json"
    )
    path = registry / "runtime" / "1.0.0"
    before = (path / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        publish_candidate(candidate, registry, approved_by="other", evaluation_reference="other")
    assert (path / "manifest.json").read_bytes() == before
    assert json.loads((candidate / "manifest.json").read_text())["status"] == "candidate"


def test_failed_publication_never_activates(tmp_path, detector, monkeypatch):
    import sentinel_net.deployment.bundle as bundle

    candidate = write_candidate(detector, tmp_path / "candidate", name="runtime", version="1.0.0")
    monkeypatch.setattr(bundle, "_seal", lambda *_: (_ for _ in ()).throw(OSError("disk failed")))
    with pytest.raises(OSError):
        publish_candidate(
            candidate, tmp_path / "registry", approved_by="op", evaluation_reference="test"
        )
    with pytest.raises(ModelLoadError, match="MODEL_NOT_FOUND"):
        load_bundle(tmp_path / "registry", "runtime/1.0.0")
    assert not list((tmp_path / "registry" / "runtime").iterdir())


def test_runtime_modules_do_not_import_training():
    import ast

    for relative in ("sensor/service.py", "sensor/runtime_model.py", "demo_replay.py"):
        tree = ast.parse((Path("src/sentinel_net") / relative).read_text())
        assert not any(
            isinstance(n, ast.Attribute) and n.attr in ("train", "fit", "fit_transform")
            for n in ast.walk(tree)
        )
        assert not any(
            isinstance(n, ast.ImportFrom)
            and n.module
            and ("training" in n.module or "evaluation" in n.module)
            for n in ast.walk(tree)
        )


@pytest.mark.parametrize("artifact", ["preprocessor.joblib", "classifier.joblib", "anomaly.joblib"])
def test_unfitted_artifact_is_rejected(tmp_path, detector, artifact):
    path = save_pipeline(tmp_path / "registry", detector)
    value = joblib.load(path / artifact)
    if artifact == "preprocessor.joblib":
        value._is_fitted = False
    elif artifact == "anomaly.joblib":
        value._is_trained = False
    else:
        from sklearn.ensemble import RandomForestClassifier

        value["model"] = RandomForestClassifier()
    joblib.dump(value, path / artifact)
    reseal(path)
    with pytest.raises(ModelLoadError):
        load(path)


async def test_missing_sensor_model_fails_before_storage_or_capture(tmp_path):
    from sentinel_net.config import SentinelConfig
    from sentinel_net.sensor.service import SensorService
    from sentinel_net.sensor.lifecycle import SensorState

    def forbidden(*_):
        pytest.fail("resource initialized before model validation")

    service = SensorService(
        SentinelConfig(capture_interface="test0", sensor_model="absent/1", model_registry=tmp_path),
        interface_validator=lambda _: None,
        capture_factory=forbidden,
        database_factory=forbidden,
    )
    with pytest.raises(ModelLoadError, match="MODEL_NOT_FOUND"):
        await service.start()
    assert service.lifecycle.state == SensorState.FAILED
    assert service.db is None and service.capture is None


async def test_missing_replay_model_never_starts_source(tmp_path, monkeypatch):
    from sentinel_net import demo_replay
    from sentinel_net.sensor.lifecycle import SensorLifecycle
    from sentinel_net.sensor.metrics import SensorMetrics

    monkeypatch.setattr(
        demo_replay, "PcapReplaySource", lambda *_: pytest.fail("source started without model")
    )
    with pytest.raises(ModelLoadError, match="MODEL_NOT_FOUND"):
        await demo_replay.run_replay(
            demo_replay.DemoReplayConfig(
                tmp_path / "none.pcap", "absent/1", model_registry=tmp_path
            ),
            None,
            None,
            SensorLifecycle(),
            SensorMetrics(),
        )


@pytest.mark.parametrize('failure', ['timestamp', 'dependency', 'checksum_inventory'])
def test_invalid_metadata_is_a_structured_failure(tmp_path, detector, failure):
    path = save_pipeline(tmp_path/'registry', detector)
    if failure == 'timestamp':
        reseal(path, created_at='not-a-time')
    elif failure == 'dependency':
        deps = versions(); deps['joblib'] = ''; reseal(path, dependencies=deps)
    else:
        checks = json.loads((path/'checksums.json').read_text())
        (path/'checksums.json').write_text(json.dumps(list(checks)))
    with pytest.raises(ModelLoadError):
        load(path)
