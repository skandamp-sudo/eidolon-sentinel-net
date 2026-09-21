"""Immutable local deployment bundles using existing component artifact formats.

Checksums are integrity checks, not authentication. The local registry and
candidate locations must be operator-trusted. No remote loading or API writes.
"""

from __future__ import annotations
import hashlib
import importlib.metadata
import io
import json
import logging
import math
import os
from pathlib import Path
import platform
import re
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Literal

import joblib
import numpy as np
from pydantic import BaseModel, ConfigDict, ValidationError

from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import (
    XGBoostClassifier,
    RandomForestBaseline,
    LogisticRegressionBaseline,
)
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.detection.registry import ModelRegistry
from sentinel_net.detection.thresholds import ThresholdConfig
from sentinel_net.features.schema import FEATURE_SCHEMA, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)
CLASSIFIERS = {
    c.__name__: c for c in (XGBoostClassifier, RandomForestBaseline, LogisticRegressionBaseline)
}
ARTIFACTS = {"preprocessor.joblib", "classifier.joblib", "anomaly.joblib", "thresholds.json"}
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")


class ModelLoadError(ValueError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__(f"{code}: {detail}")


def fail(code, detail):
    raise ModelLoadError(code, detail)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def versions():
    return {
        "python": platform.python_version(),
        **{
            name: importlib.metadata.version(name)
            for name in ("numpy", "scipy", "scikit-learn", "xgboost", "joblib")
        },
    }


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    format_version: Literal["1.0.0"]
    status: Literal["candidate", "approved"]
    model_name: str
    model_version: str
    created_at: str
    training_seed: int | None
    classifier_type: str
    anomaly_model_type: Literal["AnomalyDetector"]
    threshold_policy_version: str
    feature_schema_version: str
    feature_names: list[str]
    feature_count: int
    feature_hash: str
    preprocessing_features: list[str]
    transformed_features: list[str]
    class_labels: list[str]
    dependencies: dict[str, str]
    dataset_identifier: str | None
    dataset_hash: str | None
    training_configuration_hash: str | None
    code_revision: str | None
    evaluation_reference: str | None
    approved_by: str | None
    approved_at: str | None
    artifacts: list[str]


def identity_parts(identity):
    if not isinstance(identity, str):
        fail("MODEL_NOT_FOUND", "Specify an approved model-name/version identity")
    parts = identity.split("/")
    if len(parts) != 2 or any(not TOKEN.fullmatch(p) or p in (".", "..") for p in parts):
        fail("MODEL_NOT_FOUND", "Expected model-name/version; paths and URLs are not accepted")
    return parts


def _read(path):
    if path.is_symlink() or not path.is_file():
        fail("MANIFEST_INVALID", "Bundle contains a missing file or symbolic link")
    try:
        return path.read_bytes()
    except OSError:
        fail("MANIFEST_INVALID", "Bundle file is not readable")


def _thresholds(data):
    try:
        value = json.loads(data)
        if set(value) != {"anomaly_threshold", "min_confidence", "severity_thresholds"}:
            raise ValueError()
        severity = value["severity_thresholds"]
        if set(severity) != {"low", "medium", "high", "critical"}:
            raise ValueError()
        numbers = [value["anomaly_threshold"], value["min_confidence"], *severity.values()]
        if any(
            type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in numbers
        ):
            raise ValueError()
        ordered = [severity[k] for k in ("low", "medium", "high", "critical")]
        if ordered != sorted(ordered):
            raise ValueError()
        return ThresholdConfig.from_dict(value)
    except Exception:
        fail(
            "THRESHOLD_CONFIGURATION_INVALID",
            "Expected finite score thresholds and ordered severity cutoffs",
        )


def _compatibility(manifest):
    if manifest.feature_schema_version != FEATURE_SCHEMA_VERSION or manifest.feature_count != len(
        FEATURE_SCHEMA
    ):
        fail("SCHEMA_MISMATCH", "Feature schema must be 2.0.0 with 52 features")
    if manifest.feature_names != list(FEATURE_SCHEMA):
        fail("FEATURE_ORDER_MISMATCH", "Exact canonical feature identity/order is required")
    if manifest.feature_hash != digest(encoded(list(FEATURE_SCHEMA))):
        fail("SCHEMA_MISMATCH", "Ordered feature hash does not match runtime")
    if (
        not manifest.preprocessing_features
        or len(set(manifest.preprocessing_features)) != len(manifest.preprocessing_features)
        or any(f not in FEATURE_SCHEMA for f in manifest.preprocessing_features)
    ):
        fail("PREPROCESSOR_INCOMPATIBLE", "Invalid preprocessing feature contract")
    runtime = versions()
    if set(manifest.dependencies) != set(runtime):
        fail("DEPENDENCY_INCOMPATIBLE", "Dependency inventory is incomplete")
    for name, current in runtime.items():
        saved = manifest.dependencies[name]
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9.+_-]*)", saved):
            fail("DEPENDENCY_INCOMPATIBLE", "Invalid recorded dependency version")
        if saved == current:
            continue
        # sklearn explicitly does not support cross-version persisted estimators;
        # XGBoost Python snapshots likewise are not portable model exports.
        if name in ("scikit-learn", "xgboost") or (
            name == "python" and saved.split(".")[0] != current.split(".")[0]
        ):
            fail(
                "DEPENDENCY_INCOMPATIBLE",
                f"{name} saved={saved}, runtime={current}; recreate the recorded environment",
            )
        logger.warning(
            "Bundle dependency difference (self-check required): %s saved=%s runtime=%s",
            name,
            saved,
            current,
        )


def _load_directory(directory, *, approved, expected=None):
    try:
        manifest_bytes = _read(directory / "manifest.json")
        manifest = Manifest.model_validate_json(manifest_bytes)
    except (ValidationError, ValueError, OSError) as exc:
        if isinstance(exc, ModelLoadError):
            raise
        fail("MANIFEST_INVALID", "Manifest is missing or does not match the bundle schema")
    try:
        identity_parts(manifest.model_name + "/" + manifest.model_version)
        if datetime.fromisoformat(manifest.created_at).tzinfo is None:
            raise ValueError()
        if manifest.approved_at and datetime.fromisoformat(manifest.approved_at).tzinfo is None:
            raise ValueError()
    except ValueError:
        fail("MANIFEST_INVALID", "Invalid identity or creation/approval timestamp")
    if expected and (manifest.model_name, manifest.model_version) != tuple(expected):
        fail("MANIFEST_INVALID", "Registry identity does not match manifest")
    if approved and (
        manifest.status != "approved"
        or not manifest.approved_by
        or not manifest.approved_by.strip()
        or not manifest.approved_at
        or not manifest.evaluation_reference
        or not manifest.evaluation_reference.strip()
    ):
        fail("MANIFEST_INVALID", "Runtime requires an explicitly approved publication")
    files = set(manifest.artifacts)
    if files not in (ARTIFACTS, ARTIFACTS | {"anomaly_explainer.joblib"}) or len(files) != len(
        manifest.artifacts
    ):
        fail("MANIFEST_INVALID", "Unexpected artifact inventory")
    try:
        checks = json.loads(_read(directory / "checksums.json"))
        if not isinstance(checks, dict) or set(checks) != files | {"manifest.json"}:
            raise ValueError()
    except (ValueError, OSError):
        fail("MANIFEST_INVALID", "Checksum inventory is invalid")
    # Deserialize only the exact bytes that passed verification, avoiding a
    # checksum/open race. Every payload and the manifest is checked first.
    payload = {"manifest.json": manifest_bytes, **{f: _read(directory / f) for f in files}}
    if any(
        not isinstance(checks[f], str) or digest(data) != checks[f] for f, data in payload.items()
    ):
        fail("CHECKSUM_MISMATCH", "Bundle integrity check failed before deserialization")
    _compatibility(manifest)
    thresholds = _thresholds(payload["thresholds.json"])
    if manifest.threshold_policy_version != "1.0.0" or manifest.classifier_type not in CLASSIFIERS:
        fail("MANIFEST_INVALID", "Unsupported classifier or threshold policy identity")
    try:
        pp = FeaturePreprocessor.load(io.BytesIO(payload["preprocessor.joblib"]))
        classifier = CLASSIFIERS[manifest.classifier_type].load(
            io.BytesIO(payload["classifier.joblib"])
        )
        anomaly = AnomalyDetector.load(io.BytesIO(payload["anomaly.joblib"]))
        explainer = (
            joblib.load(io.BytesIO(payload["anomaly_explainer.joblib"]))
            if "anomaly_explainer.joblib" in payload
            else None
        )
    except Exception:
        fail("MODEL_DESERIALIZATION_FAILED", "Verified artifacts could not be deserialized")
    if (
        not isinstance(pp, FeaturePreprocessor)
        or not pp.is_fitted
        or list(pp._feature_subset) != manifest.preprocessing_features
    ):
        fail(
            "PREPROCESSOR_INCOMPATIBLE",
            "Preprocessor is unfitted or uses a different feature subset/order",
        )
    try:
        x = pp.transform(np.zeros((1, len(FEATURE_SCHEMA)), dtype=np.float64))
        if (
            pp.output_feature_names != manifest.transformed_features
            or x.shape != (1, len(manifest.transformed_features))
            or not np.isfinite(x).all()
        ):
            raise ValueError()
        if list(pp._feature_indices) != [
            FEATURE_SCHEMA.index(f) for f in manifest.preprocessing_features
        ]:
            raise ValueError()
        if (
            x.shape[1] != classifier._model.n_features_in_
            or x.shape[1] != anomaly._model.n_features_in_
        ):
            raise ValueError()
    except Exception:
        fail(
            "PREPROCESSOR_INCOMPATIBLE",
            "Transformed dimensions/feature identities do not match fitted models",
        )
    try:
        if (
            not isinstance(anomaly, AnomalyDetector)
            or not anomaly.is_trained
            or not classifier.is_trained
        ):
            raise ValueError()
        if list(classifier.supported_classes) != manifest.class_labels:
            raise ValueError()
        labels = classifier.predict(x)
        scores = classifier.predict_scores(x)
        a = anomaly.score(x)
        if (
            len(labels) != 1
            or labels[0] not in manifest.class_labels
            or set(scores) != set(manifest.class_labels)
        ):
            raise ValueError()
        if (
            np.asarray(a).shape != (1,)
            or not np.isfinite(a).all()
            or not ((a >= 0) & (a <= 1)).all()
        ):
            raise ValueError()
        if any(
            np.asarray(v).shape != (1,)
            or not np.isfinite(v).all()
            or not ((v >= 0) & (v <= 1)).all()
            for v in scores.values()
        ):
            raise ValueError()
    except Exception:
        fail(
            "MODEL_DESERIALIZATION_FAILED",
            "Inference-contract self-check failed; no model activated",
        )
    pipeline = DetectionPipeline(pp, anomaly, classifier, thresholds, anomaly_explainer=explainer)
    pipeline.deployment_identity = {
        "model_name": manifest.model_name,
        "model_version": manifest.model_version,
        "feature_schema_version": manifest.feature_schema_version,
        "manifest_sha256": digest(manifest_bytes),
    }
    return pipeline, manifest


def load_bundle(registry, identity):
    parts = identity_parts(identity)
    root = Path(registry).resolve()
    directory = root.joinpath(*parts)
    if any(p.is_symlink() for p in (root / parts[0], directory)) or not directory.is_dir():
        fail("MODEL_NOT_FOUND", "Approved registry identity was not found")
    return _load_directory(directory, approved=True, expected=parts)[0]


def _seal(directory, manifest):
    (directory / "manifest.json").write_bytes(encoded(manifest))
    names = [*manifest["artifacts"], "manifest.json"]
    # Reuse the existing registry SHA-256 implementation without modifying it.
    (directory / "checksums.json").write_bytes(
        encoded({f: ModelRegistry._compute_checksum(directory / f) for f in names})
    )
    for name in [*names, "checksums.json"]:
        with (directory / name).open("rb") as handle:
            os.fsync(handle.fileno())


def write_candidate(
    pipeline,
    destination,
    *,
    name,
    version,
    training_seed=None,
    dataset_identifier=None,
    dataset_hash=None,
    training_configuration_hash=None,
    code_revision=None,
):
    identity_parts(name + "/" + version)
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("Candidate destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".candidate-", dir=destination.parent))
    try:
        pipeline.preprocessor.save(stage / "preprocessor.joblib")
        pipeline.classifier.save(stage / "classifier.joblib")
        pipeline.anomaly_detector.save(stage / "anomaly.joblib")
        (stage / "thresholds.json").write_bytes(encoded(pipeline.thresholds.to_dict()))
        artifacts = sorted(ARTIFACTS)
        if pipeline._anomaly_explainer is not None:
            joblib.dump(pipeline._anomaly_explainer, stage / "anomaly_explainer.joblib")
            artifacts.append("anomaly_explainer.joblib")
        manifest = Manifest(
            format_version="1.0.0",
            status="candidate",
            model_name=name,
            model_version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            training_seed=training_seed,
            classifier_type=type(pipeline.classifier).__name__,
            anomaly_model_type="AnomalyDetector",
            threshold_policy_version="1.0.0",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=list(FEATURE_SCHEMA),
            feature_count=len(FEATURE_SCHEMA),
            feature_hash=digest(encoded(list(FEATURE_SCHEMA))),
            preprocessing_features=list(pipeline.preprocessor._feature_subset),
            transformed_features=pipeline.preprocessor.output_feature_names,
            class_labels=list(pipeline.classifier.supported_classes),
            dependencies=versions(),
            dataset_identifier=dataset_identifier,
            dataset_hash=dataset_hash,
            training_configuration_hash=training_configuration_hash,
            code_revision=code_revision,
            evaluation_reference=None,
            approved_by=None,
            approved_at=None,
            artifacts=artifacts,
        ).model_dump()
        _seal(stage, manifest)
        _load_directory(stage, approved=False)
        if destination.exists():
            raise FileExistsError("Candidate destination already exists")
        stage.rename(destination)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def publish_candidate(candidate, registry, *, approved_by, evaluation_reference):
    if not approved_by.strip() or not evaluation_reference.strip():
        raise ValueError("Approval identity and evaluation reference are required")
    root = Path(registry).resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = root / ".publication-lock"
    lock.mkdir()  # Serialize publishers and reject concurrent overwrite attempts.
    stage = None
    try:
        _, manifest = _load_directory(Path(candidate), approved=False)
        if manifest.status != "candidate":
            fail("MANIFEST_INVALID", "Publication requires an unapproved candidate")
        target = root / manifest.model_name / manifest.model_version
        if target.parent.is_symlink() or target.exists():
            raise FileExistsError("Published identity already exists or is unsafe")
        target.parent.mkdir(exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".publication-", dir=target.parent))
        for name in manifest.artifacts:
            (stage / name).write_bytes(_read(Path(candidate) / name))
        # Revalidate the staged copy against the original checksums before approval.
        for name in ("manifest.json", "checksums.json"):
            (stage / name).write_bytes(_read(Path(candidate) / name))
        _, staged_manifest = _load_directory(stage, approved=False)
        if staged_manifest != manifest:
            fail("CHECKSUM_MISMATCH", "Candidate changed during publication")
        data = manifest.model_dump()
        data.update(
            status="approved",
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc).isoformat(),
            evaluation_reference=evaluation_reference,
        )
        _seal(stage, data)
        _load_directory(stage, approved=True)
        stage.rename(target)
        return manifest.model_name + "/" + manifest.model_version
    finally:
        if stage and stage.exists():
            shutil.rmtree(stage)
        lock.rmdir()
