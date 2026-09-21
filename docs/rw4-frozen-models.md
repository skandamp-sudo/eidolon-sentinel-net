# RW-4 — frozen deployment models

Sensor and replay now require an explicitly approved local bundle. Both perform inference only. Training is an offline operator action. No production model was trained or scientifically revalidated in this phase.

## 1–3. Format, registry and manifest

`SENTINEL_MODEL_REGISTRY` selects the trusted local root (default `models/registry`). Runtime `--model` accepts exactly `model-name/version`, not a filesystem path or URL. Identities resolve to:

```text
models/registry/<model-name>/<version>/
  manifest.json
  checksums.json
  preprocessor.joblib
  classifier.joblib
  anomaly.joblib
  thresholds.json
  anomaly_explainer.joblib  # optional fitted statistical baseline
```

The existing component save/load formats and `ModelRegistry._compute_checksum` are reused. Label encoding/mapping lives in the existing classifier artifact; the manifest records the ordered class labels too. The protected generic registry was not modified.

The strict manifest (`deployment.bundle.Manifest`, format 1.0.0) records:

- Candidate/approved status, model name/version, UTC creation time, training seed, classifier type, anomaly type, threshold-policy version.
- Schema version, exact ordered feature names/count/hash, preprocessing subset/order, transformed feature names and class labels.
- Python, NumPy, SciPy, scikit-learn, XGBoost and joblib versions.
- Dataset identifier/hash, training-configuration hash, source revision and evaluation reference. Unknown historical values are explicitly `null`.
- Artifact inventory, approver and UTC approval timestamp. Approval fields remain null on candidates.

SHAP remains optional under the existing evidence contract. It is not required to produce scores and is not made a mandatory artifact dependency. Its availability can affect classifier explanations; statistical evidence and explanation-unavailable reasons remain distinct.

## 4–5. Integrity and compatibility

Every artifact and `manifest.json` has a SHA-256 entry in `checksums.json`. The checksum file is the integrity index, not a signature or a self-authenticating trust root. All payloads are read and verified before any joblib load; deserialization uses those exact verified bytes in memory. Files and identity directories cannot be symlinks. Only operator-trusted local registry/candidate locations are supported.

The loader validates manifest shape, identity/approval, complete checksum inventory, artifact digests, schema 2.0.0, all 52 names in exact canonical order, deterministic ordered-feature hash and preprocessing contract. It never reorders features. Dependency checks precede deserialization.

For the retained joblib formats, scikit-learn and XGBoost must match exactly: scikit-learn does not support cross-version persisted estimators, and XGBoost Python memory snapshots lack cross-version compatibility guarantees. This is a deliberately conservative policy for those executable snapshot formats, including patch releases; it is not a claim that every patch difference necessarily breaks an artifact. See [scikit-learn model persistence](https://scikit-learn.org/stable/model_persistence.html) and [XGBoost model versus memory-snapshot compatibility](https://xgboost.readthedocs.io/en/stable/tutorials/saving_model.html). Other recorded version differences are reported and checked through loading/self-check; Python major differences fail. No guessed NumPy/SciPy/joblib minor-version compatibility matrix is imposed.

After loading, a zero-valued 52-column input checks preprocessing identities/dimensions, fitted model dimensions, label output, classifier-score structure and finite classifier/anomaly scores within the existing 0–1 contract. The bundle becomes active only if the entire load succeeds. This checks artifact compatibility, not accuracy or the safety of traffic.

## 6. Offline training, evaluation and publication

```sh
export SENTINEL_MODEL_REGISTRY=/trusted/local/sentinel-registry

sentinel-net model train \
  --dataset /trusted/local/CICIDS2017 \
  --output /trusted/local/candidates/cicids2017-v1 \
  --name cicids2017 --version 1.0.0

# Evaluate this exact candidate separately and retain an evaluation report.
# Only after an operator reviews that report:
sentinel-net model publish \
  --candidate /trusted/local/candidates/cicids2017-v1 \
  --approved-by '<operator-identity>' \
  --evaluation-reference '<reference-to-reviewed-candidate-evaluation>'
```

Training retains the previous replay-training recipe (seed 42, existing preprocessing, XGBoost, benign-only Isolation Forest and statistical baseline); it does not optimize accuracy. `--dataset-hash` and `--code-revision` can record known provenance. The CLI records its training configuration hash. Do not supply guessed provenance.

Training creates a **candidate**, never an approved runtime model. Evaluation remains a separate scientific operation; `publish` records an explicit operator attestation and reference, not automated proof that the referenced evaluation is valid or passed. Existing historical experiment reports must not be represented as evaluation of a new candidate.

Publication validates, stages inside the registry filesystem, verifies the staged copy, adds approval metadata, regenerates checksums, revalidates, then atomically renames into the final identity. A publication lock serializes publishers. Existing versions are rejected. Interrupted staging cannot resolve as a runtime identity; failure cleanup removes the current staging directory. An abrupt process death may leave a lock/staging directory: an operator must establish that no publisher is running before cleaning it. Immutability is enforced by the publisher; OS access controls must protect the registry from independent writers. Checksums do not protect against a malicious writer who can replace the whole bundle and index.

## 7–8. Sensor and replay startup

```sh
# Configure SENTINEL_API_KEY privately; never put it in event metadata.
sentinel-net sensor --interface en0 --model cicids2017/1.0.0
sentinel-net replay --pcap /trusted/local/capture.pcap --model cicids2017/1.0.0
# Optional recorded timing:
sentinel-net replay --pcap /trusted/local/capture.pcap \
  --model cicids2017/1.0.0 --realtime --speed 2
```

Sensor: configuration/interface validation → approved model resolution/verification/self-check → storage/output → capture → RUNNING. Model failure occurs before storage or capture initializes. Replay CLI similarly validates the model before API/storage lifespan startup, then hands the loaded object to the shared replay worker. Direct replay calls use the same loader. `--dataset` was removed from replay; runtime has no fallback trainer, model download or version substitution.

These commands supersede the historical path-based examples in the RW-2 report and the legacy training description in the RW-3 report. Old generic full-pipeline artifacts are not silently migrated or approved. An operator can explicitly package an already-fitted pipeline with `write_candidate`, preserving unknown provenance as null, then separately review/publish it.

## 9–10. Failures and event provenance

`ModelLoadError` exposes: `MODEL_NOT_FOUND`, `MANIFEST_INVALID`, `CHECKSUM_MISMATCH`, `SCHEMA_MISMATCH`, `FEATURE_ORDER_MISMATCH`, `PREPROCESSOR_INCOMPATIBLE`, `MODEL_DESERIALIZATION_FAILED`, `THRESHOLD_CONFIGURATION_INVALID`, `DEPENDENCY_INCOMPATIBLE`. No error is converted into a detection, benign score or training request. Sensor startup preserves the structured model failure code; operational health does not expose local paths.

New runtime events include `model_name`, `deployment_model_version`, `feature_schema_version` and `model_manifest_sha256`, with the same small identity in `metadata.deployment_model`. The existing `model_version` remains the classifier component version for backward compatibility; it is not relabeled as a deployment version. REST, persistence and WebSocket share the same record. Historical deployment identity is null when unavailable. Status exposes the loaded identity and, for live mode, the capture interface. It exposes no registry path or training manifest.

## 11–18. Changes and verification

The machine-readable changed-file list is [rw4-ui-changed-files.json](rw4-ui-changed-files.json). Deployment implementation: `deployment/bundle.py`, `deployment/training.py`, `sensor/runtime_model.py`; integration: configuration, CLI, SensorService, replay, shared packet pipeline, event record and status schema/route. Scientific source files were not edited.

Focused bundle tests cover checksums before deserialization for all four required payloads plus manifest, invalid/missing/unsafe identities, schema/count/hash/order, preprocessing dimensions, invalid labels, unapproved bundles, invalid metadata/dependency inventory, verified-but-corrupt serialization, unfitted components, thresholds, dependency policy, immutable publication and incomplete publication cleanup. Missing sensor/replay models fail before capture/source activation. Tests patch fitting/training methods to fail if called during load/runtime and inspect runtime modules for training calls/imports.

Real-model integration tests now publish/load approved fixtures before unmocked inference, SQLite, authenticated REST and WebSocket checks. Event identity is preserved and local paths are absent. The seven parity cases load the same frozen XGBoost/Isolation Forest bundle: FIN, RST, idle expiry, tuple reuse, EOF/shutdown, capacity eviction and out-of-order timestamps. Canonical vectors, flow content, scores and event/evidence content match across live and replay, excluding intentionally per-run IDs/timestamps/source labels.

Final gates:

| Gate | Result |
|---|---|
| Backend | 631 passed, 14 warnings |
| Frontend | 61 passed across 5 files |
| TypeScript strict | PASS |
| Production build | PASS |
| Live/replay frozen-model parity | 7/7 scenarios PASS |
| Protected scientific files | 23/23 byte-identical to RW-3 / RW-2 |
| Feature schema | 52 features, exact order, 2.0.0 unchanged |

See [SHA-256 inventory](rw4-scientific-integrity.json). Test fixtures use small synthetic datasets solely for artifact/runtime contract checks. They are not deployment-ready trained models or scientific evaluations. The 14 backend warnings are existing upstream/deprecation warnings, not test failures.

## 19–22. Operator limits and recommendation

The commands above illustrate local training, explicit approval/publication and inference-only operation. No production bundle is supplied. No real capture interface, kernel drop accounting, sustained throughput or scientific accuracy was validated. Native capture/model calls retain their existing cancellation/resource limits; unbounded per-flow histories and retention scheduling remain future work. Exact-version snapshot loading requires retaining the recorded environment. Optional SHAP explanations can remain unavailable.

RW-1 corrected flow segmentation. Historical metrics remain historical until the corrected runtime and approved model are scientifically rerun; this phase makes no claim of reproducing those metrics.

Recommended RW-5: controlled real-interface validation, resource-bound/retention hardening and sustained-load measurements, followed by explicit scientific revalidation before making accuracy or deployment-readiness claims. Nothing from RW-5 was implemented here.

Git recommendation: first preserve the previously uncommitted RW-1–RW-3/product work as a reviewed baseline. Then stage the RW-4 files selectively with commit message `feat: load approved immutable models for sensor and replay`; stage SOC polish separately as `ui: refine SOC hierarchy and responsive operation`. Do not use `git add .`: unrelated presentations, assets and earlier work exist. No commit, branch change or publication was performed.

**GO FOR RW-5** — frozen deployment, fail-closed behavior, score parity and regression gates pass. The engineering gates support the next phase; they do not establish production readiness. Work stops after the separately requested UI polish.
