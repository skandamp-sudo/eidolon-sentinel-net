# EIDOLON // SENTINEL-NET — ML Architecture

## Overview

SENTINEL-NET uses a structured ML pipeline to detect cyber threats in passive network traffic. All models consume the canonical 52-feature schema and produce structured detection events with evidence.

## Feature Schema

**Authoritative source**: [`src/sentinel_net/features/schema.py`](../src/sentinel_net/features/schema.py)

- **52 features** — deterministic ordering, immutable tuple
- **Schema version**: 2.0.0
- **All features are metadata-only** — no payload content inspection
- Categories: basic flow metrics, directional counters, packet size statistics, inter-arrival time statistics, TCP flags, protocol identifiers, payload byte counts

### Feature Audit Summary

| Category | Count | ML Status |
|----------|-------|-----------|
| Safe for all models | 48 | Used by XGBoost, RF, LR |
| Nominal (protocol, ip_version) | 2 | Used by tree models, excluded from linear models |
| Redundant but retained | 4 | Retained in schema for telemetry, used by tree models |

See [`src/sentinel_net/detection/audit.py`](../src/sentinel_net/detection/audit.py) for the programmatic feature audit.

## Pipeline Architecture

```
FeatureVector (52 features)
    ↓
FeaturePreprocessor
    ├── Feature subset selection (tree: 52, linear: 50)
    ├── Inf → NaN replacement
    ├── SimpleImputer (median strategy)
    └── StandardScaler
    ↓
AnomalyDetector (Isolation Forest)
    ├── Trained on benign traffic only
    ├── Decision function → normalized [0,1] score
    └── NOT a calibrated probability
    ↓
ThreatClassifier (one of:)
    ├── XGBoostClassifier (primary)
    ├── RandomForestBaseline
    └── LogisticRegressionBaseline
    ↓
DetectionEvent
    ├── anomaly_result (score, is_anomalous)
    ├── threat_classification (label, confidence)
    ├── severity (configuration-driven)
    └── rationale (human-readable)
```

## Models

### Isolation Forest (Anomaly Detection)
- **Purpose**: Unsupervised anomaly detection
- **Training data**: Benign traffic only
- **Output**: Normalized anomaly score [0, 1]
- **NOT a probability** — scores are normalized decision function values
- **Deterministic**: Random seed recorded in model manifest

### XGBoost (Primary Classifier)
- **Purpose**: Multi-class threat classification
- **Training**: Supervised on labeled flows
- **Classes**: Mapped via `LabelMapper` to canonical `ThreatType` values
- **Binary case**: Uses `binary:logistic` objective
- **Multi-class case**: Uses `multi:softprob` with dynamic `num_class`
- **Output**: Per-class confidence scores (NOT calibrated probabilities)

### Random Forest Baseline
- **Purpose**: Baseline comparison for XGBoost
- **Output**: Per-class confidence scores

### Logistic Regression Baseline
- **Purpose**: Linear baseline (uses 50 features, excludes nominal)
- **Output**: Per-class confidence scores

## Leakage Prevention

1. **Preprocessing fitted only on training data** — validation/test transforms use already-fitted pipeline
2. **Scenario-aware splitting** — flows from same PCAP/scenario stay in one partition
3. **No test-set threshold tuning** — validation set used for threshold selection
4. **Dataset metadata never becomes a feature**
5. **Label isolation** — labels not leaked into feature computation

## Model Registry

- **Versioned artifacts** with SHA-256 checksum verification on load
- **Model manifest** records: training config, random seed, schema version, metrics, dependencies
- **Corrupted artifacts raise ValueError** — no silent loading of tampered models

## Evaluation Methodology

- Precision, recall, F1 (macro + weighted)
- Per-class metrics with FPR/FNR
- Confusion matrix
- ROC-AUC (anomaly detection, where applicable)
- **No fabricated metrics** — all metrics computed from actual model predictions

## Status

| Component | Status |
|-----------|--------|
| Feature schema (52) | ✅ Implemented |
| Preprocessing | ✅ Implemented |
| Isolation Forest | ✅ Implemented |
| XGBoost | ✅ Implemented |
| Random Forest | ✅ Implemented |
| Logistic Regression | ✅ Implemented |
| Model Registry | ✅ Implemented |
| Evaluation | ✅ Implemented |
| Probability Calibration | ❌ Not implemented |
| Hyperparameter Tuning | ❌ Not implemented |
| LightGBM | ❌ Not planned |
| Transformers | ❌ Not planned |
