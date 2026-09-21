# EIDOLON // SENTINEL-NET — Explainability

## Overview

The explainability subsystem provides structured evidence, human-readable rationale, and MITRE ATT&CK mapping for detection events. It is designed to be transparent about limitations and never claims causal explanations from statistical evidence.

## Key Principles

1. **A model explanation is NOT a causal explanation** — we say "Feature X contributed to the model decision", never "Feature X caused the attack"
2. **Evidence types are semantically honest**:
   - `evidence_type="model"`: Contribution derived from model's decision mechanism (SHAP values)
   - `evidence_type="statistical"`: Deviation from training distribution (z-scores)
   - `evidence_type="heuristic"`: Rule-based or threshold-based evidence
3. **SHAP is optional** — core detection works without it
4. **Limitations are always stated** — encrypted payload disclaimer in every rationale
5. **No fabricated explanations** — every evidence item traces to actual FeatureVector data

## Architecture

```
DetectionEvent
    ↓
ExplainableDetection
    ├── classifier_evidence (EvidenceCollection)
    │   └── SHAP TreeExplainer → Evidence[evidence_type="model"]
    ├── anomaly_evidence (EvidenceCollection)
    │   └── AnomalyExplainer → Evidence[evidence_type="statistical"]
    ├── rationale (human-readable string)
    │   └── RationaleGenerator
    └── attack_mappings (ATTACKMapping[])
        └── ATTACKMapper
```

## Components

### Evidence Model (`explainability/evidence.py`)

Each `Evidence` item contains:

| Field | Description |
|-------|-------------|
| `feature_name` | Name from canonical FEATURE_SCHEMA |
| `observed_value` | Actual value from FeatureVector |
| `reference_value` | Baseline (training mean). None if unavailable |
| `contribution` | Numerical contribution to decision |
| `direction` | "increase" or "decrease" |
| `evidence_type` | "model", "statistical", or "heuristic" |
| `source` | What generated this evidence |
| `model_name` | Model that produced this evidence |
| `model_version` | Model version |
| `feature_schema_version` | Schema version |

`EvidenceCollection` provides:
- `top_k` — top 5 by |contribution|
- `model_evidence` / `statistical_evidence` — filtered views
- `unavailable()` — graceful degradation when explanation unavailable

### SHAP Explainer (`explainability/shap_explainer.py`)

- **Optional dependency**: Requires `shap>=0.43`
- **Lazy import**: SHAP is only imported when `explain()` is called
- **Graceful degradation**: Returns `EvidenceCollection.unavailable()` if SHAP not installed
- **Supports**: XGBoost and Random Forest via `shap.TreeExplainer`
- **evidence_type**: "model" (genuine Shapley values)

Install: `pip install sentinel-net[explainability]`

### Anomaly Explainer (`explainability/anomaly_explainer.py`)

- **No SHAP required** — uses statistical deviation (z-scores)
- Computes per-feature z-score against training distribution
- Reports features with |z| > threshold (default: 2.0)
- **evidence_type**: "statistical" (NOT "model")
- Does NOT claim these are Isolation Forest feature contributions
- Configurable z-threshold

### Rationale Generator (`explainability/rationale.py`)

Template structure:
```
THREAT: Possible DDoS Attack
ANOMALY SCORE: 0.93
MODEL: xgboost (confidence: 0.87)
EVIDENCE:
  - elevated average packet size (contribution: 0.450)
  - average inter-arrival time significantly below baseline (z-score: 3.5)
POTENTIAL ATT&CK TECHNIQUES:
  - T1498 Network Denial of Service (Impact) — likely
LIMITATION: Classification is based on observable network metadata only.
Encrypted payload contents are not inspected. This is a model classification,
not a confirmed attack.
```

Language rules:
- Uses "possible", "suspicious", "model classified"
- Never says "confirmed attack" unless independently verified
- Always includes encrypted-payload limitation

## Limitations

- SHAP explanations are model-level, not causal
- Anomaly explanations are distributional, not model-specific
- Isolation Forest does not natively support per-feature attribution
- Statistical deviation may highlight features unrelated to model decision
- Explanations assume training distribution is representative of "normal"
