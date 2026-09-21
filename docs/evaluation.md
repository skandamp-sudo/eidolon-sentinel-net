# Evaluation Methodology

## EIDOLON // SENTINEL-NET — Phase 7

### Overview

Phase 7 provides a scientific evaluation framework for Sentinel-NET's
detection capabilities. It explicitly distinguishes between:

| Result Category | Meaning |
|----------------|---------|
| **SOFTWARE TEST** | Validates implementation correctness using synthetic fixtures |
| **SYNTHETIC ROBUSTNESS TEST** | Controlled perturbations on synthetic data |
| **SCIENTIFIC EXPERIMENT** | Evaluation on real datasets with locked protocol |
| **REAL-DATA EVALUATION** | Results from CICIDS2017 / UNSW-NB15 |

Synthetic fixtures can validate implementation correctness.
They must NOT be presented as evidence of real-world detection performance.

### Evaluation Protocol

The evaluation follows a locked protocol:

```
OPEN
  │
  ├─ register dataset split
  │   (verify train/val/test disjoint by samples AND scenarios)
  │
  ▼
THRESHOLD_LOCKED
  │
  ├─ threshold selected on VALIDATION data only
  │   (source: 'default' or 'validation_optimized')
  │
  ▼
FINAL_EVALUATED
  │
  ├─ metrics computed on FINAL TEST exactly once
  │   (no configuration changes permitted after this point)
```

**FINAL TEST is immutable after evaluation begins.**

Before FINAL_TEST:
- threshold must be locked
- model selection must be locked
- feature selection must be locked
- preprocessing must be locked
- hyperparameters must be locked

After FINAL_TEST:
- NO changes based on final-test results
- If a change is required: create a new evaluation version

### Score Type Discipline

**ANOMALY SCORE ≠ CLASSIFICATION SCORE ≠ CONFIDENCE SCORE ≠ PROBABILITY ≠ SECURITY SEVERITY**

| Model | Score Type | Calibration |
|-------|-----------|-------------|
| Isolation Forest | Anomaly score | NOT APPLICABLE |
| XGBoost | Classification score | May be evaluated |
| Random Forest | Classification score | May be evaluated |
| Logistic Regression | Classification score | Typically better calibrated |

Isolation Forest anomaly scores are NEVER treated as probabilities.
Brier score and ECE are not computed for anomaly scores.

### Threshold Configuration

The default anomaly threshold (0.5) is a **DESIGN/EVALUATION LIMITATION**,
not a software defect.

The `ThresholdOptimizer` provides validation-based threshold search as an
evaluation capability. Both default and validation-optimized thresholds
are reported for comparison.

### Experiments

#### Model Comparison
Trains and evaluates all 4 models on identical partitions.

#### Class Imbalance Analysis
Per-class counts, proportions, precision, recall, F1.

#### False Positive / False Negative Analysis
Structured collection with feature deviations, NOT causal explanations.

#### Simulated Unidirectional Feature Ablation
Simulates loss of reverse-direction telemetry by zeroing features.
**NOT equivalent to real unidirectional observation.**

#### Feature Group Ablation
Measures model dependence on feature groups.
**Does NOT prove causal importance.**

#### Controlled Robustness Experiments
Perturbation sensitivity analysis.
**Does NOT represent real attackers.**

#### Calibration Analysis
Brier score, ECE, reliability diagrams — only for classification models.

#### Cross-Scenario Holdout
Leave-one-scenario-out evaluation.

#### Model Stability
Multi-seed evaluation for variance analysis.

#### Out-of-Distribution Analysis
Synthetic OOD samples — high anomaly score means "novel", not "malicious".

#### Failure Taxonomy
10-category evidence-based failure classification (F1–F10).

### Statistical Claims

Confidence intervals and statistical tests require sufficient sample size.
If insufficient: "Insufficient sample size for reliable statistical inference."

No manufactured significance.

### Dataset Adapters (Phase 7)

Real-data evaluation uses adapters to transform external datasets to the
Sentinel-NET 52-feature schema.

| Dataset | Adapter | Available Features | Missing |
|---------|---------|-------------------|---------|
| CICIDS2017 | `CICIDSAdapter` | 41/52 (29 direct + 12 derived) | 11 |
| UNSW-NB15 | `UNSWAdapter` | 17/52 (6 direct + 8 derived + 3 proxy) | 35 |

See [dataset_adapters.md](dataset_adapters.md) and
[feature_availability.md](feature_availability.md) for full matrices.

**CICIDS2017** is the primary evaluation dataset. 79% feature coverage is
sufficient for meaningful evaluation with documented caveats for the 11
missing features (imputed to training median by the preprocessor).

**UNSW-NB15** has only 33% feature coverage. Direct model evaluation is
NOT scientifically valid for CICIDS-trained models. Possible future paths:

- UNSW-specific model trained on the 17-feature subset
- Common feature subset analysis (if methodologically defensible)
- Documentation-only limitation

**Cross-dataset generalization** cannot be claimed unless feature
compatibility is demonstrated. Different feature extraction tools
(CICFlowMeter vs Argus/Bro) produce fundamentally different feature spaces.

### Model Compatibility Warning

Models trained on Sentinel-NET PCAP-extracted features had real values for
all 52 features. When evaluated on CICIDS2017 data:

- 11 features are NaN → imputed to training median
- These features become constant → zero discriminative signal
- If these features were important to the trained model, evaluation
  metrics will be systematically degraded (not a model defect)

This is a **DATASET LIMITATION**, not a model defect.

