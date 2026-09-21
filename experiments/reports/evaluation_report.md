# EIDOLON // SENTINEL-NET — Evaluation Report
**Data source**: SYNTHETIC VALIDATION (software test — not scientific evidence)
**Dataset**: synthetic_validation
**Timestamp**: 2026-09-01T16:23:27.917073+00:00
**Feature schema**: v2.0.0 (52 features)

## Abstract
This report documents evaluation framework validation using synthetic fixtures. Results demonstrate implementation correctness and do NOT constitute scientific evidence of real-world detection performance. Real-data evaluation requires CICIDS2017 or UNSW-NB15 datasets.

## Model Comparison
**Result category**: software_test
### xgboost
- F1 Macro: 0.4898
- F1 Weighted: 0.9796
- Precision Macro: 0.5000
- Recall Macro: 0.4800
### random_forest
- F1 Macro: 0.4897
- F1 Weighted: 0.9795
- Precision Macro: 0.5000
- Recall Macro: 0.4800
### logistic_regression
- F1 Macro: 0.4897
- F1 Weighted: 0.9795
- Precision Macro: 0.5000
- Recall Macro: 0.4800

## Threshold Sensitivity
**Result category**: software_test
### Default Threshold
- Threshold: 0.5
- Precision: 1.0
- Recall: 0.19
- F1: 0.31932773109243695
- ROC-AUC: undefined

## Calibration
**Result category**: software_test
### isolation_forest
**NOT APPLICABLE**: Model 'isolation_forest' produces ANOMALY SCORES, not probabilities. Calibration analysis (Brier score, ECE, reliability diagrams) is mathematically inapplicable to anomaly scores.
### xgboost
- Brier Score: 0.011895634506871281
- ECE: 0.02638034462928772
### random_forest
- Brier Score: 0.017405
- ECE: 0.1077
### logistic_regression
- Brier Score: 0.009256002154429888
- ECE: 0.02835896571212557

## Failure Taxonomy
**Result category**: software_test
- Total failures: 4
- False positives: 0
- False negatives: 4

| Code | Description | Count |
|------|-------------|-------|
| F1 | Feature representation limitation | 0 |
| F10 | Explanation limitation | 0 |
| F2 | Insufficient directional visibility | 0 |
| F3 | Threshold limitation | 4 |
| F4 | Dataset bias | 0 |
| F5 | Model instability | 0 |
| F6 | Class imbalance | 0 |
| F7 | Out-of-distribution behaviour | 0 |
| F8 | Label ambiguity | 0 |
| F9 | Flow reconstruction limitation | 4 |

## Out-of-Distribution Analysis
**Result category**: synthetic_robustness_test
- Total OOD samples: 25
- Flagged anomalous: 0
- Mean anomaly score: 0.38954648357241595

> SYNTHETIC ROBUSTNESS TEST. These samples are crafted inputs, not real traffic. Results indicate detector behaviour on out-of-distribution patterns, not real-world OOD performance.

## Limitations
### Known Limitations
1. **Unidirectional observation**: Sentinel-NET observes passive, potentially unidirectional traffic. Reverse-direction information may be absent, degrading detection of bidirectional attack patterns.
2. **No payload inspection**: All 52 features are metadata-only. Encrypted payload contents are never inspected.
3. **Default thresholds**: The anomaly threshold (0.5) is a design default, not validation-optimized. This is a design/evaluation limitation, not a software defect.
4. **Class imbalance**: Baseline models do not use class weighting. On imbalanced datasets, models may be biased toward the majority class.
5. **Score interpretation**: XGBoost/RF classification scores are NOT calibrated probabilities. Isolation Forest produces anomaly scores, not probabilities.

### Data Limitation
All results in this report are from synthetic fixtures. They validate implementation correctness but do NOT constitute scientific evidence of real-world detection performance. Real-data evaluation requires CICIDS2017 or UNSW-NB15 datasets.
