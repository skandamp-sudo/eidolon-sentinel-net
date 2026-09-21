# Known Limitations

## EIDOLON // SENTINEL-NET

### Observation Model

1. **Passive observation only.** Sentinel-NET passively observes network traffic.
   It does not inject, modify, or retransmit packets. It does not perform active
   scanning, probing, or exploitation.

2. **Unidirectional traffic.** The sensor may observe only one direction of a
   conversation. Reverse-direction features (reverse_packets, reverse_bytes,
   rev_iat_*, fwd_rev_*_ratio, reverse_payload_bytes) may be zero or absent.
   This degrades detection of attack patterns that require bidirectional
   observation (e.g., distinguishing C2 from legitimate HTTPS).

3. **No payload inspection.** All 52 features are network metadata.
   Encrypted payload contents are never inspected. Attacks that are only
   distinguishable by payload (e.g., SQL injection, XSS) cannot be detected
   by metadata-only features.

### ML Pipeline

4. **Default threshold.** The anomaly threshold (0.5) is a design default,
   not validation-optimized. This is a design/evaluation limitation,
   not a software defect. The `ThresholdOptimizer` provides validation-based
   search for experimental comparison.

5. **No class weighting.** Baseline classifiers (RF, LogReg) do not use
   `class_weight='balanced'`. On highly imbalanced datasets (e.g., CICIDS2017),
   models may be biased toward the majority class (benign).

6. **Score interpretation.** XGBoost/RF classification scores are NOT
   calibrated probabilities. Isolation Forest produces anomaly scores,
   not probabilities. These are distinct mathematical quantities and
   must not be silently converted.

7. **Hardcoded hyperparameters.** Model hyperparameters are hardcoded defaults.
   No automated tuning (GridSearchCV, RandomizedSearchCV) is implemented.

### Evaluation

8. **Dataset dependence.** All training and evaluation use CICIDS2017 and/or
   UNSW-NB15. Results may not generalize to other network environments,
   traffic patterns, or attack types.

9. **Synthetic validation.** The evaluation framework validates implementation
   correctness using synthetic fixtures. These are software tests, not
   scientific evidence of real-world detection performance.

10. **ATT&CK mapping.** ATT&CK technique mappings are heuristic rules based
    on threat classification output. They represent potential applicability,
    not confirmed attribution.

11. **No adversarial robustness guarantee.** Perturbation tests are controlled
    sensitivity experiments, not real adversarial attacks. No guarantee is
    made against motivated adversaries.

### Operational

12. **No production readiness claim.** Sentinel-NET is a research/prototype
    system. It has not undergone production security audit, load testing,
    or operational hardening.

13. **SQLite storage.** Event storage uses SQLite. This is appropriate for
    prototype/research use but not for high-throughput production deployment.

14. **No Docker.** The system runs directly on the host. No containerization
    is provided or claimed.
