# FINAL-SCIENCE-RESTART-2 scientific report

**SINGLE-SEED REPRODUCIBILITY RUN**. All metrics below identify a fixed explicit CICIDS2017 scenario partition and the exact local candidate. No automatic approval/publication occurred. F3/F4/F5 contextual evidence is excluded from ML inputs and metrics.

## Measured primary results

| Model | Test rows | Accuracy | Macro precision | Macro recall | Macro F1 | Weighted precision | Weighted recall | Weighted F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| XGBoost | 397302 | 0.759440 | 0.367940 | 0.253151 | 0.267512 | 0.891085 | 0.759440 | 0.753750 |
| RandomForest | 397302 | 0.727761 | 0.367533 | 0.233440 | 0.240875 | 0.890392 | 0.727761 | 0.710847 |
| LogisticRegression | 397302 | 0.877398 | 0.367203 | 0.327363 | 0.338871 | 0.890550 | 0.877398 | 0.868414 |

Macro averages use the union of true/predicted labels under the existing report API, which can include predicted classes with zero true support. Full zero-support rows are retained in the CSV; their recall convention is not an observed performance estimate.

## XGBoost per-class results

| Class | Support | Precision | Recall | F1 | One-vs-rest FPR | One-vs-rest FNR |
|---|---:|---:|---:|---:|---:|---:|
| benign | 267851 | 0.847574 | 0.998970 | 0.917066 | 0.371724 | 0.001030 |
| brute_force | 0 | 0.000000 | 0.000000 | 0.000000 | 0.000003 | 0.000000 |
| c2 | 1437 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.000000 |
| ddos | 128014 | 0.992127 | 0.266783 | 0.420495 | 0.001006 | 0.733217 |
| exfiltration | 0 | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable |
| other | 0 | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable |
| reconnaissance | 0 | 0.000000 | 0.000000 | 0.000000 | 0.118759 | 0.000000 |

## Historical comparison

| Model / metric | Historical | Current | Delta | Comparable? | Reason |
|---|---:|---:|---:|---|---|
| XGBoost / accuracy | 0.759440 | 0.759440 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / precision_macro | 0.367940 | 0.367940 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / recall_macro | 0.253151 | 0.253151 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / f1_macro | 0.267512 | 0.267512 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / precision_weighted | 0.891085 | 0.891085 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / recall_weighted | 0.759440 | 0.759440 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| XGBoost / f1_weighted | 0.753750 | 0.753750 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / accuracy | 0.727761 | 0.727761 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / precision_macro | 0.367533 | 0.367533 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / recall_macro | 0.233440 | 0.233440 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / f1_macro | 0.240875 | 0.240875 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / precision_weighted | 0.890392 | 0.890392 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / recall_weighted | 0.727761 | 0.727761 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| RandomForest / f1_weighted | 0.710847 | 0.710847 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / accuracy | 0.877398 | 0.877398 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / precision_macro | 0.367203 | 0.367203 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / recall_macro | 0.327363 | 0.327363 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / f1_macro | 0.338871 | 0.338871 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / precision_weighted | 0.890550 | 0.890550 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / recall_weighted | 0.877398 | 0.877398 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| LogisticRegression / f1_weighted | 0.868414 | 0.868414 | +0.000000 | NOT DIRECTLY COMPARABLE | Historical identity not equivalently bound |
| IsolationForest c2 / ROC-AUC | 0.716983 | 0.598615 | -0.118368 | NO | Different fixed-test cohort |
| IsolationForest ddos / ROC-AUC | 0.887234 | 0.821679 | -0.065556 | NO | Different fixed-test cohort |

## Anomaly operating points — exploratory

| Protocol | Threshold | Precision | Recall | F1 | Test FPR |
|---|---:|---:|---:|---:|---:|
| validation_f1 | 0.400000 | 0.560005 | 0.975751 | 0.711605 | 0.370516 |
| default | 0.500000 | 0.395771 | 0.180570 | 0.247994 | 0.133235 |
| validation_benign_fpr_0.01 | 0.631513 | 0.500955 | 0.085129 | 0.145528 | 0.040985 |
| validation_benign_fpr_0.05 | 0.541500 | 0.502264 | 0.168821 | 0.252703 | 0.080855 |

## Held-out attack-family evaluation — limited

| Family | Train rows excluded | Test attack rows | ROC-AUC | PR-AUC | Validation target FPR | Achieved validation FPR | Test FPR | Test recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| c2 | 0 | 1437 | 0.598615 | 0.006128 | 0.01 | 0.010008 | 0.040985 | 0.000000 |
| c2 | 0 | 1437 | 0.598615 | 0.006128 | 0.05 | 0.050001 | 0.080855 | 0.028532 |
| ddos | 193756 | 128014 | 0.821679 | 0.543738 | 0.01 | 0.010021 | 0.041015 | 0.081874 |
| ddos | 193756 | 128014 | 0.821679 | 0.543738 | 0.05 | 0.050001 | 0.080780 | 0.169458 |

## Perturbation sensitivity — simulated, first 10,000 test rows

| Perturbation | Changed predictions | Prediction-change percentage |
|---|---:|---:|
| timing_jitter | 57 | 0.5700% |
| packet_size_noise | 0 | 0.0000% |
| duration_perturbation | 0 | 0.0000% |
| directional_imbalance | 0 | 0.0000% |
| metadata_dropout | 54 | 0.5400% |

## XGBoost confidence and dominant confusions

MODEL CONFIDENCE SCORE quantiles (min, 25%, 50%, 75%, 95%, max): `[0.46902310848236084, 0.9975408315658569, 0.9998045563697815, 0.9999799728393555, 0.9999878406524658, 0.9999903440475464]`. No calibration established.

- benign misclassifications: `{"brute_force": 1, "ddos": 271, "reconnaissance": 4}`.
- c2 misclassifications: `{"benign": 1437}`.
- ddos misclassifications: `{"benign": 46683, "reconnaissance": 47179}`.

Zero-support recall/FNR: NOT MEANINGFUL. **NO PRIMARY-TEST RECONNAISSANCE SUPPORT.** Exfiltration has only 36 training examples and zero test support: meaningful exfiltration accuracy is not established.

## Requested 37-point disposition

1. **Dataset identity — MEASURED.** Eight independently rehashed CICIDS2017 parquet files, 2,313,810 rows. Exact file hashes/schemas, row-level adapter mapping, scenario and label counts are in the environment artifact.
2. **Split identity — VERIFIED ENGINEERING PROPERTY.** Manifest SHA-256 `488af9eab1cd0d6a4e70d5242d55e909c6dd41de90b88aca6195e21d9ac275d5`. Only explicit_manifest_split was used; exact assignment/identity/coverage/no overlap/counts validated.
3. **Partition counts — MEASURED.** TRAIN 1,760,688; VALIDATION 155,820; TEST 397,302.
4. **Class distributions — MEASURED.** `{"test": {"benign": 267851, "c2": 1437, "ddos": 128014}, "train": {"benign": 1555790, "brute_force": 9150, "ddos": 193756, "exfiltration": 36, "reconnaissance": 1956}, "validation": {"benign": 153677, "other": 2143}}`.
5. **Real-data preprocessing — VERIFIED.** 11 all-missing canonical columns retained as NaN before imputation; TRAIN-only fitting yields tree 41 / linear 40 surviving columns. Names, actual width and n_features_out agree. is_icmp is constant. Ordered names and all mappings are recorded.
6. **Candidate identity.** Scientific manifest `experiments/final_science_restart_2/scientific-candidate-manifest.json`, SHA-256 `29898386acd94ec2e8641947cafeeedbde2363f82195eddcad9baf95d55e9573`. CANDIDATE, NOT APPROVED, NOT PUBLISHED. It binds all supervised artifacts and anomaly/preprocessor artifacts, with a loader-compatible XGBoost deployment component bundle. Fixed TRAIN-vector loaded-candidate parity passes.
7. **Training configuration.** Seed42, fixed partition, established XGBoost100/depth6, RF100, LR lbfgs/max_iter1000, IF100 benign-only. Complete get_params, fitted classes/features, timings and native resolved XGBoost configuration are recorded, not just these shorthand settings. Actual config SHA-256 `fdc9f8bbf6cc6991bbac0fa40e59801ed1486df2e1f642927a832b21157fcd92`. Random Forest restarted after an interrupted unsaved fit; saved XGBoost retained unchanged. No successful runs averaged or test-driven tuning.
8. **XGBoost aggregate results — MEASURED.** See table; primary supervised architecture, not a claim of calibrated attack probability. Established metrics use raw classifier.predict; runtime confidence-based unknown labels and severity/event enrichment are not included in classifier accuracy.
9. **Random Forest aggregate results — MEASURED.** See table; baseline evaluated under the same partition.
10. **Logistic Regression aggregate results — MEASURED.** See table; linear feature subset retained. Training iteration/warning evidence is in training.json and resume.log; no retuning after evaluation.
11. **XGBoost per-class metrics — MEASURED.** See table and full CSV with support; no zero-recall class hidden.
12. **Confusion matrix.** Full matrices for all models are in final-science-confusion-matrix.csv. XGBoost rows: `{"labels": ["benign", "brute_force", "c2", "ddos", "reconnaissance"], "matrix": [[267575, 1, 0, 271, 4], [0, 0, 0, 0, 0], [1437, 0, 0, 0, 0], [46683, 0, 0, 34152, 47179], [0, 0, 0, 0, 0]]}`.
13. **BENIGN-TO-MALICIOUS FALSE-POSITIVE RATE — MEASURED.** 276 / 267851 = 0.00103042; predicted benign 267575. False positives by class: `{"brute_force": 1, "ddos": 271, "reconnaissance": 4}`.
14. **Per-class FPR/FNR.** SCI-CORR-2 one-versus-rest reporting is used unchanged. Operational benign-to-malicious rate is benign FNR, not benign one-versus-rest FPR. Zero-denominator conventions require support qualification.
15. **C2 — MEASURED with limitations.** Support 1,437; no C2 in supervised training. Its supervised metrics/confusions remain visible above. Anomaly family ranking/operating points are in novelty JSON; F3 periodicity is entirely separate.
16. **DDoS — MEASURED.** Support 128,014; supervised metrics above. Separate held-out-family anomaly result excludes all ddos rows from supplementary preprocessing and trains IF on benign only. No F3 rate/entropy contribution.
17. **Reconnaissance.** NO PRIMARY-TEST RECONNAISSANCE SUPPORT. No scenario moved to manufacture support; not evaluated in supplementary fixed-test novelty.
18. **Exfiltration.** 36 TRAIN / 0 TEST support. No meaningful accuracy claim; directional asymmetry evidence is unrelated to supervised support.
19. **Isolation Forest ranking — MEASURED.** Primary binary ROC-AUC 0.818401; trapezoidal PR-AUC 0.541924; average precision 0.542542. PR area and average precision are distinct definitions.
20. **Threshold protocol — LIMITED / EXPERIMENTAL.** Validation benign153,677/other2,143 is narrow. Existing validation-only F1 grid and fixed 1%/5% validation-benign quantiles were locked before test inference. All threshold-dependent results are EXPLORATORY; achieved test FPR may differ from nominal validation target. No test threshold selection. Thresholds and precision/recall/F1/FPR are in metrics JSON.
21. **Held-out attack-family evaluation — LIMITED / EXPERIMENTAL.** C2 and DDoS IF ranking only, preserving original partitions. C2 train exclusion count0 because already absent; DDoS excluded193,756 from supplementary preprocessing. Other families have no fixed TEST support and are NOT EVALUATED—INSUFFICIENT SUPPORT. No zero-day accuracy claim.
22. **SIMULATED UNIDIRECTIONAL TELEMETRY LOSS.** Full TEST macro-F1 0.267512 → 0.203453, absolute signed delta -0.064060. Affected available fields `['reverse_packets', 'reverse_bytes', 'fwd_rev_packet_ratio', 'fwd_rev_byte_ratio', 'rev_iat_mean', 'rev_iat_std', 'rev_iat_min', 'rev_iat_max', 'reverse_payload_bytes', 'payload_ratio']` zeroed, original NaNs preserved. Other aggregate fields are not reconstructed, so this is controlled ablation, not physical diode or natural one-way flow validation.
23. **Robustness — SIMULATED/LIMITED.** Five established perturbations at their stated seed/magnitudes on the predeclared first10,000 TEST rows only, support `{"benign": 10000}`. Original NaNs restored after perturbation to preserve missingness; this does not alter fitted preprocessing. Results are prefix-specific sensitivity, not population robustness or causal feature importance. Jitter may produce nonphysical IATs and independent feature edits need not preserve cross-feature consistency; these are vector perturbations, not reconstructed traffic.
24. **UNSW compatibility.** EXTERNAL-DATASET DIRECT EVALUATION NOT METHODOLOGICALLY VALID. Adapter categories: `{"DIRECT": 6, "DERIVED": 8, "PROXY": 3, "MISSING": 35, "STRUCTURAL_ZERO": 0}`. Missing canonical fields and rate/IAT proxies have non-equivalent source semantics; no zero-fill or direct-transfer metric. Full mapping in supplementary artifact.
25. **Historical comparison.** Current and historical values/deltas are recorded only after measurement. Candidate/data/environment identities are not equivalently verifiable for historical runs, and Phase8 novelty cohorts differ: NOT DIRECTLY COMPARABLE. No improvement/regression claim.
26. **F3/F4/F5 — VERIFIED ENGINEERING PROPERTY.** Deterministic positive, legitimate, malformed-input and bounded-state fixtures; F3 7/7, F4 8/8, F5 12/12 parity pass in post-evaluation regression. No population-level precision/recall for those heuristics.
27. **What can be claimed.** The measured fixed-split results, qualified anomaly ranking/operating points, simulated telemetry-removal outcomes and separate tested engineering properties. See final-science-claims.md.
28. **What cannot be claimed.** Perfect detection, universal zero-day detection, calibrated attack probability, production readiness/Gbps guarantee, physical diode/BPF verification, population heuristic accuracy, JA4, encrypted DNS visibility or TLS/QUIC payload decryption.
29. **Candidate recommendation: SUITABLE FOR OPERATOR REVIEW as a scientific candidate, not deployment approval.** Review must consider absent C2 training, zero-support classes, measured errors, limited anomaly validation and existing operational constraints. Nothing automatically approved or published.
30. **Backend total.** 906 passed, 43 warnings in 107.33 seconds. Full source unchanged; no new runtime tests added.
31. **Frontend total.** 90 passed across 6 files.
32. **TypeScript/build.** Both PASS.
33. **SCI-CORR-2 integrity.** 23/23 byte-identical throughout checks; exact hashes in environment. No scientific or product source edited.
34. **Parity and lifecycle.** Core, F3, F4, F5, frozen bundle/inference, auth/event contract, model loader, replay, sensor lifecycle and SCI-CORR1/2/3 regression tests pass in the full suite.
35. **Remaining limitations.** Single seed, flow-table adapter representation, no statistical significance/uncertainty claim; corrected runtime segmentation is not directly validated by CICFlowMeter tables. Primary absent-class support, narrow validation, simulated one-way, prefix robustness and protocol coverage remain explicit. Historical scientific stop evidence preserved.
36. **Git recommendation.** Suggested message: `docs(science): record fixed-split final revalidation and candidate provenance`. Review/commit harnesses, configuration, manifests and reports as a scientific evaluation record. Store binary candidates in trusted artifact storage; do not automatically add large binaries to Git or publish a deployment. No commit/push performed.
37. **Next phase.** Scientific results and candidate are available for operator review and separately authorized final SIH hardening. This task stops; no F6, presentation or product work begun.

GO FOR FINAL SIH HARDENING
