# FINAL-SCIENCE — stopped at scientific preflight

**NO-GO FOR FINAL SIH HARDENING.** The mandatory scientific stop rule was triggered by two reproducible defects in protected scientific source. No model training, final-test evaluation, threshold selection, candidate publication or product modification was performed. This is a stop report, not a completed scientific revalidation.

Source revision: `9d6b3b4fe34d09237a827c445aea4c6a4173328c` (clean initial worktree). All 23 protected files remain byte-identical to the F5 integrity baseline. Historical reports remain untouched.

## Confirmed defects and impact

**SC-1: scenario split depends on Python hash randomization.** `src/sentinel_net/detection/dataset.py:194` constructs `list(set(scenarios))` before the seeded shuffle. The same eight scenario IDs and NumPy random seed 42 produce different partitions in fresh processes:

| PYTHONHASHSEED | Validation | Test |
|---|---|---|
| 0 | Bruteforce-Tuesday | Benign-Monday, Infiltration-Thursday |
| 1 | Botnet-Friday | Bruteforce-Tuesday, Infiltration-Thursday |
| 2 | DDoS-Friday | Botnet-Friday, Portscan-Friday |

This changes training/validation/test composition before any model fitting. It affects reproducibility of all downstream supervised, anomaly, false-positive, threshold and robustness results when the historical driver is rerun from seed alone. It does **not** prove the archived metrics were incorrectly calculated for their recorded split. The historical explicit assignment is available and must be preserved rather than replaced with whichever assignment a new process generates.

Proposed remediation, **not applied**: support/reuse a validated explicit partition manifest for historical reproduction, checking disjointness, full coverage, scenario IDs, dataset identity and row counts. For newly generated partitions, sort unique IDs before seeded shuffling and test across fresh processes with different hash seeds. Sorting alone must not silently substitute a new partition for the historical one. Reconcile this change with the protected-source policy in a separate authorized correction phase.

**SC-2: preprocessing metadata is wrong after all-missing columns are dropped.** `src/sentinel_net/detection/preprocessing.py:50` pairs the post-imputation variance mask with the original feature list; `n_features_out` at line 90 returns the pre-imputation selected width. A deterministic eight-row fixture with `pkt_size_median` missing and `iat_mean` constant produces:

| Property | Actual | Reported |
|---|---|---|
| Output width | 51 | 52 |
| Constant feature | iat_mean | pkt_size_p90 |
| `output_feature_names` length | 51 | 51 (correct) |

The established CICIDS adapter declares 11 unavailable columns, so dropped-column handling is relevant to this evaluation. The demonstrated defect affects preprocessing identity/width and constant-feature reporting, including historical driver logs/smoke metadata using `constant_features`. This reproduction does **not** establish incorrect transformed numeric arrays or classifier predictions; historical metric deltas cannot be inferred from it. Existing `output_feature_names` already handles surviving names correctly, but the other accessors do not use it.

Proposed remediation, **not applied**: align the constant mask with the fitted imputer's surviving feature names and derive fitted output width from the actual transformed schema. Add tests for a dropped column before a constant column, multiple missing columns, tree/linear subsets and save/load identity. Preserve feature mathematics and missing values; do not fill missing columns with fabricated zeros.

Evidence: [reproducer](final-science-audit/reproduce.py), [exact output](final-science-audit/reproduction.json), [warnings](final-science-audit/reproduction-stderr.txt). Run with `PYTHONPATH=src .venv/bin/python docs/final-science-audit/reproduce.py`. This fits only a tiny synthetic preprocessor to demonstrate the defect; it trains no classifier/anomaly model and evaluates no real-data test rows.

## Requested 31-point disposition

1. **Dataset inventory — MEASURED.** Eight local CICIDS2017 parquet files, **2,313,810 rows** counted from parquet metadata. Full-file SHA-256, byte sizes, schemas and per-file counts are in [environment](final-science-environment.json). This is an inventory, not completed row-level quality/label validation. UNSW training/testing CSVs and raw files are present; they were not evaluated.
2. **Scenario split — historical reference only.** TRAIN: Benign-Monday, Bruteforce-Tuesday, DoS-Wednesday, Infiltration-Thursday, Portscan-Friday. VALIDATION: WebAttacks-Thursday. TEST: Botnet-Friday, DDoS-Friday. These are recovered from `experiments/metrics/dataset_split.json`, not reassigned to improve results. Historical counts are 1,760,688 / 155,820 / 397,302; current per-partition row/label reconstruction was stopped. SC-1 prevents claiming the seeded driver reproduces this assignment by itself.
3. **Evaluated candidate identity — NOT VERIFIED.** No candidate created or evaluated. No candidate manifest/hash exists for this attempt; none is fabricated.
4. **Training configuration — reference only.** Historical seed 42; median imputation then StandardScaler fitted on training; tree subset 52 and linear subset 50 before all-missing-column removal; XGBoost 100 trees/depth 6/learning rate 0.1, RF 100 trees, logistic regression lbfgs/max_iter 1000, Isolation Forest 100 trees trained on benign samples. Effective fitted identities and full defaults were not locked because training stopped. This is not a training run or a single-seed result.
5. **XGBoost results — NOT RUN.** No current accuracy, macro/weighted scores or confidence distributions.
6. **Random Forest results — NOT RUN.** No current metrics.
7. **Logistic Regression results — NOT RUN.** No current metrics.
8. **Per-class metrics — NOT RUN.** CSV contains a header only; absent rows mean unavailable, not zero performance.
9. **Confusion matrix — NOT RUN.** CSV contains a header only; no invented predictions/counts.
10. **Benign false-positive analysis — NOT RUN.** No current benign support, predicted-malicious count or FPR is claimed.
11. **Isolation Forest results — NOT RUN.** No current ROC-AUC, PR-AUC or threshold-dependent metrics.
12. **Held-out-family results — NOT RUN.** [Novelty artifact](final-science-novelty.json) records the stop; no universal zero-day claim.
13. **C2 findings — historical limitation only.** Historical primary test includes C2 while training does not. Archived XGBoost C2 recall is 0 with support 1,437; this is not a current measurement. F3 periodicity is separate contextual evidence and cannot replace ML recall.
14. **DDoS findings — NOT REVALIDATED.** Historical primary training includes DoS variants mapped to `ddos`, with DDoS-Friday in test. Current supervised and anomaly performance remain unavailable; streaming rate/entropy evidence is excluded from ML metrics.
15. **Reconnaissance findings — NOT REVALIDATED.** Historical primary split puts Portscan-Friday in training, with zero reconnaissance support in its primary test. A current recall claim from that test would be unsupported.
16. **Exfiltration limitation — historical support only.** Archived training has 36 mapped Infiltration samples and no primary test support. This cannot establish meaningful exfiltration accuracy; current labels/support were not revalidated.
17. **Simulated unidirectional results — NOT RUN due to stop.** No delta reported. A future rerun must specify removed directional fields and be labeled SIMULATED UNIDIRECTIONAL TELEMETRY LOSS, never physical data-diode validation.
18. **Robustness results — NOT RUN due to stop.** Timing jitter, packet-size noise, duration changes, imbalance and metadata dropout are unavailable in [robustness artifact](final-science-robustness.json). No causal importance claim.
19. **Score/threshold semantics.** MODEL CONFIDENCE SCORE is not calibrated true attack probability; anomaly score is separate. No recalibration or threshold change occurred. Historical validation contains benign plus web attacks mapped to `other`, a narrow composition. Any resumed threshold-dependent operational results require a justified validation-only protocol or explicit exploratory labeling; test results must not select thresholds.
20. **Historical comparison.** [Comparison JSON](final-science-historical-comparison.json) preserves historical supervised values with current values/deltas null and comparable NO. Historical Phase 8 novelty remains reference only; no current novelty comparison exists. The stop does not justify calling any historical/current change an improvement or regression.
21. **Protocol / behavioral evidence validation status — prior VERIFIED ENGINEERING PROPERTY.** F3/F4/F5 have deterministic positive/legitimate/malformed/bounded-state tests and recorded 7/8/12-case parity in the F5 engineering baseline. No population-level precision/recall for these heuristics is established. No protocol suite was rerun after this mandatory stop. Operational performance remains separately documented in RW-5B/F3/F4/F5 reports.
22. **What can be claimed.** Current dataset metadata inventory/hashes, two reproduced preflight defects, clean starting revision and unchanged protected scientific source. Prior engineering results may be cited with their phase and date; they are not new accuracy measurements.
23. **What cannot be claimed.** Current supervised/anomaly accuracy, candidate equivalence, final scientific completion, production readiness, universal zero-day detection, physical diode verification or population protocol-heuristic accuracy. **EXTERNAL-DATASET DIRECT EVALUATION NOT METHODOLOGICALLY VALID** under the unvalidated CICIDS-to-UNSW representation: UNSW adapter contains many missing fields and explicit proxies with different source semantics. Full UNSW unit/semantic audit was not completed; no direct-transfer metric was forced.
24. **Exact backend/frontend totals.** No new full regression run. Last F5 baseline: 866 backend passed (14 warnings), 90 frontend passed across 6 files; 956 combined. These are clearly prior results, not FINAL-SCIENCE gates.
25. **TypeScript/build.** Not rerun after stop. Prior F5: both PASS. No product/source edits made.
26. **23-file integrity — VERIFIED ENGINEERING PROPERTY in this audit.** 23/23 hashes match F5. Canonical 52-feature schema v2.0.0 unchanged. No scientific source fix applied.
27. **Parity regression status.** Not rerun. Prior core 7/7, F3 7/7, F4 8/8, F5 12/12 PASS; no current candidate runtime parity exists because no candidate was trained.
28. **Remaining scientific limitations.** SC-1/SC-2 block the mandated evaluation workflow; dataset row-level audit, exact current partition counts, model/artifact identity, calibration, threshold protocol and all requested experiments remain incomplete. Historical CICFlowMeter feature tables also cannot by themselves validate corrected runtime segmentation. BPF, exact-history growth and prior protocol coverage limits remain.
29. **Operator approval/publication.** No evaluated candidate is available for approval. Existing deployment remains untouched. Do not publish a model based on this stop report.
30. **Git recommendation.** Review and optionally commit these audit-only documents as `docs: record final-science preflight blockers`. No commit/push performed. Preserve historical reports.
31. **Recommended next phase.** Separately authorize a narrowly scoped scientific reproducibility correction for SC-1/SC-2, review protected-baseline changes explicitly, then restart FINAL-SCIENCE preflight with the archived partition locked before inspecting test results. Do not start SIH-F6 or PPT work.

## Artifact status

All requested artifact paths exist to make the stop explicit. Metrics/novelty/robustness contain null or NOT_RUN status, and metric CSVs are header-only. They are not completed evaluation deliverables. Environment binds current dataset hashes, source revision, library versions and protected-file hashes. [Claims](final-science-claims.md) distinguishes measured facts, prior engineering properties and unavailable results.

NO-GO FOR FINAL SIH HARDENING
