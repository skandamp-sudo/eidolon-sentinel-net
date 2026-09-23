# FINAL-SCIENCE-RESTART — SC-3 scientific stop

**NO-GO FOR FINAL SIH HARDENING.** A new reproducible scientific reporting defect triggered the mandatory stop rule before model training. No protected source was patched, no final-test predictions were inspected, and no scientific candidate was created or published. This is an incomplete revalidation, not an accuracy report.

## SC-3: binary per-class FPR/FNR uses the wrong class orientation

In `src/sentinel_net/detection/evaluation.py:61–65`, `ClassificationReport.from_predictions` unpacks the same binary confusion matrix as `tn, fp, fn, tp` for every class. That calculation treats the second sorted class as positive. It is then attached to both classes, although each entry is a per-class report. The multiclass branch already computes each class one-versus-rest.

The metric-only reproducer uses eight hand-specified labels/predictions, with four benign and four DDoS examples. No model or actual dataset predictions are involved. Sorted class order is benign, ddos; the confusion matrix is `[[3, 1], [2, 2]]` (rows true, columns predicted).

| Per-class rate | Correct one-versus-rest | Current reported |
|---|---:|---:|
| benign FPR | 0.50 | 0.25 |
| benign FNR | 0.25 | 0.50 |
| ddos FPR | 0.25 | 0.25 |
| ddos FNR | 0.50 | 0.50 |

For the benign class as positive, TP=3, FN=1, FP=2, TN=2. For the ddos class as positive, TP=2, FN=2, FP=1, TN=3. Operational benign-to-malicious false-positive rate is a different, explicitly defined quantity: here 1/4 = 0.25, equal to the benign class's one-versus-rest FNR. These definitions must not be conflated.

**Demonstrated impact:** the first sorted class's binary per-class FPR/FNR is incorrect when the two class orientations have different rates. This can misstate class-level error analysis in binary reports. It does not demonstrate incorrect classifier predictions, aggregate accuracy, macro/weighted precision/recall/F1, confusion-matrix entries, the multiclass branch, or the separate `AnomalyReport`. No numerical impact on historical Phase 7/8 claims is inferred; historical binary report consumers need a scoped audit before any impact claim. Historical values remain historical measurements tied to their recorded partition and prior implementation.

**Proposed fix, not applied:** compute TP/FP/FN/TN for each class from its own row/column in both binary and multiclass reports, retaining documented denominator behavior. Add asymmetric binary examples, reversed label names/order, multiclass and zero-support/one-class cases. Verify aggregate metrics and the raw confusion matrix remain unchanged. A separately authorized correction is required because `evaluation.py` is protected source.

Reproduce with `PYTHONPATH=src .venv/bin/python docs/final-science-restart-audit/reproduce_metric_defect.py`. [Source](final-science-restart-audit/reproduce_metric_defect.py), [measured output](final-science-restart-audit/reproduction.json). No workaround, silent patch or continued scientific evaluation was used.

## Requested 35-point disposition

1. **Dataset identity — MEASURED.** All eight CICIDS2017 files were rehashed against the locked manifest. Parquet metadata totals **2,313,810 rows**. File schemas, byte sizes, counts and SHA-256 are in [environment](final-science-environment.json). This is not completed row-level adapter/label validation.
2. **Exact split identity — VERIFIED ENGINEERING PROPERTY.** The partition file digest matches the authorized SCI-CORR-1 baseline. [Split manifest identity](final-science-split-manifest-used.json) retains the exact manifest, digest and independently reverified dataset identity. It is explicitly marked verified but not applied to training.
3. **Actual partition counts — MEASURED from parquet metadata.** TRAIN **1,760,688**, VALIDATION **155,820**, TEST **397,302**. Exact scenario coverage/no overlap and reference-count matching verified. No split was generated or substituted.
4. **Class distributions — NOT RUN.** The scientific stop occurred before row-level label/adapter validation. No historical distribution is presented as newly measured.
5. **Preprocessing identity — NOT FITTED ON REAL DATA.** SC-2 corrected source is accepted and hash-verified. The requested current real-training-data precheck was not run after discovery of SC-3.
6. **Evaluated candidate identity — NONE.** No candidate or model manifest was generated.
7. **Exact training configuration — NOT EXECUTED.** No fitted model configuration exists for this attempt. Established seed-42 recipe was not run or tuned.
8. **XGBoost aggregate metrics — NOT RUN.**
9. **Random Forest aggregate metrics — NOT RUN.**
10. **Logistic Regression aggregate metrics — NOT RUN.**
11. **XGBoost per-class metrics — NOT RUN.** CSV is header-only, not zero-valued results.
12. **Confusion matrix summary — NOT RUN for CICIDS.** The only new matrix is the eight-row synthetic SC-3 reproducer, explicitly not a model evaluation. Scientific confusion CSV is header-only.
13. **Benign false-positive rate — NOT MEASURED on CICIDS.** No rate extrapolated from the synthetic reproduction.
14. **C2 result — NOT REVALIDATED.** Weak historical performance is neither hidden nor replaced with an invented current result. F3 periodicity remains separate engineering evidence.
15. **DDoS result — NOT REVALIDATED.** No supervised or anomaly metric; no inclusion of F3 rate/entropy evidence in ML results.
16. **Reconnaissance result — NOT REVALIDATED.** The archived split has Portscan-Friday in training, not primary test. No zero-support recall claim.
17. **Exfiltration limitation — NOT REVALIDATED.** Historical tiny support does not establish useful exfiltration accuracy; no new sample support or metric is claimed.
18. **Isolation Forest ROC-AUC/PR-AUC — NOT RUN.** SC-3 is in ClassificationReport, not a demonstrated defect in AnomalyReport, but the global stop rule prevents continuing evaluation.
19. **Threshold protocol/result — NOT RUN.** No threshold selected, recalibrated or tuned. Future validation-composition audit remains required; narrow validation implies exploratory operational claims unless justified. Model confidence and anomaly scores remain distinct.
20. **Held-out-family results — NOT RUN.** [Novelty artifact](final-science-novelty.json) records the stop. No zero-day accuracy claim.
21. **Simulated unidirectional results — NOT RUN.** No new SIMULATED UNIDIRECTIONAL TELEMETRY LOSS measurement or physical diode validation.
22. **Robustness results — NOT RUN.** [Robustness artifact](final-science-robustness.json) records the stop. No prediction-change rates or causal importance claims.
23. **UNSW compatibility — NOT COMPLETED THIS RESTART.** No direct transfer evaluated. Prior compatibility limitations remain: many missing canonical fields and explicit proxies require semantic/unit verification. **EXTERNAL-DATASET DIRECT EVALUATION NOT METHODOLOGICALLY VALID** without that compatibility. No fresh usable-feature count is asserted after the stop.
24. **Historical comparison — NOT PERFORMED.** The brief requires current measurements first; none exist. [Comparison artifact](final-science-historical-comparison.json) is explicitly unavailable. No improvement/regression claims or historical report edits.
25. **F3/F4/F5 engineering status — prior VERIFIED ENGINEERING PROPERTY.** Prior fixture, legitimate-control, malformed-input and bounded-state validation remains separate from population accuracy. Prior F3 7/7, F4 8/8, F5 12/12 parity passed, including the SCI-CORR-1 full regression. Not rerun after this stop.
26. **Current claim matrix.** See [claims](final-science-claims.md). Newly measured claims are limited to the metric reproducer and metadata/hash inventory; no current accuracy claims.
27. **Candidate recommendation: NOT SUITABLE FOR OPERATOR REVIEW.** No evaluated candidate exists. This says nothing new about existing deployed artifact quality. Nothing published or approved.
28. **Backend total — NOT RERUN.** Previous SCI-CORR-1: **896 passed, 41 warnings**. Those are prior engineering results, not a fresh restart gate.
29. **Frontend total — NOT RERUN.** Previous SCI-CORR-1: **90 passed across 6 files**.
30. **TypeScript/build — NOT RERUN.** Previous SCI-CORR-1 both PASS. The mandatory scientific stop took precedence over post-evaluation gates; no evaluation completed.
31. **Baseline integrity — VERIFIED ENGINEERING PROPERTY.** **23/23 byte-identical to SCI-CORR-1**, including its two authorized corrected files. Baseline `sci-corr-1-29bc756272dbd981a6768a94edfaa69c75de12f0a31c2158498dbd901c4d37f2`. They are not treated as failures against older hashes.
32. **All parity results — NOT RERUN.** Prior core 7/7, F3 7/7, F4 8/8, F5 12/12 engineering evidence remains historical. No new evaluated-candidate runtime parity exists.
33. **Remaining limitations.** SC-3 blocks this restart; model training, row-level prechecks, candidate identity, supervised/anomaly/robustness results and final claim validation remain incomplete. Real BPF, physical diode operation, JA4, encrypted DNS and population protocol precision/recall remain unverified or unsupported as previously documented.
34. **Git recommendation.** Review and optionally commit the preserved stop provenance and new SC-3 audit as `docs: record binary per-class metric reporting blocker`. No commit/push was performed.
35. **Recommended next phase.** Separately authorize a minimal SC-3 reporting correction and its regression/integrity transition, then restart FINAL-SCIENCE from preflight with the same archived explicit split. Do not begin SIH-F6, judge-demo or product work.

## Preserved provenance

The previous requested FINAL-SCIENCE artifacts are copied byte-for-byte to [previous-stop](final-science-restart-audit/previous-stop/final-science-report.md), with [archive hashes](final-science-restart-audit/previous-stop/archive-sha256.json). The original SC-1/SC-2 audit and SCI-CORR-1 artifacts remain in place. Current metric/novelty/robustness JSON files explicitly contain unavailable results; CSVs contain headers only. These are stop artifacts, not completed scientific deliverables.

NO-GO FOR FINAL SIH HARDENING
