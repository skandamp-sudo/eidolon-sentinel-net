# FINAL-SCIENCE claim matrix — mandatory scientific stop

## WHAT WE CAN CLAIM

| Classification | Claim | Evidence |
|---|---|---|
| MEASURED | Eight local CICIDS2017 parquet files contain 2,313,810 rows by metadata count; full-file hashes recorded. | final-science-environment.json |
| VERIFIED ENGINEERING PROPERTY | 23/23 protected source files match F5 at audited revision 9d6b3b4. | final-science-environment.json |
| MEASURED | Same NumPy split seed produces different partitions under Python hash seeds 0/1/2. | final-science-audit/reproduction.json |
| MEASURED | A dropped-column preprocessor fixture exposes incorrect output-width and constant-name reporting. | final-science-audit/reproduction.json |
| VERIFIED ENGINEERING PROPERTY | Prior F5 recorded 866 backend and 90 frontend passes, plus protocol parity; not rerun in this stopped phase. | sih-f5-report.md |
| LIMITED / EXPERIMENTAL | Historical Phase 7/8 metrics apply only to their archived methodology/artifacts and are not revalidated here. | final-science-historical-comparison.json |

## WHAT WE CANNOT CLAIM

| Classification | Unsupported claim |
|---|---|
| NOT VERIFIED | Current supervised accuracy, per-class recall, false-positive rate or calibration |
| NOT VERIFIED | Current Isolation Forest ROC/PR or validation-selected operational recall |
| NOT VERIFIED | Reproducibly evaluated or publication-ready scientific candidate |
| SIMULATED | A future one-way perturbation would simulate telemetry loss; no new simulation ran here |
| NOT VERIFIED | Physical data-diode operation or native real-interface BPF capture |
| NOT VERIFIED | Population precision/recall for F3/F4/F5 contextual evidence |
| NOT VERIFIED | Meaningful direct CICIDS-to-UNSW transfer without feature/unit/semantic compatibility |
| NOT VERIFIED | Universal zero-day detection, production readiness or universal throughput |

No scores or sample supports were fabricated. Model confidence, anomaly scores, contextual protocol evidence and operational performance remain separate concepts. Final scientific revalidation is incomplete.

NO-GO FOR FINAL SIH HARDENING
