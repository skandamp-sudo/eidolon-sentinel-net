# FINAL-SCIENCE-RESTART claim matrix — SC-3 stop

## WHAT SENTINEL-NET CAN CLAIM

| Category | Claim | Evidence |
|---|---|---|
| MEASURED | Binary per-class FPR/FNR has an orientation error on the documented eight-row synthetic fixture. | final-science-restart-audit/reproduction.json |
| MEASURED | Eight dataset files match archived hashes; parquet metadata totals 2,313,810 rows and the fixed partition counts. | final-science-environment.json |
| VERIFIED ENGINEERING PROPERTY | All 23 protected files match the authorized SCI-CORR-1 baseline. | final-science-environment.json |
| VERIFIED ENGINEERING PROPERTY | Archived split identity verified; no fallback or generated split applied. | final-science-split-manifest-used.json |
| VERIFIED ENGINEERING PROPERTY | Prior SCI-CORR-1 recorded 896 backend and 90 frontend passes, with parity/runtime gates; not rerun here. | sci-corr-1-report.md |
| LIMITED / EXPERIMENTAL | Historical science remains bound to its recorded partition and implementation; no numerical invalidation inferred from SC-3. | final-science-report.md |

## WHAT SENTINEL-NET CANNOT CLAIM

- **NOT VERIFIED:** current model accuracy, per-class recall/FPR, anomaly ranking, calibration or an evaluated candidate.
- **SIMULATED:** no new one-way experiment ran; any future telemetry-removal result must remain explicitly simulated.
- **NOT VERIFIED:** physical data-diode operation or native real-interface BPF capture.
- **NOT VERIFIED:** universal zero-day detection, perfect accuracy, production readiness or capacity guarantees.
- **NOT VERIFIED:** population precision/recall for F3/F4/F5 contextual heuristics.
- **NOT VERIFIED / NOT IMPLEMENTED:** JA4, encrypted DNS analysis or TLS/QUIC payload inspection.
- **NOT VERIFIED:** meaningful CICIDS-to-UNSW direct transfer without representation compatibility.

No candidate exists for operator review or publication. Model confidence is not automatically calibrated attack probability; anomaly score and contextual evidence are separate. This restart stopped before scientific training and evaluation.

NO-GO FOR FINAL SIH HARDENING
