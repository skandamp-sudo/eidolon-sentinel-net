# SC-3 historical consumer audit

**Classification: NOT USED in the inspected saved Phase 7/8 primary claims.** This is a scoped static/artifact conclusion, not a recalculation of historical metrics or proof about external presentations.

- `experiments/run_evaluation.py:335–350` serializes ClassificationReport per-class rates and confusion matrices for the three Phase 7 classifiers. The saved `experiments/metrics/model_performance.json` and repeated `experiments/reports/complete_evaluation.json` entries each have five-class matrices. Those use the existing multiclass one-versus-rest path, outside the demonstrated binary defect.
- Phase 7's operational false-positive calculation (`run_evaluation.py:525`) divides actual benign misclassifications by benign support directly. Its threshold FPR values come from AnomalyReport. Neither consumes binary ClassificationReport per-class FPR/FNR.
- `experiments/run_phase8.py` computes ClassificationReport objects for held-out/scenario experiments but persists aggregate classifier precision/recall/F1. Its saved anomaly FPR comes from AnomalyReport; novelty ranking/operating-point data are separate. No saved binary ClassificationReport per-class FPR/FNR consumer was found in those experiment paths.
- A recursive scan of available `experiments/**/*.json` found per-class FPR records in the above five-class artifacts and the separate four-class synthetic validation report. No two-class per-class rate artifact was found. [Scan output](sci-corr-2-validation/historical-artifact-scan.json) records paths/class counts. The synthetic report is not a Phase 7/8 real-data claim.
- The inspected markdown reports and evaluation documentation did not establish a claim based on the broken binary first-class rates. No historical claim correction is asserted.

Scope does not cover absent artifacts, unpublished notebooks or external slides. Impact there is UNKNOWN. Calling ClassificationReport can compute unused binary rates internally; that is not evidence that a saved scientific claim consumed them.

Historical values remain historical measurements tied to their recorded partition and prior implementation. No historical report, metric, partition or model was rewritten or recalculated in SCI-CORR-2.
