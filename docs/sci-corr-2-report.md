# SCI-CORR-2 final report

SC-3 is corrected within the authorized reporting-only scope. No scientific model training, final CICIDS evaluation, test-prediction inspection, threshold tuning or publication occurred. The required full regression suite runs its existing isolated synthetic model fixtures; these are not scientific candidate training. Prior uncommitted FINAL-SCIENCE-RESTART stop artifacts were preserved.

1. **Exact SC-3 root cause.** The binary branch unpacked the same matrix as tn/fp/fn/tp for each class, assigning second-sorted-class-oriented FPR/FNR to both class entries.
2. **Exact code change.** Removed that binary branch in `ClassificationReport.from_predictions`. The existing multiclass one-versus-rest calculation now applies uniformly; no unrelated evaluation code changed.
3. **Unified design.** For each class i, TP is its diagonal, FN its remaining row, FP its remaining column and TN the remaining matrix total. FPR=FP/(FP+TN), FNR=FN/(FN+TP). Existing zero-denominator result 0.0 is preserved and is not evidence of meaningful performance when support is absent.
4. **Synthetic before/after.** Exact SC-3 matrix `[[3,1],[2,2]]`, four samples per class: benign before 0.25/0.50, after 0.50/0.25 (FPR/FNR); DDoS before and after 0.25/0.50. Full [comparison](sci-corr-2-validation/before-after.json) uses the actual pre-correction implementation, not historical dataset predictions.
5. **Benign result.** One-versus-rest FPR **0.50**, FNR **0.25** on this synthetic fixture only.
6. **DDoS result.** One-versus-rest FPR **0.25**, FNR **0.50**, unchanged on this fixture.
7. **Confusion-matrix invariance.** Before/after matrix is exactly identical; labels/predictions and matrix construction are unchanged.
8. **Aggregate invariance.** Accuracy plus macro and weighted precision/recall/F1 are exactly identical across the before/after reproducer. Permanent tests check these against sklearn on perfect, all-error, zero-predicted-positive, zero-actual-support, one-class and three-class fixtures.
9. **Multiclass regression.** Complete three-class report exactly matches the old implementation. Tests independently compute rates from Boolean one-versus-rest counts. Reversed lexical labels and reversed semantic roles confirm rates do not depend on which class sorts second.
10. **AnomalyReport regression.** The report is unchanged in source and exactly equal in the before/after comparison. Its binary attack-oriented operational rate remains separate.
11. **Operational benign false-positive semantics.** Actual benign predicted non-benign / actual benign is benign one-versus-rest **FNR** (0.25 here). Benign one-versus-rest FPR counts non-benign predicted benign / actual non-benign (0.50 here). Tests/documentation protect this distinction.
12. **Historical consumer audit.** **NOT USED** in inspected saved Phase 7/8 primary claims. Phase 7 persisted classifier matrices are five-class; Phase 8 persists aggregate classifier metrics and separate AnomalyReport rates. No affected binary per-class claim found. Unavailable/external material remains UNKNOWN. [Scoped audit](sci-corr-2-historical-audit.md); no historical metrics recalculated or rewritten.
13. **Files changed in this phase.** `src/sentinel_net/detection/evaluation.py`; `tests/unit/test_binary_class_rates.py`; new SCI-CORR-2 report, historical audit, restart contract, integrity and validation artifacts. Existing FINAL-SCIENCE dirty documents are prior work, not this correction.
14. **Protected source intentionally changed.** Exactly one file, evaluation.py. **22/23 unchanged from SCI-CORR-1**, including its corrected dataset.py and preprocessing.py. No changes to extraction, model behavior, thresholds, schema or runtime inference.
15. **Previous/new evaluation.py SHA-256.** Previous `f91be2692b3807d6d7c26ec7ddee1efc0862e950d28142e0c5a3ce800f8e9d6b`; new `8143cc6a3098f2eb086ffdc360e6e35bb307b643a5732ee6142acd39c541a868`.
16. **New scientific baseline.** `sci-corr-2-a5d927bf3a52f5634bd95013eed3cbbde03203343f565c6a6050f7212e9b75be`. [Integrity manifest](sci-corr-2-scientific-integrity.json) binds previous baseline/file hash, corrected source map, base revision `6311934ea99fc59be9e71e77a8a3fe476dbb03ed`, reason and tests. It identifies an uncommitted correction worktree, not a new Git revision.
17. **Focused tests.** **19 passed, 4 warnings**: ten new cases plus nine existing evaluation tests. No failed test is suppressed.
18. **Backend total.** **906 passed, 43 warnings**, 94.38 seconds. Warnings include existing scientific edge-case/imputer/deprecation warnings and single-label matrix warnings in the new edge-case checks. [Backend log](sci-corr-2-validation/backend.txt).
19. **Frontend total.** **90 passed across 6 files**; combined **996**. [Frontend log](sci-corr-2-validation/frontend.txt).
20. **TypeScript/build.** Both PASS. [TypeScript](sci-corr-2-validation/typescript.txt), [build](sci-corr-2-validation/build.txt).
21. **Core/F3/F4/F5 parity.** All pass in the full suite, including established core, F3 7-case, F4 8-case and F5 12-case parity coverage. Sensor/replay lifecycle and auth/event-contract tests also pass.
22. **Frozen deployment compatibility.** Frozen bundle loader/inference regressions pass. Existing runtime/1.0.0 QA bundle loads twice with exact synthetic-vector preprocessing/classifier/anomaly parity and unchanged file hashes. Runtime scientific source other than reporting remains byte-identical. No republishing or deployment mutation needed/performed.
23. **SCI-CORR-1 regression.** Explicit-manifest/generated partition tests and preprocessing schema/numeric/save-load tests pass in the full suite. Archived partition file remains unchanged.
24. **New scientific issues.** None discovered in this scoped correction. The claimed impact remains binary per-class FPR/FNR reporting; no broader historical/model accuracy defect is asserted.
25. **Git recommendation.** Review and commit the focused correction as `fix: report binary per-class rates one versus rest`. Preserve prior stop documents and historical results. No commit/push performed.
26. **FINAL-SCIENCE readiness.** May restart separately using the archived explicit manifest and SCI-CORR-2 baseline; rerun real-data preprocessing prechecks before training/evaluating from scratch. Preserve the mandatory scientific-stop rule. [Restart contract](sci-corr-2-restart-contract.md). This phase ends here.

Historical values remain historical measurements tied to their recorded partition and prior implementation. Current real-data results still require a separate FINAL-SCIENCE run.

GO FOR FINAL-SCIENCE RESTART
