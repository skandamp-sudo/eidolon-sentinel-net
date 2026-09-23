# SCI-CORR-1 final report

SC-1 and SC-2 are corrected within the authorized scope. No final candidate training, final scientific evaluation, final-test prediction inspection, threshold tuning or deployment publication occurred. Required regression tests use their existing isolated synthetic model fixtures; those are not a scientific candidate training run. Historical Phase 7/8 and FINAL-SCIENCE stop artifacts are untouched.

1. **SC-1 root cause.** An unordered Python set was converted to a list before the seeded shuffle, making scenario assignment depend on process hash randomization.
2. **SC-1 code change.** Added `DatasetBuilder.explicit_manifest_split` and changed the future generator to sort unique IDs before shuffling; both paths record origin, method version, scenario IDs, row counts and optional dataset identity.
3. **Explicit-manifest design.** Versioned train/validation/test assignment with exact coverage, no duplicate/overlapping/unknown IDs, required nonempty partitions, input row alignment, bound identity matching, optional expected counts and canonical manifest digest. It preserves assignment and input row order. Identity must be independently verified by the caller; the method does not hash data files itself.
4. **Deterministic-generator design.** Sorted unique IDs then the existing seeded NumPy shuffle, labeled GENERATED_DETERMINISTIC. This is for future experiments and does not reproduce the archived historical assignment.
5. **Multi-PYTHONHASHSEED results.** Fresh processes with 0, 1, 2 and random produced identical results within each mode. Both EXPLICIT_MANIFEST and GENERATED_DETERMINISTIC passed. Toy process fixtures contain one row per scenario; they are not final scientific dataset evaluation. Full outputs: [reproduction](sci-corr-1-validation/reproduction.json).
6. **Historical split preservation.** Locked [manifest](../experiments/manifests/final-science-partition.json) retains TRAIN: Benign-Monday, Bruteforce-Tuesday, DoS-Wednesday, Infiltration-Thursday, Portscan-Friday; VALIDATION: WebAttacks-Thursday; TEST: Botnet-Friday, DDoS-Friday. Rehashed all eight local files and verified metadata-derived counts **1,760,688 / 155,820 / 397,302**. Generated seed-42 validation is DoS-Wednesday and test is DDoS-Friday/Portscan-Friday, so it is explicitly not substituted.
7. **SC-2 root cause.** Post-imputation variance positions were paired with pre-imputation names, and n_features_out reported selected input width after missing columns had been dropped. The demonstrated impact was metadata reporting, not incorrect transformed values or historical prediction metrics.
8. **SC-2 code change.** Fitted constant metadata uses surviving imputer names. Public constant names derive from fitted state (including old loaded objects), and n_features_out is the actual fitted output-schema length. Imputation, scaling, selected features and ordering are unchanged.
9. **Transformed-array comparison.** **12/12 exactly equal** before versus after using the actual pre-correction implementation, across tree/linear and six missing/constant patterns. Permanent tests also compare against the unchanged sklearn numeric recipe. No tolerance-only comparison or fabricated zero columns.
10. **n_features_out.** Original eight-row reproducer now reports **51**, equal to actual transformed width. Before fitting it raises RuntimeError, consistent with output_feature_names; input width remains available separately.
11. **output_feature_names.** Preserves surviving selected-column order, with length equal to n_features_out. Tree/linear and CICIDS-like eleven-missing-column fixtures pass.
12. **Constant-feature metadata.** Original reproducer now correctly reports **iat_mean**, not pkt_size_p90. Multiple constants, no constants, no dropped columns and multiple dropped columns are covered.
13. **Save/load.** All twelve new metadata/numeric cases pass serialization round trips. A pre-correction serialized preprocessor loads with corrected public metadata and exactly identical arrays, while its bytes and private stale cache remain untouched. No migration/republication occurs.
14. **Files changed.** Two scientific source files; `tests/unit/test_scientific_corrections.py`; locked partition JSON; new SCI-CORR-1 report, restart contract, integrity and validation artifacts. Full [inventory](sci-corr-1-validation/changed-files.txt).
15. **Protected files intentionally changed.** Only `detection/dataset.py` (SC-1) and `detection/preprocessing.py` (SC-2). **21/23 unchanged, 2/23 intentionally changed.** Canonical schema/extractor/aggregation/segmentation/classifiers/anomaly/threshold source and all other protected files remain byte-identical.
16. **Previous/new SHA-256.** See the exact transition table below and [new baseline](sci-corr-1-scientific-integrity.json).
17. **Backend total.** **896 passed, 41 warnings**, 90.50 seconds. Prior 866 plus 30 new tests. Focused new/existing dataset/preprocessing suite: **61 passed**. The additional 27 warnings are expected all-missing-column imputer warnings from the correction fixtures. [Backend log](sci-corr-1-validation/backend.txt).
18. **Frontend total.** **90 passed across 6 files**. Combined total **986**. [Frontend log](sci-corr-1-validation/frontend.txt).
19. **TypeScript/build.** Both PASS. [TypeScript](sci-corr-1-validation/typescript.txt), [production build](sci-corr-1-validation/build.txt).
20. **Parity regressions.** Core live/replay, F3, F4 and F5 pass in the full backend run, as do auth/event-contract and deployment bundle tests. Test-file mapping is recorded in [summary](sci-corr-1-validation/summary.json).
21. **Frozen deployment compatibility.** Existing runtime/1.0.0 loads; the fixed synthetic feature vector yields identical preprocessing, classifier-score and anomaly-score results through the old/current numeric path. Every bundle file hash remains unchanged. Public metadata access on legacy preprocessors is corrected dynamically, while serialized bytes stay unchanged. No incompatibility requiring publication was found.
22. **New scientific issues.** None discovered in this scoped correction. Existing accepted scientific/operational limitations remain; no claim of new accuracy, calibration or production readiness is made.
23. **New baseline identity.** `sci-corr-1-29bc756272dbd981a6768a94edfaa69c75de12f0a31c2158498dbd901c4d37f2`. It records the base revision `1fb90e7db871e0e4e555589db098ce0cbf7940c0` plus exact corrected worktree hashes; no new commit is implied. Scope reviewed by the implementing agent, not represented as independent human approval.
24. **Git recommendation.** Review and commit this focused correction as `fix: make scientific partitions and preprocessing metadata reproducible`. No commit/push performed. Preserve old baselines and historical metrics.
25. **FINAL-SCIENCE readiness.** May restart as a separate phase using the explicit archived manifest and this new integrity baseline. Follow the [restart contract](sci-corr-1-restart-contract.md); do not run historical drivers unchanged or generate a new split from seed 42. This task stops before training/evaluation.

## Exact protected-file hash transition

| File | Previous SHA-256 | New SHA-256 |
|---|---|---|
| src/sentinel_net/detection/dataset.py | `d69adadcdc9e27c378ea83463cf0c31d42439d8692576fb88940ec266bc36eb5` | `267ae91eef7e7021a2180b06feede621cc8c4f6a86bcf4a533122041702ec7cf` |
| src/sentinel_net/detection/preprocessing.py | `ec282476c0ddd38b8dca65ae0fac51c14cc61a71863c39db9abd8e518660488f` | `72809d177be97dec0d0e010c3c06b2d29db24f3ffdd0e44e62d47fee5fc209d6` |

Historical values remain historical measurements tied to their recorded partition and prior implementation. SCI-CORR-1 does not assert that those measured values were wrong. New current measurements belong to the next FINAL-SCIENCE phase.

GO FOR FINAL-SCIENCE RESTART
