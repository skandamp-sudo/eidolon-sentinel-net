# FINAL-SCIENCE restart contract after SCI-CORR-2

1. Use `docs/sci-corr-2-scientific-integrity.json` as the authorized corrected scientific baseline; reverify all 23 file hashes before and after evaluation. Keep SCI-CORR-1's dataset/preprocessing corrections.
2. Use only `experiments/manifests/final-science-partition.json` with `DatasetBuilder.explicit_manifest_split`. Independently hash dataset files and pass observed identity; verify exact scenario coverage/no overlap and counts 1,760,688 / 155,820 / 397,302. Do not substitute any generated split or rerun historical drivers unchanged.
3. Rerun the real-data training-only preprocessing precheck: missing columns, surviving ordered names, actual width, n_features_out and constants. Preserve missing data and canonical feature math.
4. Only then train/evaluate from scratch under the established recipe, fixed partition and validation-only threshold protocol. SCI-CORR-2 itself performs no scientific candidate training/evaluation.
5. Preserve the mandatory scientific-stop rule for any newly reproduced defect. No silent fix or continuation; no automatic candidate approval/publication.

For each class, FPR and FNR are one-versus-rest. The project's existing zero-denominator convention remains 0.0; always report support and do not interpret that convention as measured performance when support is absent. Operational benign-to-malicious false-positive rate is the fraction of actual benign examples predicted non-benign: benign one-versus-rest **FNR**, not benign one-versus-rest FPR. Benign one-versus-rest FPR measures non-benign examples predicted benign.

The correction changes rate reporting only. Aggregate metrics, predictions, matrix construction, AnomalyReport, preprocessing, feature extraction, thresholds and runtime inference are not modified. Preserve historical reports and previous scientific-stop evidence.
