# FINAL-SCIENCE restart contract after SCI-CORR-1

The next FINAL-SCIENCE run must use `experiments/manifests/final-science-partition.json` through `DatasetBuilder.explicit_manifest_split`. Do not call `scenario_aware_split` to reconstruct the historical assignment. Do not rerun the historical evaluation drivers unchanged: they generate a partition and write historical output paths.

Before training, independently inventory/hash the local dataset, validate labels/adapter/scenario IDs, and construct observed identity with the manifest's `dataset_id` and filename-to-SHA-256 structure. Pass that observed identity as `dataset_identity`; do not simply copy the expected identity from the manifest and claim it was verified. The splitter checks exact equality of supplied versus expected identity and records it, but does not access or hash files itself.

```python
manifest = json.loads(Path('experiments/manifests/final-science-partition.json').read_text())
split = DatasetBuilder().explicit_manifest_split(
    X, labels, scenarios.tolist(), manifest,
    dataset_identity=independently_verified_dataset_identity,
)
```

The manifest fixes TRAIN to Benign-Monday, Bruteforce-Tuesday, DoS-Wednesday, Infiltration-Thursday and Portscan-Friday; VALIDATION to WebAttacks-Thursday; TEST to Botnet-Friday and DDoS-Friday. It binds all eight dataset file hashes and expected counts 1,760,688 / 155,820 / 397,302. SCI-CORR-1 rechecked these file hashes and summed parquet metadata counts; it did not read labels, fit a scientific model or inspect final-test predictions.

Explicit splitting validates version, exact train/validation/test keys, list/string IDs, uniqueness within/across partitions, exact observed-scenario coverage, required nonempty partitions, matching row dimensions, optional identity binding and optional expected row counts. It preserves assignment-list order and input row order. Empty validation/test can be explicitly allowed for other experiments through `required_partitions`; all three are required by default. Provenance includes `EXPLICIT_MANIFEST`, method version, canonical manifest digest, scenario lists, observed identity, observed counts and a null random seed. The manifest digest hashes compact sorted-key JSON; the integrity baseline separately records the exact manifest-file digest.

The generated method is for future experiments. It sorts unique IDs before seeded shuffling and reports `GENERATED_DETERMINISTIC`, seed, method version, scenario IDs, row counts and optional observed identity (null if not supplied). This is deterministic for the same inputs, configuration and relevant library behavior, not a promise that it recreates an old arbitrary set order. Do not relabel it as the historical experiment.

SC-2 changes metadata access, not imputation/scaling mathematics. Before fitting, `n_features_out` now raises RuntimeError like `output_feature_names`, because a surviving output schema does not yet exist. After fitting, both report the actual surviving sequence/width. `constant_features` derives its public value from fitted names and variances, so a legacy serialized private cache can remain stale without corrupting public reporting. Loading does not rewrite artifacts. A newly saved preprocessor records corrected fitted metadata. Existing frozen-bundle checksums are unchanged; synthetic-vector numeric/classifier/anomaly parity passed.

Historical values remain historical measurements tied to their recorded partition and prior implementation. SCI-CORR-1 does not recalculate or invalidate them. Restarting FINAL-SCIENCE requires new candidate/evaluation artifacts and the new SCI-CORR-1 scientific-integrity baseline. No scientific evaluation is started by this correction phase.
