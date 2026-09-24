# FINAL-SCIENCE-RESTART-2 execution record

This directory contains one completed-seed evaluation workflow, not an approved deployment registry. While execution is in progress, only completed checkpoints exist. The final scientific manifest is created only after primary and supplementary outputs and regression gates exist.

- `run.py`: original primary harness, locked seed42 recipe and explicit partition; original process stopped after saved XGBoost, during an unsaved Random Forest fit.
- `resume.py`: continuation from the saved XGBoost/preprocessor; it restarts only the unfinished Random Forest and subsequent stages. `resume-provenance.json` records retained hashes and harness identity. An interrupted invocation with no logged work was restarted; no results were selected across completed seeds.
- `locked-config.json`: recipe recorded before TEST evaluation. `training.json` records actual fitted estimator parameters/classes/features and elapsed fit times. XGBoost's native resolved configuration is separately saved. JSON null for its `missing` get_params value represents numpy.nan, as documented in the supplementary protocol.
- `supplementary-protocol.json`: fixed before TEST evaluation; no scenario reassignment. Supplementary IF family ranking is distinct from the supervised primary experiment. Prefix robustness is explicitly limited.
- `supplementary.py`: runs only after primary candidate reload parity succeeds.
- `finalize.py`: archives previous stop artifacts, assembles reports after required outputs/gates, binds all component hashes and marks serialized candidate files read-only. Read-only files/checksums are local integrity controls, not authentication against an owner who can change permissions.

Run with the project's Python environment and `PYTHONPATH=src`. Do not rerun into this directory or overwrite recorded artifacts. A new scientific run requires a separate output directory, fresh identity checks and the same explicit split manifest; output paths must be changed consistently. Do not substitute the generated scenario split. Preserve the recorded adapter file order for exact row-order reproduction.

Protected scientific source, historical Phase7/8 reports and approved deployment registry are not edited by this workflow. Raw classifier predictions provide supervised metrics; runtime unknown-label confidence gating/severity/event enrichment are separate. Post-evaluation regression test fixtures train their own small synthetic test models, not new scientific candidates.
