# Release artifact policy

The evaluated scientific candidate is **SUITABLE FOR OPERATOR REVIEW, NOT APPROVED, NOT PUBLISHED to the runtime registry**. The previous Git tree nevertheless distributed its binaries. Those are distinct meanings of publication: Git availability is real distribution even without application deployment approval.

**Final policy:** eleven `.joblib` files under `experiments/final_science_restart_2/` have been removed from the index using `git rm --cached`, without deleting local copies. Each path has an exact ignore rule. Their local hashes remain valid. Keeping these unapproved binaries in a new release would distribute them, so the intended release excludes them. Earlier commits still contain them; this is neither confidentiality nor retroactive removal. No history rewrite was performed.

The local artifacts are retained for scientific reproduction and bound by the original 14-component ledger (eleven binary components plus candidate thresholds/manifest/checksums). Manifests, hashes, configuration, split identity, results and scientific harnesses remain tracked. Do not edit their hashes to accept replacement bytes. Restore binaries only from an operator-trusted existing source and verify every expected hash before loading. Joblib is executable serialization; hashes do not make an untrusted producer safe.

| Local artifact | Purpose |
|---|---|
| `RandomForest.joblib`, `LogisticRegression.joblib`, `XGBoost.joblib` | Fixed-partition supervised scientific comparisons |
| `IsolationForest.joblib` | Primary anomaly ranking evaluation |
| `novelty-ddos-iforest.joblib` | Supplementary held-out-family research |
| `tree-preprocessor.joblib`, `linear-preprocessor.joblib`, `novelty-ddos-preprocessor.joblib` | Corresponding fitted research preprocessing |
| `candidate/classifier.joblib`, `candidate/anomaly.joblib`, `candidate/preprocessor.joblib` | Unapproved deployment-format candidate copies |

These files are needed to reproduce artifact-based scientific inference, not to import/test/build the repository or run the pinned judge QA replay. Tests construct their own isolated fixtures. The demo loads the separately existing `runtime/1.0.0` registry supplied by the operator. A fresh release archive excluding all eleven binaries imported source and passed 962 backend tests with zero skips after guarded legacy fixture generation, 100 frontend tests, strict TypeScript and build. Three fresh golden replays, interruption/recovery, preflight and the actual launcher passed using only the separately trusted QA registry. No clean checkout is claimed to contain the evaluated model or datasets.

The QA registry is also a trusted local prerequisite, not silently reconstructed by setup. It remains **SYNTHETIC QA MODEL — PIPELINE DEMONSTRATION ONLY**; all 72 current labels are DDoS and are not accuracy evidence. Its reviewed manifest/ledger/artifact hashes remain pinned and unchanged. It must not be confused with the scientific candidate.

Old root presentation scripts/images and their root-only Playwright package files have no engineering/demo dependencies and are removed, with local backups preserved and historical Git copies retained. `scratch.py` stays because SCI-CORR-2 records reference its cleanup state. Existing scientific logs stay as historical provenance, including uncertain legacy logs; newly generated logs are ignored. Existing validation logs may contain local paths and historical warnings. They are not judge-facing operational screens and have not been rewritten to conceal original evidence.

Only `data/judge-demo/judge-demo.pcap` is excepted from the general PCAP ignore rule. Runtime databases, sidecars, local environments, node_modules, build metadata, Office locks and new logs remain ignored. No arbitrary PCAP exception, model approval or production deployment is introduced.
