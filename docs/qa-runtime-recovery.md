# Exact trusted QA runtime recovery

Verification date: 2026-09-29. This report is new post-freeze operator evidence; no frozen evidence file was replaced.

## Identity and all required contents

Canonical registry: `.local/sentinel-qa-registry/`. Bundle directory: `runtime/1.0.0/` beneath that root. Compatibility path: `/tmp/sentinel-rw4-preview/registry` points to the stable registry; the launcher itself uses the stable path.

Runtime `runtime/1.0.0`, schema `2.0.0`, 52 features. Original status `approved`, approver `test-operator`, evaluation reference `synthetic-contract-test-only`. Created `2026-09-21T17:26:35.647496+00:00`; approved `2026-09-21T17:26:35.717343+00:00`. These are recovered original fields, not a new scientific approval. The distinct scientific candidate remains CANDIDATE, not approved and not published.

The immutable expected values come from `docs/judge-demo-scientific-integrity.json`, `runtime_components`. Each file was hashed after reconstruction and again after copying to its canonical destination, before the trusted runtime loader was invoked.

| File | Expected SHA-256 (also actual) | Result |
| --- | --- | --- |
| anomaly.joblib | `153cf24fde1ff649d6a8e8a0dcc450b45253952c346116c1f1e3aa34f69a6e33` | MATCH |
| anomaly_explainer.joblib | `e5aa35cc8b36aa92161ff9db70fff17c1e1b3f0817ffceb0afd9e2fac1c30433` | MATCH |
| preprocessor.joblib | `d2312c5f9b08abd9274fc5a872aed394215abaf0185ecd76bcbf8c4effb12eae` | MATCH |
| thresholds.json | `e3ee08d050b20ba04716c47adb8205dcf7b5ce4a487cc27c11e0f98bc21a9b14` | MATCH |
| classifier.joblib | `42b1095b6a0ff3b45cd7fc5ace63a83e33a070b2a350d0ecb8298b242c733f22` | MATCH |
| manifest.json | `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f` | MATCH |
| checksums.json | `1c2d606d9ac707e0bc2c2570bf520a8a39fb2ac217a9c48fc6ce59e296b52ce0` | MATCH |

## Search and reconstruction provenance

The preceding recovery pass searched accessible project/home/Desktop/Documents/Downloads/Trash/local backup and temporary/cache locations, including `/private/tmp` and `/private/var/folders`, without following symlinks or accessing external storage. It hashed 105 candidate files and found no exact artifact matches. 269 locations were inaccessible; dependency folders, Git internals and cloud-backed folders were excluded from that filesystem walk. The accessible search therefore is not an assertion that every possible local backup was inspected. Git history/worktree information, fixtures and shell history were also inspected. No existing complete bundle was found.

The original manifest bytes and creation procedure were recovered from local task history `rollout-2026-09-20T22-57-03-01a0bfdb-6a75-76c0-a80b-4d825962b952.jsonl`, lines 1194 (fixture invocation) and 1667 (manifest output). The original manifest's terminating newline is part of its exact hash.

An isolated `git archive 7e8a48b` supplied the historical source, including the preprocessor before later scientific corrections. The recovered procedure calls `tests.unit.test_passive_sources.real_detector.__wrapped__()`, then `tests.unit.test_sensor_runtime_model.save_pipeline(registry, detector)`. It uses the original RandomState(42), 40x52 normal fixture, original benign/ddos labels and estimator configurations. Only the two calls to the bundle module's clock were supplied the recovered original created/approved timestamps. No current source was patched and no new training/data/parameter choice was made.

All original dependencies matched: Python 3.12.14, NumPy 2.5.2, SciPy 1.18.1, scikit-learn 1.9.0, XGBoost 3.4.1, joblib 1.6.0. The reconstruction reproduced every frozen file SHA exactly; no differing reconstruction was accepted. The original approved metadata and checksum ledger are byte-identical. Recovery scratch source, manifest and hash results are retained under ignored `.local/qa-recovery-work/`; model binaries are not tracked.

## Operational verification

- Trusted current runtime loader and judge preflight: PASS, including pinned PCAP, manifest, ledger, schema and 23 protected scientific files.
- Focused command: `PYTHONPATH=src:. .venv/bin/python -m pytest tests/operator/test_sih_launcher.py tests/unit/test_judge_demo.py tests/unit/test_offline_fixture_generation.py -q`.
- Result: **18 passed, 1 existing Starlette deprecation warning in 8.63 seconds**. The operator boundary tests cover credential persistence/permissions and hostile bootstrap requests; existing judge/RF-1 tests were preserved.
- Two sequential real Chrome browser integration cycles: automatic authentication, authenticated API and WebSocket, **191 packets / 72 completed flows / 72 events**, one subscriber. Missing API credential returned 401; reuse of the bootstrap grant returned 410.
- Both cycles retained the credential and found no key in stdout/stderr, URLs, browser console or HTML. Both SIGINT shutdowns released ports 8010/5174 and removed owned temporary workspaces. An immediate second invocation passed after the first cleanup completed its bounded TCP-state wait.
- Occupied-port tests on both ports failed closed and preserved the existing listeners.
- Normal `./run-sih-demo.sh` default-browser verification: **PASS**: macOS accepted the browser open request, automatic API/WebSocket authentication reached DEMO READY, and SIGINT cleanup released both ports without secrets in the log.
- Integration results and logs are retained under `.local/qa-recovery-work/`; these local diagnostic files are not frozen release evidence.

## Freeze integrity and limits

All 23 SCI-CORR-2 protected files and all 14 scientific candidate component hashes match their recorded values. No protected application, model, threshold, schema, judge PCAP or frozen release evidence file was modified. HEAD and frozen tag target remain `5e3673b309f81fc24fb96186e83caf1f61db504f`; annotated tag object remains `f32e2e26f9686a426d02913b33b8cbd9085f05dd`. No commit, push, publication or retag occurred.

No frontend code changed; frontend typecheck/build and full backend suite were not rerun for this recovery. The existing production frontend build was exercised by real browser integration. No throughput/latency benchmark was run. The synthetic 72 DDoS labels demonstrate pipeline execution, not scientific accuracy or confirmed attacks. Local-user compromise, deletion of ignored local files, browser storage restrictions and force-kill cleanup limitations remain as documented in the operator guide.

## Changes and next action

Operator-only changes: stable registry path and failure message in `scripts/run_sih_demo.py`; ignored stable bundle/scratch paths in `.gitignore`; updated `docs/sih-one-command-demo.md`; this new report. Existing uncommitted launcher, shell entry point and operator tests are preserved. No new test case was needed for the constant path change; the focused suite and live process/browser checks were rerun.

Run `./run-sih-demo.sh` from the project directory and leave its Terminal open. It opens the frontend and handles local credentials automatically. Stop with Control+C and wait for cleanup before restarting. Preserve a local backup of the verified seven-file bundle; Git intentionally excludes it.

Recommended commit: `feat(tools): add local one-command SIH demo bootstrap`.
