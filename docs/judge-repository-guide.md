# Technical judge repository guide

Sentinel-NET is a passive network-metadata research prototype for one-way observation. Start with [README](../README.md), especially the QA-runtime/scientific-candidate distinction.

| Question | Where to inspect |
|---|---|
| Packet → flow → canonical features | `src/sentinel_net/ingestion/`, `sensor/sources.py`, `sensor/pipeline.py`, `flow/`, `features/` |
| Frozen models and scientific methods | `src/sentinel_net/deployment/`, `detection/`, `evaluation/`; [final science](final-science-report.md) and `experiments/final_science_restart_2/` manifests/results |
| Behavioral/DNS/encrypted metadata | `src/sentinel_net/intelligence/`, `dns/`, `encrypted/` |
| Analyst correlation/export/API | `src/sentinel_net/operations/`, `api/routes/operations.py`, `storage/database.py` |
| SOC | `frontend/src/`; [F6 architecture](sih-f6-architecture.md) |
| Tests | `tests/unit/`, `tests/integration/`, `frontend/src/__tests__/`; complete commands in README |
| SIH requirements | [39-row matrix](sih26145-compliance-matrix.md); COMPLETE is software scope, not certification |
| Actual judge route | [Runbook](judge-demo-runbook.md), [expectations](judge-demo-expectations.json), [recovery](judge-demo-recovery.md) |
| Limitations | README, [security](../SECURITY.md), [science claims](final-science-claims.md), [freeze report](release-freeze-report.md) |
| Trusted local model prerequisites | [Artifact policy](release-artifact-policy.md); binaries are not automatically downloaded, trained or approved |

Release freeze software gates pass; the operator commit is pending. RF-1's legacy generator defect was discovered during freeze, corrected separately, and verified by regression. The fresh intended release archive passes all 962 backend tests after local fixture generation. See the release report for the preserved stop history and final results. Candidate binaries are excluded from the release tree; local copies and historically reachable Git copies remain distinct from runtime approval.

First read the disclaimers, then run the documented demo preflight with an existing trusted QA registry and privately configured key. Without that bundle, run the repository test/build commands instead; do not substitute the unapproved candidate.

The reviewed replay is 191 synthetic packets → 72 flows/events. **Its 72 DDoS labels come from a synthetic QA model, not 72 validated attacks.** Scientific accuracy/macro-F1 and zero C2 recall belong to a different fixed-partition candidate. Core/live-source parity does not validate native capture or physical diode hardware. No JA4, encrypted DNS visibility, TLS/QUIC decryption or population heuristic accuracy is claimed.

Historical phase records remain for auditability; current limits and results are in README and the release manifest. `FINAL_FREEZE_COMMIT` remains `PENDING_OPERATOR_COMMIT` until the operator reviews and creates the commit. This phase does not create a tag or presentation.
