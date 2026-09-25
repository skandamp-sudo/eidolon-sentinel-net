# Release checklist — BLOCKED

**NO-GO FOR CODE FREEZE.** RF-1: legacy test-fixture serialization can invoke active ARP resolution. Freeze instructions require STOP before behavioral source fixes. No source correction was made.

- [x] Clean starting base on `main` equals locally recorded `origin/main`: `b26004c986b13cdb2db19f024295193245095f47`, ahead/behind 0/0.
- [x] Read-only scan of all 13 locally reachable commits / 687 unique blobs; no real credential discovered. Remote-only/unreachable history and exhaustive secret absence are not verified.
- [x] Every root candidate classified; 26 obsolete artifacts removed with local backups. `scratch.py` and scientific provenance retained.
- [x] Runtime/generated artifact ignore audit; narrow judge-PCAP exception retained.
- [x] Model binaries inventoried and manifest-bound; local copies intact.
- [ ] Proposed eleven-binary Git untracking: NOT PERFORMED after STOP.
- [x] 23 protected source hashes, 14 candidate components, QA runtime hashes verified unchanged before deserialization.
- [x] Judge PCAP independently regenerated to identical 16,833 bytes / SHA / 191 packets.
- [x] README/security/current claims corrected; matrix has 39 rows (12 COMPLETE, 25 PARTIAL, 2 NOT VERIFIED).
- [x] Clean archive without candidate binaries imports source and builds frontend using existing local dependencies.
- [x] Clean archive initial backend: 958 passed, 1 skipped, 43 warnings; frontend: 100 passed / seven files; TypeScript/build PASS.
- [ ] Full zero-skip clean backend gate: blocked by missing legacy generated fixture and RF-1.
- [ ] Final no-Internet judge verification, golden replay and interruption/recovery recheck: NOT RUN this phase after mandatory STOP. Prior judge-demo evidence is retained, not relabelled current.
- [x] Installed Python dependency check: 63 packages compatible; no downloads. Current vulnerability-advisory audit NOT VERIFIED offline.
- [x] No application/scientific/model/threshold change; no commit/push/tag/publication/PPT.
- [ ] Separately authorize RF-1 correction and regression, then restart release audit and all pending gates.
- [ ] Operator review/commit/tag only after a later GO decision.

`FINAL_FREEZE_COMMIT = PENDING_OPERATOR_COMMIT`

Do not use the previously proposed legacy generator preparation command. Do not bypass permissions, mock away the defect to claim offline success, or alter expected replay hashes. Physical projector and spoken rehearsal remain pending operator tasks.
