# Release checklist — final software gates passed

**GO FOR CODE FREEZE — BEGIN SIH PRESENTATION.** Operator review/commit remains pending. This is not scientific candidate approval or production readiness.

- [x] `main` equals local `origin/main`: `9c186a0d977463261a0b0664ac420887b188bc23`, ahead/behind 0/0. Remote freshness not fetched.
- [x] RF-1 discovered during initial freeze, corrected separately, committed in base, and all three no-network regressions pass. Initial stop evidence preserved verbatim.
- [x] Unchanged loopback test passes on normal host; sandbox denial recorded accurately.
- [x] Complete worktree backend: 962 passed, zero failures/skips, 43 warnings.
- [x] Complete fresh archive backend: 962 passed, zero failures/skips, 43 warnings; legacy generated fixture no longer skipped.
- [x] Frontend: 100 passed / seven files in both trees; strict TypeScript and production builds PASS.
- [x] All eleven candidate binaries absent from tested archive; index-only untracking performed; local bytes preserved; exact ignore rules.
- [x] 23 protected source hashes, 14 local candidate components and QA runtime hashes unchanged.
- [x] No required Internet dependency demonstrated under blocked socket/DNS use; no host-wide zero-traffic claim.
- [x] Three fresh golden 191-packet/72-event replays and clean recovery match prior substantive hashes, scores/evidence/correlation/timeline.
- [x] Interruption drains accepted events; REST/WebSocket/export verification passes.
- [x] Clean archive preflight and actual loopback launcher pass with separate trusted QA registry.
- [x] Core/F3/F4/F5/F6/auth/REST/WS/retention/lifecycle/replay/frozen-loader/SCI-CORR/judge/RF-1 regressions pass.
- [x] Prior root/secret/privacy audit retained; new delta reviewed; no new credential discovered, no exhaustive absence claim.
- [x] Final status, unstaged/cached diffs, whitespace checks and per-file classification reviewed.
- [x] Reports/manifest/guide retain synthetic QA vs scientific candidate distinction and all limitations.
- [x] No source/model/threshold/science modification, commit/push/tag/publication/PPT in this resumed phase.
- [ ] Operator selective staging/review/commit, actual commit recording and optional tag/push under explicit authorization.
- [ ] Presentation preparation as a separate task; physical projector/spoken rehearsal.

`FINAL_FREEZE_COMMIT = PENDING_OPERATOR_COMMIT`

Exact evidence: [report](release-freeze-report.md), [manifest](release-freeze-manifest.json), `release-freeze-validation/resume/`. Historical stop snapshots are under `release-freeze-validation/initial-stop-*`. Native interface/physical diode remain unverified; scientific candidate remains NOT APPROVED / NOT PUBLISHED to runtime. Restart the local demo before presentation; validation processes are stopped.
