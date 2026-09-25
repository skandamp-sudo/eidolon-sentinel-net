# EIDOLON // SENTINEL-NET

**Passive AI threat detection for unidirectional IP traffic.**

Sentinel-NET is a research prototype that turns observed packet metadata into model results and separate contextual evidence for analyst investigation. It records only observed directions; missing reverse traffic is not synthesized.

> **Judge demo:** the deterministic recorded replay currently uses a **synthetic QA / contract-test runtime model**. Its 72 DDoS labels demonstrate pipeline execution, **not 72 validated attacks or scientific accuracy**. The evaluated scientific candidate is different, not approved and not operationally published. Eleven candidate binaries are excluded from the intended release tree while local copies remain hash-bound; historical Git copies are still reachable. Git availability is distribution even without runtime approval.

## Release freeze verification

**GO FOR CODE FREEZE — operator commit pending.** RF-1 was discovered during the initial freeze, corrected separately in `9c186a0`, and verified by no-network regression. Final worktree and clean-archive suites pass with zero failures/skips. See the [freeze report](docs/release-freeze-report.md) for evidence, historical blocker details and limitations. This is a software freeze decision, not production or scientific candidate approval.

## Pipeline

```text
Traffic / PCAP → passive parsing → flow aggregation
→ 52 canonical features (schema 2.0.0) → frozen ML / anomaly detection
→ F3 behavioral evidence → F4 passive DNS → F5 TLS/QUIC metadata
→ SQLite / REST / WebSocket → F6 analyst investigation → SOC / verified export
```

The live source architecture uses a receive-only capture backend; the judge demonstration is **RECORDED TRAFFIC REPLAY**. Native real-interface capture on the presentation host and a physical data diode are **NOT VERIFIED**. The analysis path does not probe monitored hosts, inject traffic, perform reputation lookups, decrypt payloads or train models at runtime. The SOC/API intentionally use network connections for local operator access; structural passivity refers to the monitored network, not absence of all network I/O.

The SOC provides distinct model/anomaly results, bounded F3/F4/F5 context, source/model provenance, labelled timelines and SHA-256-verified JSON exports. Heuristics and fingerprints are context, not malware verdicts or a combined attack probability. Export digests verify bytes, not authorship or legal chain of custody.

## Start reviewing

- [Judge repository guide](docs/judge-repository-guide.md): source, tests and evidence map.
- [Judge demo runbook](docs/judge-demo-runbook.md): local commands, mandatory disclaimer and presenter routes.
- [Demo expectations](docs/judge-demo-expectations.json): observed results, hashes and claims boundaries.
- [39-row SIH26145 matrix](docs/sih26145-compliance-matrix.md): implemented software scope and remaining gaps; not certification.
- [Architecture](ARCHITECTURE.md), [security](SECURITY.md), [datasets](DATASETS.md).
- [Release checklist](docs/release-checklist.md) and [freeze manifest](docs/release-freeze-manifest.json).

## Scientific results — separate from the QA runtime

The final scientific evaluation uses the fixed CICIDS2017 scenario-aware partition, seed 42, 397,302 test rows. These are candidate results, not the runtime judge replay's results.

| Metric | Measured result |
|---|---:|
| XGBoost accuracy | 0.759440 |
| XGBoost macro-F1 | 0.267512 |
| Benign → malicious false-positive rate | 0.103% |
| C2 supervised recall | **0%** |
| DDoS supervised recall | **26.68%** |
| Isolation Forest ROC-AUC | 0.818401 |

ROC-AUC is not accuracy. No primary-test reconnaissance/exfiltration support exists. Threshold-dependent anomaly results remain exploratory. F3/F4/F5 do not have population-level accuracy estimates. See [final science report](docs/final-science-report.md), [metrics](docs/final-science-metrics.json) and [claims](docs/final-science-claims.md).

Runtime `runtime/1.0.0` manifest: `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f` — **SYNTHETIC QA MODEL; PIPELINE DEMONSTRATION ONLY**.

Scientific candidate manifest: `29898386acd94ec2e8641947cafeeedbde2363f82195eddcad9baf95d55e9573`; deployment candidate manifest: `7d503614ac076f8e0014d0f060e8052e8bb29e6f52fd827357e3f6416965caa6`. **SUITABLE FOR OPERATOR REVIEW; NOT APPROVED; NOT PUBLISHED to the runtime registry.** Git history previously distributed the candidate binaries; no confidentiality or retroactive withdrawal is implied. See [artifact policy](docs/release-artifact-policy.md).

## Local verification

Python 3.12+, the existing local `.venv`, Node/npm, and installed frontend dependencies are required. `uv.lock` and `frontend/package-lock.json` record dependency resolution. Provision dependencies before offline presentation; these commands do not install or download anything.

From the repository root:

```sh
PYTHONPATH=src:. .venv/bin/python tests/fixtures/generate_test_pcap.py
PYTHONPATH=src:. .venv/bin/python -m pytest -q
```

From `frontend/`:

```sh
npm test
npm run typecheck
npm run build
```

Generate the ignored legacy fixture before the full suite so its fixture-dependent test runs. RF-1 regression blocks the inspected resolver/send/routing/interface/socket paths. Frame bytes are deterministic; existing wall-clock record timestamps remain variable.

Final freeze verification: **962 backend passed, zero failures/skips, 43 warnings** in both worktree and clean archive; **100 frontend tests across seven files**, strict TypeScript and production build pass in both trees. The unchanged loopback test passes on the normal host; sandbox binding restrictions are not a product failure or a passing substitute. See the freeze report for exact results.

For the judge fixture, from the repository root:

```sh
PYTHONPATH=src:. .venv/bin/python scripts/generate_judge_demo.py
PYTHONPATH=src:. .venv/bin/python scripts/verify_judge_demo.py --registry "$DEMO_REGISTRY"
```

`DEMO_REGISTRY` must name the existing trusted QA registry, not the unapproved candidate directory. The reviewed local machine's path is documented in the runbook. The verifier blocks socket connections/DNS use, runs three fresh replays, an interruption and clean recovery, and checks real REST/WS/export handlers. It does not generate or approve models.

The [preflight](docs/judge-demo-preflight.md) requires a privately configured API key and free loopback ports. The [launcher](scripts/judge_demo.py) creates a fresh isolated database and invokes the actual `sentinel-net replay --pcap ... --model runtime/1.0.0` command. No arbitrary database deletion. The PCAP is 16,833 bytes / 191 packets and produces 72 flows/events under the pinned QA runtime.

## Limits to preserve

- QA runtime predictions are not scientific accuracy evidence; the candidate stays separate and unapproved.
- Zero C2 supervised recall, limited DDoS recall, missing primary-test recon/exfiltration support, exploratory anomaly thresholds.
- No population-level accuracy estimates for behavioral/DNS/encrypted-session heuristics.
- JA4 **NOT IMPLEMENTED**; encrypted DNS unavailable; TLS application data and QUIC Initial payloads are not decrypted.
- Native capture and physical diode **NOT VERIFIED**. Replay/source-adapter parity is software validation only.
- Exact per-flow timestamp/packet-size histories retain a prototype resource limitation: active-flow caps do not strictly bound every flow's memory.
- Performance measurements are host/workload-specific; no capacity or latency guarantee.
- Physical projector and spoken rehearsal remain operator tasks. A technical browser route was measured separately.

## Repository

`src/` backend; `frontend/` SOC; `tests/` behavioral/security/integration checks; `scripts/` maintained engineering tools; `experiments/` manifests/results and local trusted scientific artifacts; `docs/` evidence and operations; `data/judge-demo/` the narrowly authorized synthetic PCAP. Historical phase records remain for provenance and may describe superseded results. `scratch.py` is retained because SCI-CORR-2 records reference its cleanup state.

MIT license — see [LICENSE](LICENSE).
