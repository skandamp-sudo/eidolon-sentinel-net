# Golden judge demo

This is a **pipeline mechanics demonstration using an existing synthetic QA model**. It is not a demonstration of the evaluated scientific candidate. The QA model labels all 72 fixture flows DDoS, including ordinary UDP. Disclose this before opening events. No model was retrained, substituted, approved or published.

Runtime: `runtime/1.0.0`, manifest `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f`, existing approval `test-operator`, evaluation `synthetic-contract-test-only`. Current local registry: `/tmp/sentinel-rw4-preview/registry`. This temporary location is a portability risk: preflight must pass on the actual presentation host. Never regenerate a replacement model or publish the candidate to recover.

Final candidate: `final-science-xgboost/2026.09.23-seed42`, deployment manifest `7d503614ac076f8e0014d0f060e8052e8bb29e6f52fd827357e3f6416965caa6`; scientific manifest `29898386acd94ec2e8641947cafeeedbde2363f82195eddcad9baf95d55e9573`. Different artifacts, NOT APPROVED, NOT PUBLISHED. Keeping the existing QA bundle preserves prior pipeline results but provides no scientifically evaluated runtime classification claim.

## Preparation before judges arrive

Use the repository root in Terminal 1. Dependencies must already be installed. No Internet, installation or privilege changes are part of the demo. Keep terminals and Settings off the projected screen when configuring credentials. The browser never needs dataset/home/registry paths.

```zsh
read -s 'SENTINEL_API_KEY?Enter a private local demo key (16+ characters): '
export SENTINEL_API_KEY
export PYTHONPATH=src:.
.venv/bin/python scripts/judge_demo.py preflight --registry /tmp/sentinel-rw4-preview/registry
.venv/bin/python scripts/judge_demo.py run --registry /tmp/sentinel-rw4-preview/registry
```

`run` repeats preflight, creates a fresh private temporary workspace/SQLite DB, clears ambient Sentinel overrides, and invokes the actual `sentinel-net replay` CLI on loopback port 8010. Default detector thresholds remain unchanged. No database is deleted. Startup automatically replays unpaced. Wait for `Replay complete` / `REPLAY_COMPLETE`; a listening server alone is not success.

Then Terminal 2, from `frontend`:

```zsh
npm run preview -- --host 127.0.0.1 --port 5174 --strictPort
```

Open `http://127.0.0.1:5174/settings`. Enter `http://127.0.0.1:8010` and the same key, then Connect. The password input clears. Use Sensor to verify REPLAY COMPLETE, 191 parsed packets, 72 completed flows/events, zero errors. This fast path normally finishes replay before browser subscription: WS Deliveries may correctly be zero. REST supplies retained events; the verification harness separately proves WS delivery when subscribed before replay.

The single PCAP lasts 25 capture seconds, but unpaced replay takes under one measured second. Do not imply that replay completion indicates a live sensor. For another fresh run, stop these two owned foreground processes with Ctrl-C, then repeat. Never kill an unknown process.

## Presenter route (target 5–6 minutes; spoken rehearsal not measured)

1. **0:00–0:45 Sensor:** recorded replay, passive software properties, no probing/injection/decryption/training. State the QA/candidate distinction and native-capture/hardware limits.
2. **0:45–1:30 Detections:** 72 actual events. Open source `192.0.2.20`, destination port `1059` (latest `.20` row) for PORT_FANOUT. Open latest `.30`, source port `43007`, for periodicity. These are contextual observations, not confirmed attacks. DDoS headings come from the synthetic QA model.
3. **1:30–2:20 DNS:** source `192.0.2.40`; paired TXT/NXDOMAIN metadata, long/high-diversity labels and six contextual signals. Entropy does not prove DGA. Do not filter by DNS Tunneling threat class: model class and heuristic signals are separate.
4. **2:20–3:20 TLS/QUIC:** `.50` shows split ClientHello reassembled, peer ServerHello, `judge.example.test`, h2/http/1.1, JA3/JA3S. `.60` shows one visible QUIC header. JA4 NOT IMPLEMENTED. Neither payload nor QUIC Initial is decrypted; QUIC bytes are an inert header fixture, not a completed connection.
5. **3:20–4:15 Investigation:** correlation references and labelled capture/processing timeline. Each investigation has one event with multiple evidence sources; no cross-flow identity claim or combined probability.
6. **4:15–4:45 Export:** Download evidence JSON; wait for “Export SHA-256 verified”. Digest verifies exact bytes, not authorship, signature or trusted time.
7. **4:45–5:45 Sensor scientific summary:** separate fixed-partition results: 75.94% accuracy, 0.2675 macro-F1, C2 recall zero, DDoS recall 26.68%, benign→malicious FPR 0.103%, IF ROC-AUC 0.818. These describe the unapproved candidate, not runtime/1.0.0. Threshold-dependent anomaly results remain exploratory.

Find events by addresses/ports, not UUIDs. IDs and processing timestamps intentionally change. Tables can scroll horizontally on mobile. Browser Find can locate ENCRYPTED SESSION or Scientific evaluation on long pages. Use 100% zoom.

**90-second path:** Sensor replay/QA disclaimer (20s), TLS `.50` observation and separate scores (30s), timeline/export (25s), candidate weakness/limits (15s).

**3-minute path:** assurance (30s), latest `.30` periodicity (30s), `.40` DNS (30s), `.50` TLS (35s), export (25s), science/limits (30s).

## Reproduce validation

```zsh
PYTHONPATH=src:. .venv/bin/python scripts/generate_judge_demo.py
PYTHONPATH=src:. .venv/bin/python scripts/verify_judge_demo.py --registry /tmp/sentinel-rw4-preview/registry
```

The generator only writes an offline PCAP. The verifier creates five fresh DBs: three equal runs, one deliberate interruption, one clean recovery. It invokes real frozen inference and real authenticated API/WS/export handlers with an in-process ASGI transport; it never inserts fixtures into storage. All 72 exports are checked on each complete run. Detailed observations are in the expectation manifest and validation JSON. Do not substitute older `generate_demo_pcap.py`, which is outside this reviewed route.
