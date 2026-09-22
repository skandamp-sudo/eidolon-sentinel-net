# SIH-F4 completion report

**GO FOR SIH-F5** — all 23 F4 acceptance gates pass within the documented passive prototype scope. This is a phase-completion decision, not production readiness or a malware-accuracy claim. SIH-F5 has not started.

1. **DNS parser architecture:** independent iterative wire reader consumes existing retained raw bytes after canonical ingest. One bounded engine is owned by the shared processing worker. No protected canonical parser/feature/model code changed. [Architecture and exact limits](sih-f4-architecture.md).
2. **Supported transports/messages:** complete UDP/53 datagrams and up to four complete TCP/53 length-prefixed messages inside one segment; Ethernet/two VLANs, IPv4/direct IPv6, standard DNS opcode. TCP reassembly, retransmission suppression, nonstandard ports, fragmented DNS and encrypted DNS decoding are outside this phase. Explicit parser status distinguishes parsed, truncated, malformed, unsupported and encrypted/unavailable.
3. **Parser safety:** 4096 bytes/message, four questions, 64 total RRs, 32 labels/name, 63 bytes/label, 255 decoded wire-name bytes, 16 pointer hops, visited-offset loop checks, no recursion, checked envelope/record lengths, and a bounded TCP framing budget. Unsupported/broken messages never populate DNS behavioral windows or generate DNS threat findings.
4. **Normalization:** deterministic lowercase ASCII, terminal-dot removal, no resolver/WHOIS/reputation lookup, no lossy binary decoding, no IDNA language model. Last-two-label parent grouping is explicitly a proxy, not registrable-domain truth.
5. **Lexical/entropy evidence:** exact length, label count, repeated labels, digit/alphabetic/hexadecimal ratios, character diversity, full-name/per-label Shannon entropy, sample sizes and scope; high entropy requires adequate length on the same label. Operational reference thresholds are centralized and saved with evidence. N-grams deliberately omitted without a validated reference corpus.
6. **DGA-like evidence:** minimum query observations, diverse parent proxies and elevated entropy must combine with repeated long labels or sufficiently frequent conservatively paired NXDOMAIN observations. One-way queries work without manufacturing response context. Entropy alone never means DGA.
7. **Tunnelling-like evidence:** repeated client/parent-proxy observations combine unique names, adequate count/rate, long labels and elevated entropy. Neither a lone long name nor TXT independently triggers the combined finding. This is review context, not confirmed tunnelling/exfiltration.
8. **QTYPE/response analysis:** named and unknown numeric types, bounded distributions, TXT fraction, observed response RRs, effective rcode (including EDNS extension), and NXDOMAIN count/fraction. Response echoes do not inflate query counts. Multi-question messages count once per parent message rate. No RDATA is retained.
9. **Transaction correlation:** capped 1024-entry LRU, 10-second capture-time TTL, both endpoint ports/IPs, transport, ID and normalized question signature. Opposite QR match consumes the entry. Tests cover port/question mismatches, reuse, expiry and reverse arrival order. Identical tuple/ID/question reuse remains observationally ambiguous.
10. **Unidirectional semantics:** QUERY_ONLY, RESPONSE_ONLY and PAIRED refer to the latest retained message. No visible response means unobserved, never timeout/failure/NXDOMAIN. Response-only windows still report measured lexical/rcode context; absent denominators are unavailable.
11. **Bounded state:** F3 bucket implementation reused in a separate namespace: default 60 s/1 s, 512 tagged keys, 128 identities per dimension/key across the whole window, 1024 transactions and 1024 latest-message conversation observations. Deterministic LRU/expiry, late exclusion, overflow/lower-bound semantics, peak/error counters and shutdown cleanup are documented and tested. Worst-case Python object overhead is material despite finite bounds.
12. **Evidence/event integration:** additive dns_status, dns_observation, dns_evidence and dns_attack_context through existing SQLite/REST/authenticated WS. Classifier confidence, anomaly score, severity, risk, F3 evidence and canonical segmentation are preserved. Only the existing T1071.004 mapping is reused for combined tunnelling-like context, qualified possible; no intent/attribution claim.
13. **SOC integration:** neutral DNS Observation section distinguishes MEASURED, DERIVED and UNAVAILABLE, with names/types/lengths/entropy, visibility, window aggregates, thresholds and limitations; added operational DNS counters. Product page and polished SOC structure remain intact. Desktop 1440/mobile 390 checks show no document overflow or page errors.
14. **Privacy/data retention:** normalized bounded question names and necessary header/type/length/statistical context only; latest retained message, not complete DNS history. No payload/RDATA/TXT answer content, external requests, telemetry upload or new raw-payload logging. Existing authentication and database retention apply; name redaction/encryption is not added.
15. **Files changed:** 21 phase-specific code/test/fixture/script files, listed below and in [the inventory](sih-f4-validation/changed-files.json), relative to the pre-F4 snapshot. Existing prior-phase work is preserved.
16. **Tests added:** 76 backend and 9 frontend cases. Coverage includes all requested safe positive/legitimate controls, malformed/random inputs, parser and state caps, full sliding membership, rate/correlation semantics, error isolation, unchanged ML/F3 values, frozen-runtime parity, SQLite/REST/WS equality and SOC states. Synthetic fixtures are not malware examples. Existing test-only model constructors remain part of regression infrastructure; the deployed QA bundle was not retrained or modified.
17. **Exact backend total:** **773 passed, 14 warnings**. [Log](sih-f4-validation/backend.txt).
18. **Exact frontend total:** **76 passed across 5 files**. Combined **849 passing tests**. [Log](sih-f4-validation/frontend.txt).
19. **TypeScript/build:** both PASS. Ruff on new DNS/tests and git diff --check also pass. [TypeScript](sih-f4-validation/typescript.txt), [build](sih-f4-validation/build.txt).
20. **Live/replay DNS parity:** **8/8 cases PASS**, with a repeat replay per case: query-only, response-only, paired, TXT, complete TCP, malformed, DGA-like, tunnelling-like. Durable event equality excludes only established provenance/runtime identity differences. Existing core 7/7 and F3 7/7 parity regressions pass within the full suite.
21. **Scientific integrity:** **23/23 protected files byte-identical** to F3; exact 52 features, ordering/schema v2.0.0, canonical aggregation, extractor, preprocessor, classifier, Isolation Forest and thresholds unchanged. [SHA-256 proof](sih-f4-scientific-integrity.json).
22. **Benchmark against F3:** seven paired 30-second fresh-process workloads, F3 enabled in both modes, DNS off versus on, plus historical F3 references for the original six. Input/model/source hashes verified. All requested rates, packet/finalization/DNS p50/p95/p99, RSS and state peaks are recorded. Zero DNS processing errors. [Full performance comparison](sih-f4-performance-report.md). Single-run variability and injected stress effects remain explicit.
23. **False-positive risks:** legitimate CDN/cloud hostnames, discovery, security/email TXT records, telemetry, shared resolvers/NAT, deployment failures and generated subdomains can satisfy even combined heuristics. References are operational and uncalibrated. Parent proxies, retransmissions/capture duplication, state loss and event-finalization timing limit conclusions. No accuracy claim or automatic mitigation.
24. **Remaining SIH26145 gaps:** real BPF capture remains NOT VERIFIED, exact canonical histories can grow, scientific accuracy needs separate revalidation, no production calibration/capacity guarantee, encrypted DNS/nonstandard ports/TCP splits/fragmentation remain unavailable, sensitive-name redaction is not implemented. DNS evidence may expire before canonical idle finalization (60 s versus 120 s default), or be delayed by a long-lived flow.
25. **Proposed SIH-F5:** separately scoped bounded passive TLS ClientHello/ServerHello metadata, explicit visibility/unavailable semantics and safe QUIC metadata only where observable without decrypting application content; preserve scientific files and frozen ML, rigorous malformed/parity/retention/performance controls, qualified fingerprints only after an explicitly specified deterministic policy. No F5 code or TLS/QUIC work has begun.
26. **Git recommendation:** preserve prior-phase changes separately, review the F4 snapshot-relative inventory, then make a focused commit such as `feat: add bounded passive DNS evidence and SOC context`. Include validation/report artifacts; do not blindly stage the pre-existing dirty worktree. No commit, push or PR was created.

## Phase-specific code inventory

- `frontend/src/__tests__/detection-detail.test.tsx`
- `frontend/src/__tests__/fixtures/f4-event.json`
- `frontend/src/api/types.ts`
- `frontend/src/pages/DetectionDetail.tsx`
- `frontend/src/pages/Sensor.tsx`
- `scripts/rw5b_benchmark.py`
- `scripts/rw5b_environment.py`
- `src/sentinel_net/cli.py`
- `src/sentinel_net/config.py`
- `src/sentinel_net/demo_replay.py`
- `src/sentinel_net/dns/__init__.py`
- `src/sentinel_net/dns/config.py`
- `src/sentinel_net/dns/engine.py`
- `src/sentinel_net/dns/parser.py`
- `src/sentinel_net/models/event_record.py`
- `src/sentinel_net/sensor/metrics.py`
- `src/sentinel_net/sensor/operational_health.py`
- `src/sentinel_net/sensor/pipeline.py`
- `tests/integration/test_dns_delivery.py`
- `tests/unit/test_dns_intelligence.py`
- `tests/unit/test_dns_parity.py`

## Supporting artifacts

- [Architecture, policy, parser limits and memory bound](sih-f4-architecture.md)
- [Performance report](sih-f4-performance-report.md)
- [Validation summary](sih-f4-validation/summary.json)
- [Browser verification](sih-f4-validation/browser.json)

**GO FOR SIH-F5**
