# SIH-F5 acceptance evidence map

| Original acceptance requirement | Evidence |
|---|---|
| 1. Bounded passive TLS parsing | `encrypted/tls.py`, `wire.py`; parser/state tests |
| 2. ClientHello/ServerHello | Legitimate profiles, offered/selected versions and both hello fixtures |
| 3. Bounded split-handshake handling | Split/reordered/retransmitted/overlap/sequence-wrap/multi-record cases; architecture limits |
| 4. JA3/JA3S deterministic correctness | Published JA3 vectors and literal JA3S canonical/digest fixtures |
| 5. JA4 exact or explicitly omitted | NOT IMPLEMENTED in API/UI/docs; no guessed algorithm |
| 6. Bounded QUIC headers | v1/VN/unknown version/CID/varint/length tests |
| 7. No decryption | Parser code audit, forbidden-network/decryption test, CCS boundary test |
| 8. Honest one-way semantics | Client-only/server-only/both and QUIC one-way tests/UI |
| 9. SQLite/REST/WS persistence | Two authenticated end-to-end delivery cases |
| 10. SOC display | 14 component tests, four actual-event browser viewport checks |
| 11. Bounded state | Connection/span/sample caps, capture expiry, late input, eviction/reuse tests; benchmark peaks |
| 12. Safe malformed handling | Nested lengths, duplicate/count limits, overlap, random inputs, malformed QUIC cases |
| 13. No heuristic attack probability | Existing fields preserved; contextual evidence/null thresholds; unchanged-score tests |
| 14. Live/replay parity | 12 cases, each replayed twice; provenance excluded only where legitimate |
| 15. Backend passes | 866 passed, 14 warnings |
| 16. Frontend passes | 90 passed across 6 files |
| 17. TypeScript passes | `typescript.txt` |
| 18. Production build passes | `build.txt` |
| 19. 23 protected files unchanged | `../sih-f5-scientific-integrity.json` |
| 20. F3/F4/RW-5B regressions | Full backend/frontend gates and explicit enabled/disabled field preservation |
| 21. Benchmark comparison | Nine matching workloads per mode; source/model/input hashes, environment validation and performance report |

This mapping does not certify production capture, historical scientific accuracy or comprehensive TLS/QUIC protocol conformance. See the 28-point report and architecture for coverage boundaries.
