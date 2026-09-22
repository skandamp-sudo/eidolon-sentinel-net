# SIH-F3 bounded streaming evidence

This phase adds passive behavioral evidence around the frozen v2.0.0 / 52-feature core. No model, threshold, feature, canonical segmentation or protected scientific file is changed. No DNS/TLS/QUIC intelligence or network transmission is added.

## One lifecycle owner

Each shared `PacketProcessingPipeline` owns one `StreamingIntelligence`, called from its single processing thread. After canonical ingestion, the engine sees the parsed capture observation and whether the canonical aggregator actually created a flow. It does not infer sessions from packet flags independently. On finalized flows it observes existing directional totals, evaluates policy, and adds behavioral metadata to the already enriched DetectionEvent. Durable persistence still precedes EventBus publication. Live and replay use the same owner; replay CLI receives the same centrally configured intelligence policy. Final drain enriches accepted flows before the intelligence owner clears all state.

Packet and completed-flow timestamps advance an event-time watermark. No wall-clock date advances intelligence windows, including live idle callbacks. Thus idle live state remains at most its configured cap until another observed capture timestamp advances it, or shutdown clears it. Historical replay never expires merely because it is old relative to today's date. Intelligence processing duration and complete finalization-to-event latency use monotonic runtime clocks.

An unexpected intelligence exception increments `intelligence_processing_errors`, closes the affected intelligence owner, marks subsequent evidence unavailable, and lets canonical inference and durable output continue. Health degradation is operational; it does not modify anomaly/classifier output.

## Bounded state proof

One capped deterministic LRU map contains tagged destination, source and session keys. There are no detector-specific global registries or histories. Production defaults and absolute configuration ceilings are explicit in `intelligence/config.py`:

| State | Default | Configurable ceiling | Retention / eviction |
|---|---:|---:|---|
| Total destination + source + session keys | 1024 | 10000 | Least-recently-observed key evicted at capacity; counted |
| Capture-time window | 60 s | 3600 s | Epoch-aligned buckets; at most 120 buckets allowed |
| Bucket width | 1 s | 60 s | Horizon must be an integral number of buckets |
| Buckets per key | 60 | 120 | Buckets before the event-time cutoff expire |
| Distinct members per key per dimension | 64 | 1024 | Sources/destinations/ports admitted only while below the cap; overflow counted |
| Session timestamps per session key | 32 | 256 | Sorted latest timestamps; oldest removed; truncations counted |
| Minimum periodicity observations | 6 sessions / 5 intervals | Must fit sample cap | Zero mean interval is ineligible |
| Metrics histories | Latest 4096 timings per stage | Existing fixed cap | Scalar cumulative counters plus bounded deques |

Membership admission is capped across an entire key, not independently per bucket. Each bucket can therefore hold at most M values per dimension; each key also holds at most M membership-set entries per dimension. With K keys, B buckets, M members and S session samples, retained state is O(K × (B × (fixed scalar counters + 3M) + 3M + S)). Temporary expiry lists contain at most K keys; per-key aggregate Counters contain at most M entries per dimension; interval arrays contain at most S−1 elements. There are at most ten counter names and thirteen possible detector outputs per evaluation (the two opposing asymmetry outputs cannot both qualify). A signal list has a fixed number of detector outputs. Addresses originate from parsed IP headers; no arbitrary payload histories are stored. These are entry-count bounds, not a universal byte/RSS guarantee; operator-selected maxima can still be expensive.

This intelligence bound does not change the already accepted **unbounded exact canonical per-flow histories**. Those histories are neither reused nor truncated by intelligence. `intelligence_keys`, key/bucket/member/session peaks, evictions, expirations, member overflows, sample truncations, late observations, evidence generation and processing errors are exposed through existing metrics/status.

## Event-time and loss semantics

For latest bucket index t, retain buckets `[t−B+1, t]`, with the reported half-open timestamp interval `[start, end)`. The latest bucket may be partial. Packet/flow rates divide retained counts by the full configured horizon, not the elapsed benchmark runtime. Startup, missed capture, key eviction and dropped input can reduce observation coverage; rates are observations over this configured window, not estimates of unseen traffic.

In-window late observations update their correct buckets; session timestamps are sorted. Older observations are excluded and counted. Key eviction loses historical coverage and is disclosed in supporting context. Membership overflow preserves aggregate rate counters but loses identities: distinct counts and concentration become lower-bound observations. **Entropy is suppressed when source membership is incomplete**, avoiding a misleading entropy from a censored distribution. Session-cap truncation is flagged for the lifetime of that session key; only the retained recent intervals are analyzed. No wall-clock time, UUID or arrival-runtime duration participates in signal values.

## Signals and operational defaults

Thresholds are centralized, configurable operational policy defaults, not scientifically calibrated decision boundaries or ML probabilities. Nested environment settings use `SENTINEL_INTELLIGENCE__...` (for example `SENTINEL_INTELLIGENCE__SYN_RATE=1000`).

| Signal | Definition / default threshold |
|---|---|
| SYN_RATE | Initial SYN without ACK per destination / 60 s; ≥1000 packets/s |
| UDP_RATE | UDP packets per destination / window; ≥1000/s |
| UDP_FLOW_RATE | Canonical UDP flow creations per destination / window; ≥100/s |
| FLOW_RATE | All canonical flow creations per destination / window; ≥100/s |
| DESTINATION_PACKET_RATE | Parsed packets toward destination / window; ≥2000/s |
| UNIQUE_SOURCE_COUNT | Retained distinct source addresses toward destination; ≥32 |
| SOURCE_DISTRIBUTION_ENTROPY | Packet-weighted Shannon H=−Σpᵢlog₂pᵢ, bits; ≥3 bits and ≥32 packets, complete source membership required |
| C2_PERIODICITY_EVIDENCE | Source/destination/protocol/destination-port flow-creation intervals; ≥6 sessions, positive mean, population stddev/mean ≤0.1 and concentration ≥0.8 |
| DESTINATION_CONCENTRATION | Sessions toward the evaluated destination / all source sessions; ≥0.8 and ≥6 total sessions; retained frequency distribution included |
| PORT_FANOUT / HOST_FANOUT | Source's distinct destination ports / hosts over canonical flow creations; ≥60 ports / ≥32 hosts |
| DIRECTIONAL_ASYMMETRY | Completed flows grouped by initiator/destination/protocol/destination-port; ≥3 direction-heavy flows, ≥1 MiB dominant directional bytes, and dominant/opposing ratio ≥10 (denominator floor 1 byte) |

Periodicity includes interval samples, mean, population variance, standard deviation, CV and truncation metadata. Flow creation includes idle/capacity segmentation: these are **not verified application sessions**, and capacity churn can produce artifacts. Asymmetry uses neutral `initiator_to_responder` / `responder_to_initiator`; no protected-network orientation is assumed. Completed-flow bytes are attributed at recorded end time, explicitly not a claim that every byte was transferred inside the window. A single large upload does not satisfy the repeated-flow requirement, but repeated backups may.

## Policy and contract

Default `policy_mode=enrich_ml` stores signals on existing ML events. `informational` records the same evidence as informational context. Explicit `behavioral_alert` sets a separate review-request flag on that event; it neither emits a duplicate transport event nor mutates ML severity, risk, confidence, anomaly score, rationale or existing ATT&CK mappings. No heuristic probability/confidence is assigned.

Each signal includes type, measured value/unit, configured threshold/comparison, capture observation window, supporting counts/coverage, detector/version and explicit non-probabilistic interpretation. The additive EventRecord fields are `behavioral_evidence`, `behavioral_policy`, `behavioral_attack_context`, and `behavioral_evidence_status`. Historical records report `not_recorded`; an enabled empty result is `available`; disabled and failed processing remain distinguishable. `detection_source` gains only applicable `stream_ddos`, `stream_c2`, `stream_recon`, `stream_asymmetry` provenance. Existing model/source provenance is preserved. SQLite, REST and WebSocket share the same serializer.

ATT&CK context reuses only existing applicable mappings, qualified `possible`: T1498 for aggregate destination rate behavior and T1046 for host/port fan-out. No new mapping is invented. Periodicity alone does not establish an application-layer C2 protocol or encryption; asymmetry alone does not establish a C2/exfiltration channel, so those mappings are intentionally omitted. Context never establishes intent or attribution.

Evidence emits when a canonical flow finalizes, not as an independent packet-time alert stream. A continuously active flow can therefore delay its attached evidence until canonical finalization. No canonical segmentation change is made to reduce that delay.

## SOC and false-positive risks

The existing Detection Detail adds a behavioral-evidence table with observed value, operational threshold, event-time window, expandable context and explicit non-probability wording. Historical/disabled/failed/empty statuses differ. Existing model evidence remains separate. The sensor view adds bounded-state/error counters. The product page and polished console layout remain intact.

High rates can be legitimate demand; high source diversity is not spoofing proof; periodicity and concentration occur in health checks and polling; fan-out occurs in service discovery, proxies and monitoring; asymmetry occurs in uploads and backups. Capture loss, partial windows, late data, key eviction, bounded membership and canonical flow eviction create further limitations. No alert is proof of DDoS, C2, reconnaissance or exfiltration.

## Predeclared measurement plan

Reuse all six RW-5B synthetic workloads for 30 seconds each plus drain, on the same approved QA bundle and host. Run an enabled suite and a same-code `--intelligence-disabled` suite in separate fresh processes, sequentially, without competing test runs. Compare both with archived RW-5B numbers. Record throughput, latency percentiles, RSS, intelligence key/bucket/member/session peaks and losses. A single sequential comparison is descriptive and is not a statistically established capacity regression/improvement. No production accuracy or capacity claim follows from the small synthetic bundle.

The reused RW-5B high-cardinality input varies source ports while keeping source/destination addresses and destination port fixed. It stresses canonical flow cardinality but collapses to a few SIH-F3 session keys. Its measured state peaks do not establish high-host-diversity performance. Deterministic tests separately reach the configured key/member/sample limits and a complete 60-bucket sliding window.

Directional evidence also requires a completed flow whose recorded end remains inside the intelligence horizon. With a 60-second intelligence window and the canonical default 120-second idle timeout, an idle-finalized old flow may already be outside the intelligence window and be excluded. FIN/RST completion and EOF cases can qualify earlier. Choose an explicit horizon/bucket policy appropriate to the deployment; no canonical timeout is changed to hide this limitation.
