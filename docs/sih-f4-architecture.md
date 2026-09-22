# SIH-F4 passive DNS architecture

DNS is a separate passive metadata/evidence subsystem. No canonical feature, model, model threshold, flow segmentation or scientific mathematics changes. No DNS requests, resolution, WHOIS, reputation services, telemetry uploads, decryption, TLS or QUIC parsing. N-grams are deliberately omitted: there is no validated lexical reference corpus; length, character distributions and repeated observable behavior are reproducible and explainable without a fabricated DGA classifier.

## Ownership and data path

The existing canonical parser remains byte-identical. `ParsedPacket.raw_packet` supplies retained captured bytes to a small independent byte reader. The shared `PacketProcessingPipeline` owns one DNS engine on its serialized processing worker, after canonical ingest. Completed canonical flows receive DNS metadata after ML/F3 enrichment and before the existing persist-and-publish operation. No new standalone detections are fabricated. SQLite, REST and authenticated WS use the same additive `EventRecord` fields. DNS errors clear DNS state, mark evidence unavailable, increment a dedicated operational error counter and leave canonical inference/F3 running.

The DNS reader does not use Scapy DNS decoding. Synthetic fixture generation uses Scapy with explicit Ethernet endpoints; nothing is transmitted. The inherited canonical parser still uses Scapy and computes its existing payload entropy; F4's safety bounds apply to the independent DNS reader, not a claim of a whole-sensor parser audit.

## Supported wire input and status

- Ethernet, up to two VLAN tags; IPv4 UDP and TCP; direct IPv6 UDP/TCP.
- Port 53 UDP: complete captured datagrams, limited to 4096 DNS bytes. Standard opcode only.
- Port 53 TCP: up to four complete length-prefixed messages entirely contained in one segment. No stream reassembly, sequence tracking, retransmission suppression or cross-segment buffering. Empty TCP ACK/SYN is not a malformed DNS message. Incomplete framing rejects the segment's frames; safely framed messages are parsed independently.
- IPv4 fragments and observable IPv6 extension/fragment candidates are unavailable. Noninitial fragments without identifiable ports cannot be identified as DNS. DNS on nonstandard ports is not inferred.
- Port 853 is only an encrypted-DNS *candidate*: metadata unavailable, no assertion that the payload is DNS. DoH over port 443 cannot reliably be identified without application/decryption context, so an event reports unavailable/not observed rather than inventing DNS metadata. No DoT/DoQ decryption or QUIC/TLS work.
- `PARSED`, `TRUNCATED`, `MALFORMED`, `UNSUPPORTED`, `ENCRYPTED_OR_UNAVAILABLE` are explicit. TC=1 reports truncated and does not enter behavioral windows. Disabled, historical-not-recorded, operational-error and no-retained-observation states remain separate.

Extracted header fields: transaction ID, QR, opcode, effective rcode (including EDNS OPT extended rcode), question/answer/total record counts, bounded questions (QNAME/QTYPE/QCLASS), numeric response record types, message byte length, TC flag. A/AAAA/CNAME/MX/TXT/NS/PTR/SRV and common DNSSEC types have display names; unknown numeric QTYPEs remain numeric. RDATA is skipped using validated lengths, never interpreted or persisted. Malformed/unsupported/truncated observations do not contribute behavioral findings.

## Parser limits

| Resource | Hard limit / behavior |
|---|---|
| DNS message | 4096 bytes |
| TCP messages per segment | 4; framing budget 4 × 4098 bytes |
| Compression indirections per name | 16 |
| Compression loops | Visited-offset set; rejected |
| Labels per decoded name | 32 |
| Label bytes | 63; extended encodings rejected |
| Decoded wire name | 255 bytes including length octets/root; presentation ≤253 characters |
| Questions | 4 |
| Answers / authority / additional | Combined ≤64 records; bounds each category too |
| Recursion | None; iterative loops with explicit limits |
| Offsets and record sizes | Checked before every read |
| Trailing bytes | Rejected as malformed |
| Non-ASCII/binary label encoding | Unsupported; no lossy decoding |

Names are lowercase ASCII without the terminal dot. Letters, digits, hyphen, underscore and wildcard are accepted. ASCII `xn--` labels are retained as ASCII, without IDNA interpretation. Case/wire encoding is not persisted; normalized names, numeric types and lengths suffice for this evidence scope. Response RR owner names are validated transiently and discarded. No arbitrary response content is retained.

## Lexical measurements and interpretation

For name characters excluding dots, Shannon entropy is `H = -Σ p(c) log2 p(c)` over lowercase ASCII character frequencies, in bits/character. Empty strings have H=0. Per-label entropy and length are separately computed over at most 32 labels. Retained derived fields include QNAME length, longest-label length, label count, digit/alphabetic/hexadecimal ratios, distinct-character count, repeated-label count, subdomain-depth proxy, full-name entropy, maximum label entropy and sample character counts. A high-entropy label must itself meet the minimum length; high entropy on one short label cannot be combined with the length of another label.

Length and entropy findings on the latest observed query **or response question echo** are lexical observations with sample count 1. Response echoes never inflate query window counts. IN-class questions feed behavioral query statistics. Source/server message rates count observed messages, while lexical/unique/QTYPE behavior counts eligible question observations. Duplicate captures and TCP retransmissions are observations, not deduplicated application transactions.

No median is claimed. Exact bounded-window sums/counts give mean query length, mean maximum label entropy, fractions exceeding length/entropy references and TXT fraction. No raw length-history list is stored. Ratios with no response denominator are null, never zero-as-proof. These values are operational evidence, never classifier confidence, anomaly score, risk, severity or attack probability.

## Behavioral policy defaults

Configuration is centralized in `DNSConfig`, exposed through `SENTINEL_DNS__...` and shared by live/replay.

| Reference | Default |
|---|---:|
| Elevated label entropy | ≥3.5 bits/character on a label ≥20 characters |
| Long label / long QNAME | ≥40 / ≥100 characters |
| Minimum eligible questions | 20 |
| Unique names / distinct parent proxies | 16 |
| Unique names under repeated parent proxy | 16 |
| High-entropy fraction | 0.7 |
| Long-label fraction | 0.7 |
| Parent question rate | 0.3 /second over full configured window |
| NXDOMAIN fraction / minimum observed responses | 0.5 /10 |
| TXT question fraction | 0.8 with minimum 20 questions |

`DNS_LEXICAL_ANOMALY` and `DNS_HIGH_ENTROPY_LABEL` describe individual lexical observations. `DNS_UNIQUE_DOMAIN_RATE`, `DNS_NXDOMAIN_PATTERN` and `DNS_QTYPE_PATTERN` are contextual distribution findings. TXT, NXDOMAIN, entropy and long names are never individually declared malicious.

`DGA_LIKE_BEHAVIOR` requires minimum query observations **and** diverse parent proxies **and** a high fraction of qualifying high-entropy labels **and** either (a) enough conservatively paired NXDOMAIN responses at the configured ratio or (b) a high fraction of long labels. The second branch supports one-way query visibility without inventing response failures. Evidence includes the branch, observed counts, ratios and all policy references. It does not assert domain generation by malware.

`DNS_TUNNELLING_LIKE_BEHAVIOR` requires minimum question observations **and** enough unique names under the same client/parent proxy **and** high-entropy fraction **and** long-label fraction **and** question rate. TXT is not required and does not independently trigger this combined finding. The parent proxy is the last two labels, **not** a public-suffix-aware registrable domain. This can group unrelated tenants under multi-label public suffixes; deployment interpretation must retain this limitation.

Only the existing project's `dns_tunneling` → `T1071.004` mapping is reused for the combined tunnelling-like finding, separately under `dns_attack_context`, with qualification `possible` and a rewritten contextual rationale. It does not establish command and control, transfer, intent or attribution. DGA/lexical/TXT-only findings get no DNS ATT&CK mapping. Existing ML and F3 mappings remain intact.

## Correlation and unidirectional visibility

The capped correlation key contains client IP, server IP, both transport ports, transport, transaction ID and the entire bounded normalized question signature (name/type/class). Both ports are retained even if an unusual QR/port orientation is observed. Exact opposite QR observations within 10 capture-time seconds pair; consume the entry on a match. Same-side retries replace that key, conflicting questions/ports cannot pair, empty question signatures do not pair, and old entries expire without failure inference. A response observed first may pair with a later-arriving query within the timestamp horizon. A transaction ID plus identical question reused on the identical tuple within the TTL remains inherently ambiguous; no correlation method can disambiguate it from these bytes alone.

`QUERY_ONLY`, `RESPONSE_ONLY` and `PAIRED` describe the latest retained message's correlation state, not proof of complete session visibility. Other messages in the flow may be unseen. Out-of-order older messages do not replace the latest capture-time observation; an exact correlated match can update its visibility. Missing responses are not NXDOMAIN, failure, timeout or malicious behavior. A response-only window can describe observed rcode fractions but cannot satisfy DGA query-diversity criteria on its own.

## Bounded state proof

F3's `BoundedWindow` is reused with separate DNS configuration, keys and metric namespace. No F3 state or thresholds are shared/mutated. Defaults:

| State | Limit | Expiry / eviction |
|---|---:|---|
| All tagged source/server/client-parent keys combined | 512 | Deterministic LRU; empty state expires |
| Event window / bucket | 60 s /1 s | ≤60 buckets/key; configurable integral ratio ≤120 |
| Name, parent-proxy and QTYPE identities | 128 **per key per dimension across entire window** | Excess new identities censored; overflow counted |
| Correlation entries | 1024 | 10 event-time seconds; LRU at capacity |
| Conversation observations | 1024 | Latest one message only; 60 event-time seconds; LRU |
| Names in one observation | ≤4 | Parser question cap |
| Labels per name | ≤32 | Parser cap |
| Per-name bytes | ≤253 normalized ASCII bytes | Parser cap |

Fixed counter names per bucket; at most `K × B × 3 × M` identity counter entries plus `K × 3 × M` membership entries, fixed counters, and capped transaction/observation objects. This is a conservative structural bound, not an RSS guarantee; Python object overhead is material and maximal settings can be expensive. Default identity-counter upper bound is 11,796,480; typical occupancy is far smaller. No unbounded domain history, response-body cache, TCP buffer or transaction list exists. Aggregation summaries are transient and bounded by the same membership caps. Record/evidence size is bounded by parser caps, identity caps and a fixed number of signal families, not by flow packet count.

Window watermark is the maximum capture-event time, buckets are epoch aligned, and the retained interval is `[floor(watermark/bucket)*bucket - window + bucket, next_bucket)`. The newest bucket may be partial. Late observations inside the interval update their buckets; older ones are excluded and counted. Identity distinct counts/distributions become explicit lower bounds on overflow; query counts, length/entropy sums and TXT ratios remain exact for retained eligible observations. No entropy is estimated over a censored domain identity distribution. State eviction may reduce window coverage; evictions/expirations/overflows are observable.

Neither wall time nor live idle callback advances the DNS event window. Expiry occurs on the next packet/completed-flow timestamp, with all state cleared on stop. Idle state therefore remains resident but capped. Evidence emits on canonical flow finalization, not on a separate timer. The canonical 120 s idle timeout can exceed the 60 s DNS horizon, so DNS metadata may expire before a quiet flow finalizes. Long-running flows can delay evidence. A reused tuple cannot inherit an observation outside that flow's start/end interval. Window context is a current retained client/server/parent aggregate, not an assertion that every contributing query belongs to the event's canonical flow.

Operational counters include all requested `dns_messages_observed`, `dns_messages_parsed`, `dns_malformed`, `dns_truncated`, `dns_unavailable`, `dns_state_keys`, `dns_evictions`, `dns_evidence_generated`, `dns_processing_errors`, plus key/bucket/member/transaction/observation peaks, overflow, expiry and late-observation counters. Observed-message count includes parser/candidate observations such as port-853 unavailable records. DNS processing latency includes packet observation and flow enrichment, measured monotonically; it is not DNS response latency.

## Persistence, UI and privacy

Additive public fields: `dns_status`, `dns_observation`, `dns_evidence`, `dns_attack_context`. Only evidence-producing records append `dns_intelligence` to evidence sources. No ML/F3 fields are overwritten. Malformed input may appear as an unavailable parser status attached to the independently produced canonical ML event; it never creates a DNS threat finding.

The existing SOC gets a neutral DNS Observation section and operational DNS counters. It separates MEASURED protocol values, DERIVED lexical/window statistics, and UNAVAILABLE fields, and preserves the polished layout and product page. It exposes scope/parent-proxy/visibility limitations and contextual ATT&CK qualification.

Persisted DNS metadata: at most the latest bounded normalized question set per retained conversation, header/type/count/length fields, lexical statistics, window aggregate counts/distributions and justified evidence context. No DNS payload, TXT data, answer IP contents, arbitrary RDATA, original case, resolver response body or external reputation result is added to persistence or logs. The canonical parser's pre-existing in-memory raw packet retention is unchanged. Domain names are sensitive; existing authenticated access and bounded database retention apply. F4 does not add domain redaction, field encryption or telemetry uploads.

## Remaining limitations

This is passive prototype evidence, not calibrated malware detection or production readiness. CDNs, tracking/telemetry, cloud-generated names, security TXT records, discovery, failed service deployment and shared resolvers/NAT can meet thresholds. Even combined heuristics can be legitimate. DNSSEC large responses can exceed the message cap or fragment. Unsupported encodings/ports, TCP splits, encrypted DNS and packet loss reduce visibility. Correlation is observational and ambiguous under retransmission/reuse; passive missing responses carry no failure conclusion. Exact canonical per-flow histories remain potentially growing. Real-interface BPF capture remains NOT VERIFIED. Historical scientific accuracy needs a separate revalidation phase.
