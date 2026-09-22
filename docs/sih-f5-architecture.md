# SIH-F5: passive encrypted-session metadata

## Placement and contract

`encrypted/wire.py` reads bounded payload views from existing passive packets. `tls.py` and `quic.py` have no socket, resolver, crypto-decryption or reputation dependencies. `reassembly.py` retains only the bounded range needed for a first supported TLS hello. `engine.py` owns the cache, capture-time expiry, correlation and contextual evidence. The sensor observes packets independently of canonical extraction and enriches completed canonical events after F3/F4. Processing failure clears F5 state, increments an operational error counter and leaves the scientific path intact.

The additive fields are `tls_status`, `tls_observation`, `tls_evidence`, `quic_status`, `quic_observation`, `quic_evidence`. Existing SQLite JSON metadata, authenticated REST and WebSocket delivery carry the same projection. Existing classifier/anomaly scores, severity, risk, model/source provenance, F3/F4 evidence and segmentation are not rewritten. No metadata identifier becomes a probability, malware verdict or ATT&CK attribution.

## TLS parsing and bounded reassembly

Ethernet (up to two VLAN tags), IPv4 and direct IPv6 TCP/UDP are supported. IP fragments and IPv6 extension chains are unavailable. Candidate ports default to TCP 443/8443/853 and UDP 443/4433/853; the port itself is not protocol evidence. STARTTLS and nonconfigured ports are not covered.

Each direction uses fixed data and presence arrays. TCP sequence arithmetic handles wrap; contiguous segments, holes, earlier prefixes, split records, split handshake messages and identical overlap/retransmissions are supported within the retained span. Conflicting overlapping bytes discard that direction as MALFORMED. A range beyond the configured span is TRUNCATED. Parsing occurs only over the contiguous prefix. Terminal results release the byte arrays immediately. The first supported hello is retained; subsequent handshakes, renegotiation and post-completion conflicting retransmissions are not adjudicated. This is not a general TCP implementation. An earliest available prefix that resembles a terminal record remains ambiguous; arbitrary midstream record synchronization is not attempted.

Expiry uses a monotonic capture-time watermark, not packet arrival wall time. The default handshake deadline is 10 seconds and connection retention 60 seconds. Late packets cannot revive expired state or bypass a direction deadline. Quiet capture does not advance the watermark; residual state remains bounded until another packet or shutdown. SYN sequence/closed-epoch checks reduce tuple-reuse leakage, and event-flow interval checks reject observations outside the canonical interval. Missing SYNs and long or segmented flows can still make metadata unavailable. Default canonical idle expiry may outlast metadata retention.

A valid ChangeCipherSpec before a supported hello terminates inspection as UNAVAILABLE: subsequent TLS 1.2 encrypted handshake bytes must not be interpreted as plaintext. This is conservative for TLS 1.3 compatibility CCS. A type-23 record header reports ENCRYPTED_APPLICATION_DATA, declared length and completeness only; no body interpretation. HRR is flagged by its defined random sentinel, but no second ClientHello exchange is reconstructed.

| Limit | Default or fixed cap |
|---|---:|
| Connections | 256, configurable 1–2048 |
| Direction span | 32768 bytes, configurable 1024–65536 |
| Directions per connection | 2 |
| Capture-time handshake / connection TTL | 10 / 60 seconds |
| Packet samples per connection | 64, configurable 2–256 |
| TLS plaintext record / hello body | 16384 / 16384 bytes |
| Records per supported hello | 8 |
| Cipher suites / extensions | 256 / 64 |
| Individual extension bytes | 4096 |
| Groups / signature algorithms | 128 each |
| EC point formats / supported versions | 32 each |
| ALPN | 16 items, 255 bytes per item |
| SNI | One ASCII hostname, 253 bytes; labels at most 63 |
| Session ID | 32 bytes; only length retained |
| Compression methods | 16 |

Nested vector lengths, complete enclosing structures and duplicate extension IDs are validated. Overruns in complete structures are MALFORMED; policy limits are UNSUPPORTED; missing bytes remain INCOMPLETE unless envelope truncation is known. Unknown extension values are discarded. Statuses distinguish COMPLETE, INCOMPLETE, TRUNCATED, MALFORMED, UNSUPPORTED, UNAVAILABLE and ENCRYPTED_APPLICATION_DATA.

Default maximum reassembly arrays are 256 × 2 directions × 2 arrays × 32768 = **32 MiB**, plus bounded Python metadata/sample objects and transient copies. The benchmark deliberately uses 64 connections (8 MiB array ceiling) to exercise eviction. Maximum permitted configuration can allocate 512 MiB of arrays; trusted operators must budget this. These bounds do not change the accepted unbounded exact canonical per-flow histories.

## Fields and fingerprints

ClientHello/ServerHello retain record/legacy versions, handshake type, offered or selected versions, cipher suites, compression methods, extension IDs, groups, signature algorithms, point formats, observable ALPN/SNI, session-ID length and selected server cipher. The TLS 1.3 legacy hello field is not presented as the negotiated version. Client-only and server-only visibility are valid; an unseen peer is not a handshake failure.

JA3 uses decimal `legacy_version,ciphers,extensions,groups,point_formats`; JA3S uses `legacy_version,selected_cipher,extensions`. Lists preserve wire order and use hyphens; empty fields retain comma positions. GREASE values 0x0a0a through 0xfafa at step 0x1010 are excluded from the relevant 16-bit lists. The ASCII canonical string is constructed before standard MD5 (`usedforsecurity=False`); both string and digest are retained. JA3 uses the legacy ClientHello field, not the supported_versions maximum. JA3S likewise uses the ServerHello legacy field. Published JA3 vectors and literal deterministic JA3S vectors are tested. Fingerprints are spoofable, shared and collision-prone identifiers, not application identity proof or reputation.

**JA4 NOT IMPLEMENTED:** no exact verified local specification and deterministic vectors were established. No approximation is labeled JA4.

References: [Salesforce JA3 canonicalization](https://github.com/salesforce/ja3), [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html).

## QUIC visibility

The parser reads only visible long-header invariants and supported QUIC v1 type-specific header fields: version, Initial/0-RTT/Handshake/Retry type, CID lengths and SHA-256 digests, Initial/Retry token length, visible declared protected length and version-negotiation lists. CIDs are capped at 20 bytes, token length at 4096 bytes and VN at 16 nonzero versions; varints are bounded to 1/2/4/8 bytes with enclosing-length checks. Retry requires its 16-byte integrity-tag space but the tag is not authenticated. Unknown versions (including v2) expose invariants only and are UNSUPPORTED for v1 layout interpretation.

Short-header fields, packet numbers, protected reserved bits and encrypted payloads are not interpreted. No Initial keys are derived and no TLS ClientHello is extracted from QUIC. Only the first packet in a datagram is parsed; remaining byte count is disclosed without interpreting coalesced packets. A retained long-header observation survives later unsupported short headers, with separate latest-packet status/time/reason. CID hashes are linkable identifiers, not anonymization. No CID migration correlation or authenticity claim is made; VN can be spoofed. Reference: [QUIC transport, RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html).

## Evidence, privacy and display

Evidence records observable profiles and identifiers, with null thresholds and no attack probabilities. Bounded recent packet-size and capture-time IAT summaries describe transport packets (including ACKs/retransmissions), not decrypted application behavior. Samples are retained in arrival order then sorted by capture time; scope/count/capping are explicit and insufficient IAT data is unavailable. No heuristic threshold for uncommon fingerprints, ALPN or legacy TLS is introduced.

SNI is persisted only when structurally visible: lowercase ASCII, at most 253 bytes. ECH marks the outer name as outer-only, never the hidden inner hostname. Absent SNI and encrypted TLS 1.3 post-ServerHello ALPN remain unavailable. No raw records, random values, session ID values, key shares, tokens, certificates or application bytes are added to persistence/logs. Existing authentication, local SQLite retention and event access controls apply; metadata is not uploaded or resolved. Transient handshake buffers necessarily contain bounded packet bytes until completion/expiry.

The existing Detection Detail adds one restrained ENCRYPTED SESSION section with MEASURED/DERIVED/UNAVAILABLE labels, offered versus selected version, profiles, canonical fingerprint detail, partial visibility and explicit no-decryption/no-verdict text. Sensor displays operational counters. No SOC redesign or product-page change is included.

Metrics distinguish TLS/QUIC counters, errors, connection/sample/byte peaks, evictions and expiry. Disabled/unobserved processing stages have no measured latency distribution; they must not be reported as zero cost. Per-family timers include capture-watermark expiry work; the overall pipeline F5 timer additionally includes integration/enrichment overhead.
