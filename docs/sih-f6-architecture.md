# SIH-F6 analyst operations architecture

F6 is an authenticated, read-only projection over persisted evidence. It does not run inference, change a detector, aggregate new network features, alter thresholds/scores/severity/risk, deserialize models, publish a model, or hook into packet processing. SQLite event records remain authoritative. Existing REST/WebSocket event contracts remain unchanged.

The flow is: authenticated event ID → bounded SQLite snapshot → allowlisted event projection → deterministic correlation/timeline → schema validation → canonical JSON → SHA-256 → browser verification/download. Detection Detail adds the investigation section; Sensor adds assurance. No separate dashboard or graph store is introduced.

## Exact correlation rules

The anchor event always belongs to its own investigation, including historical events with incomplete provenance. A second event is linked only when **all** these recorded fields agree and are non-null: flow ID, ordered source/destination IP and port, protocol, traffic source. REPLAY additionally requires an equal, nonempty replay identifier; LIVE requires an equal, nonempty capture interface. The candidate timestamp must be within ±300 seconds of the anchor's recorded event timestamp (at most a 600-second candidate span). Unknown provenance does not join. Shared IP, hostname, DNS parent, fingerprint, or time alone never joins events. No cross-flow/session correlation is claimed.

Within each selected event, only existing classifier/anomaly scores, model explanation, behavioral/DNS/TLS/QUIC evidence and retained protocol observations contribute. A source count means distinct displayed source **types**, not independent sensors or statistically independent signals. Explanation can derive from the model, and protocol evidence can derive from protocol metadata. Evidence references identify event IDs and relative field paths. Correlation is not another classifier or verdict.

The correlation ID is SHA-256 over the anchor ID, deterministically ordered selected event IDs, and rule version. It is an association identifier; the export-content SHA-256 separately identifies the exact snapshot. Updated content under the same event IDs changes the content digest, not necessarily the correlation ID.

## Bounds, expiry and retention

- Maximum four active investigation/export responses per API process. Excess requests receive 429 immediately; no waiting queue is created. Deployment process counts multiply this bound.
- Maximum 32 selected candidate events, including anchor. One extra row detects truncation. Candidate ordering is anchor first, then timestamp and ID; final output is timestamp/ID sorted. Conservative filters can omit valid neighbors after the initial cap; the truncation limitation remains visible.
- Maximum 128 KiB per stored event JSON and metadata field, checked in SQL before transferring those values. Maximum input is bounded by 33 fetched rows and both field caps; only 32 decode. Malformed/oversized records reject the investigation, rather than silently dropping evidence.
- Maximum 256 evidence references, 512 timeline items, two TLS/QUIC directions, 128 entries per nested list, 256 keys per dictionary, 4,096 characters per retained string, ten nesting levels, finite numbers and bounded integers. Final canonical export maximum 1 MiB.
- Five-second read deadline; 15-second ASGI response-send lease. Cancellation and exceptions release admission. This is an application bound, not a transport/proxy-wide connection guarantee. SQLite may finish an already queued bounded query after coroutine cancellation.
- Browser export reader caps accumulated bytes at 1 MiB and aborts after 20 seconds. No export files are staged on the server.
- Zero cached investigations / zero retained correlation graph. Active projections expire on response completion/cancellation; no eviction policy is needed for inactive state. Retention changes the next snapshot; a deleted anchor returns 404. Downloads remain point-in-time snapshots, not live references.

## Timeline clock semantics

Only stored timestamps are used. DNS timestamp and retained TLS/QUIC direction timestamps use capture time. Evidence window ends are labelled as window ends, not signal generation times. `created_at` is record creation processing time, not database commit time. Historical event timestamp semantics are not assumed: `event_timestamp_unspecified` remains explicit. Missing timestamps produce no timeline item. Ordering is timestamp, clock, event ID, reference. Mixed clocks are labelled, not inferred to establish causality. REPLAY is displayed as RECORDED TRAFFIC REPLAY even when capture dates differ from execution dates.

The F5 fixture's capture timestamp is around epoch 1000 while its record was created in 2026. F6 intentionally shows both and does not change them to attractive demo dates.

## Export / security boundaries

Existing API-key middleware protects both endpoints. IDs follow a bounded alphanumeric/underscore/hyphen pattern and only bind SQL parameters. No user-supplied path or filename reaches a filesystem operation. Response filenames use a generated digest prefix. Exports are JSON only, with no-store and nosniff headers. No HTML report renderer is added. The SOC renders all export-related text as React text nodes; stored `<script>` content is tested as text.

An explicit field-name allowlist excludes arbitrary metadata, configuration secrets, registry paths, raw TLS payloads, raw DNS RDATA, model serialization, and stack-trace fields. Known ATT&CK mappings are extracted from the explanation only and retain their qualifications. Unselected supporting-context fields are intentionally omitted, disclosed in the export; the original event remains authoritative. Legitimate DNS names, endpoint addresses and SNI are sensitive observation metadata and remain visible to authenticated analysts. This is not anonymization. The existing shared API key grants event access; no per-event roles or multitenancy are claimed.

No change to scientific source or approved model registry is necessary. Model identity in assurance reflects the loaded runtime identity; integrity means the existing loader's checks at load time, not continuous attestation or signature verification. Missing identity is UNAVAILABLE. Database readiness is an actual SELECT 1; WebSocket status is the current browser connection. Native BPF and physical diode validation remain NOT VERIFIED.

## Scientific summary

`operations/science.json` is a small packaged snapshot of FINAL-SCIENCE-RESTART-2 with the source metrics-file digest and scientific candidate manifest digest. A regression test compares exact values and hash to the completed report. It includes zero C2 recall, weak DDoS recall, and separate heuristic evaluation. The UI does not equate this candidate with runtime/1.0.0. Missing packaged data is UNAVAILABLE. No retraining or scientific source change occurs.

## Threat review and residual limits

Adversarial IDs, unauthorized exports, malformed/oversized stored JSON, conflicting aliases, deep structures, reference pressure, stale records, digest mutations, HTML text, and slow/cancelled sends have explicit tests. Export integrity protects against accidental byte changes; an attacker controlling content and digest can replace both. The host, database and shared credentials remain trust boundaries. Existing canonical flow-history growth and deployment-wide HTTP connection/rate controls remain outside this phase. No claim of production readiness, complete legal chain of custody, or population heuristic accuracy is made.
