# EIDOLON // SENTINEL-NET — security boundaries

Sentinel-NET is a research prototype. This document describes implemented controls and their limits, not a security certification or production-readiness claim.

## Passive observation

The monitored-network path accepts offline PCAP bytes or a receive-only live source. `sensor/capture.py` opens an L2 listen socket and supplies it to `AsyncSniffer(store=False)`. It does not provide active probing, packet injection or monitored-host connection operations. Capture permissions are deployment-specific; failures are explicit and the application does not elevate privileges. Native capture on the presentation host and physical data-diode operation remain NOT VERIFIED.

The API and browser intentionally establish operator-facing network connections. Default API binding is loopback; exposing it elsewhere changes the trust boundary and is outside the reviewed judge runbook. “Passive” does not mean the entire host emits zero network traffic.

TLS ClientHello/ServerHello and visible QUIC headers are metadata inputs. TLS application data and QUIC Initial payloads are not decrypted. DNS names/SNI/endpoints can be sensitive: authorized API access and exports disclose retained metadata. No reputation lookup or external enrichment feed is required.

## Models and scientific trust

Runtime loading requires an explicitly approved local deployment bundle, schema/order compatibility and artifact checksums before deserialization. The judge helper pins the reviewed manifest and checksum ledger. **Checksums do not make untrusted joblib/pickle objects safe:** they establish byte integrity relative to a trusted ledger, not authorship or absence of executable behavior. Load only operator-trusted artifacts; never deserialize downloaded or substituted models merely to complete a demo.

The existing runtime is a synthetic QA contract-test model, not the evaluated scientific candidate. The candidate remains unapproved and outside the runtime registry. The release policy excludes its eleven model binaries from the index while preserving local files and manifest-bound hashes. Clean-archive tests and the actual QA demo passed without those binaries. Earlier Git history still contains them; see [artifact policy](docs/release-artifact-policy.md).

Classifier scores, normalized anomaly scores, statistical deviations and heuristics have different meanings. None is automatically a calibrated attack probability. Final-science limitations include zero C2 supervised recall, weak DDoS recall and exploratory threshold-dependent anomaly results. No scientific source/model/threshold modifications are part of release freeze.

## Authentication and frontend

REST event/flow/investigation routes use the existing API-key middleware and constant-time comparison. Health/readiness and framework documentation routes have their documented public scope; review configured exposure before deployment. The default development key is a placeholder, not a production secret. The judge preflight requires an explicitly configured private key.

WebSockets authenticate by initial message with timeout; query-string authentication is disabled by default. Enabling URL credentials can expose them in logs/history. The browser stores its configured key in per-tab sessionStorage, uses a password input, and clears the input after connection; the key exists in browser memory and is not protected from a compromised browser. Do not project Settings during setup or publish keys in logs, commands or screenshots.

Backend strings render as React text; the frontend consumes backend evidence without generating replacement scores. Loading/error/UNAVAILABLE states distinguish absent data. The F6 download is size/time bounded and checks the server-provided SHA-256 before offering JSON; this is not a signature, external timestamp or legal chain of custody.

## Resource and persistence limits

Queues, subscribers, parser state, query/export limits and retention have explicit operational bounds and metrics. Overflow/error counters must be monitored. An active-flow count cap does **not** bound an individual continuously active flow's exact timestamp/packet-size histories. This known prototype limitation remains unchanged to preserve scientific semantics.

SQLite uses parameterized queries and transactions/WAL. These reduce injection/concurrency risks; they do not guarantee immunity from disk failure or corruption. Retention removes authoritative observations. WebSocket copies may be dropped for slow consumers; REST is the retained-record path, not a promise of exactly-once streaming delivery. Accepted replay packets drain on graceful interruption, with STOPPED distinct from REPLAY_COMPLETE.

Investigation correlation is bounded to the recorded matching flow/endpoints/protocol/source context. It is an evidence projection, not attribution, causal inference or a new probability model. Export allowlists omit arbitrary stored metadata and raw payload fields, but intentionally include relevant observed endpoint/name metadata.

## Verification and dependency limits

Run the full suite using the README commands. Tests cover malformed input, passive-source parity, frozen loading, auth, REST/WS, retention, lifecycle, bounded investigations and export integrity. AST checks are supporting regression checks, not a proof against all attacks. Lockfiles record dependency resolutions; this freeze neither installed a scanner nor downloaded vulnerability advisories. A dependency vulnerability assessment against current advisories is NOT VERIFIED offline.

The judge verifier demonstrates **no required Internet dependency under blocked socket/DNS use** in its in-process replay/API/export test. Browser assets are local. This is not a host-wide zero-traffic attestation.

The release audit scans current tracked content and locally reachable Git history with conservative credential signatures and literal-assignment review. No scanner can prove the absence of every secret. If a credential is found, stop release, revoke/rotate first, and arrange separately authorized remediation; do not automatically rewrite history.

Report suspected vulnerabilities privately to the repository maintainer; do not post sensitive evidence or secrets in public issues.
