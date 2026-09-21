# EIDOLON // SENTINEL-NET — Security Policy

## Passive Ingestion Security Model

SENTINEL-NET is designed as a **structurally passive** network analysis system. This is enforced at the code level, not merely as a policy.

### What "Structurally Passive" Means

The ingestion layer has **no code path** capable of:

- ❌ Sending packets to any network interface
- ❌ Modifying packet data in transit
- ❌ Probing or scanning hosts
- ❌ Initiating network connections to monitored hosts
- ❌ Performing active reconnaissance
- ❌ Injecting traffic
- ❌ Decrypting TLS/QUIC content
- ❌ Executing offensive capabilities

### How This Is Enforced

1. **Import Restrictions**: 
   - Ingestion modules (`parser.py`, `replay.py`) import only read-only scapy functions (Ether, raw, PcapReader, IP/TCP/UDP/ICMP layers)
   - `sensor/capture.py` imports `sniff` ONLY — the sole module permitted to use scapy capture (receive-only mode)
   - ❌ Never imports anywhere: `send`, `sendp`, `sr`, `sr1`, `AsyncSniffer`

2. **File-Only Input (PCAP mode)**: `PcapReplay` only accepts filesystem paths. It validates file existence, readability, and extension before processing.

3. **Passive Capture (Live mode)**: `PassiveCaptureSource` uses `scapy.sniff()` with `store=False` and `prn=callback` — receive-only, no packet generation. BPF filter strings are validated against shell injection patterns.

3. **No Socket Operations**: The ingestion layer never opens network sockets, never binds to interfaces, never creates raw sockets.

### Verification

To verify passive compliance, run:

```bash
# Search for any sending function imports across ALL modules
grep -rn "from scapy.*import.*send\|sendp\|sr\b\|sr1\b\|sniff\b\|AsyncSniffer" src/sentinel_net/

# Verify no socket operations in flow/feature modules
grep -rn "import socket\|from socket" src/sentinel_net/flow/ src/sentinel_net/features/ src/sentinel_net/pipeline.py

# Verify no network imports in flow aggregation
grep -rn "import requests\|import urllib\|import http" src/sentinel_net/flow/ src/sentinel_net/features/

# All commands should return no results
```

### Flow Engine Security

The `FlowAggregator` in `flow/aggregator.py` is a pure in-memory data structure:
- Accepts only `ParsedPacket` objects (no raw network data)
- Performs no I/O of any kind
- Does not import scapy, socket, or any network library
- Bounded memory via `max_active_flows` prevents unbounded state growth

### Feature Extractor Security

The `FeatureExtractor` in `features/extractor.py`:
- Is a pure computation engine using only numpy
- Does NOT decrypt TLS, QUIC, or any encrypted payload
- Treats encrypted payload as opaque — only metadata features (sizes, timing, flags) are used
- No cryptographic key material is introduced
- No payload persistence — raw bytes are never stored in features

### Detection Engine Security (Phase 3)

The detection module (`detection/`) enforces:

1. **No network I/O**: All ML inference is pure local computation. No model serving, no API calls, no telemetry.
2. **No payload inspection**: All 52 features are derived from observable metadata (sizes, timing, flags). No TLS/QUIC decryption.
3. **Safe deserialization**: Model artifacts are verified via SHA-256 checksum before loading. No `pickle.loads()` on untrusted data — all models are loaded through the `ModelRegistry` which validates integrity.
4. **No arbitrary code execution**: Models are sklearn/xgboost objects loaded via `joblib.load()` with checksum verification. No `eval()`, no `exec()`, no dynamic code generation.
5. **Configuration-driven thresholds**: All detection thresholds are configurable. No hardcoded `if score > 0.8` patterns.
6. **Scores are NOT probabilities**: Model outputs are labeled as "confidence scores" or "raw scores", never as "calibrated probabilities" (calibration is not implemented).
7. **Preprocessing fitted only on training data**: Validation/test transforms use already-fitted pipelines to prevent data leakage.
8. **Scenario-aware data splitting**: Flows from the same PCAP/scenario stay in the same partition to prevent cross-scenario leakage.

### Verification (Detection Layer)

```bash
# Verify no network imports in detection module
grep -rn "import requests\|import urllib\|import http\|import socket" src/sentinel_net/detection/

# Verify no unsafe deserialization
grep -rn "pickle\.loads\|pickle\.load\|eval(" src/sentinel_net/detection/

# Verify no payload inspection
grep -rn "decrypt\|tls_key\|ssl_context" src/sentinel_net/detection/

# All commands should return no results
```

## Data Handling

### Unidirectional Fidelity
The system represents only what is directly observed. If traffic is captured in one direction only, it records that single direction without inferring reverse flows. This prevents false data amplification.

### No Data Exfiltration
- The API binds to `127.0.0.1` by default (localhost only)
- API access requires an API key (`X-API-Key` header)
- No telemetry, no phone-home, no external API calls

### Storage Security
- SQLite database stored locally with filesystem permissions
- No remote database connections
- No cloud storage integration

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Code injection via malformed PCAP | Scapy handles malformed packets gracefully; parser returns `None` for unparseable packets |
| API unauthorized access | API key middleware enforces authentication on all endpoints except `/health` |
| Data corruption | SQLite WAL mode prevents write corruption; immutable dataclasses prevent in-memory corruption |
| Supply chain | Minimal dependency tree; pinned versions via `uv.lock` |
| Privilege escalation | No root required; no raw socket operations; no setuid |

## Reporting Security Issues

If you discover a security vulnerability, please report it privately. Do not open a public issue.

## Detection Engine Security (Phase 3)

### Model Artifact Security
- Model artifacts are treated as untrusted input
- SHA-256 checksum verification on every model load (`ModelRegistry`)
- Corrupted artifacts raise `ValueError` — no silent loading
- No `pickle.loads()` on untrusted data — `joblib` used through registry only
- Model manifests record provenance, training config, and dependencies

### ML Pipeline Isolation
- Preprocessing fits only on training data
- Scenario-aware splitting prevents train/test leakage
- No test-set threshold tuning
- Model scores are NOT labeled as calibrated probabilities

## Explainability Security (Phase 4)

### SHAP as Optional Dependency
- SHAP is NOT imported at module load time
- Core detection pipeline operates without SHAP
- `shap` is imported lazily only when `SHAPExplainer.explain()` is called
- If SHAP is unavailable, structured "explanation unavailable" result returned

### Evidence Integrity
- Every evidence item traces to actual `FeatureVector` data
- No invented evidence
- No causal claims — "Feature X contributed to the model decision"
- Evidence types are semantically honest:
  - `"model"`: Genuine model-derived contributions (SHAP values)
  - `"statistical"`: Distributional deviation (z-scores from training data)
  - `"heuristic"`: Rule-based evidence
- Isolation Forest anomaly explanations use `evidence_type="statistical"` only

### ATT&CK Mapping Security
- Static mapping table — no external API calls
- All mappings are qualified ("possible", "likely", "observed indicators consistent with")
- Never claims confirmed ATT&CK technique from classifier output alone

### Automated Security Tests
- AST-based source scanning verifies passive architecture across all modules
- Tests verify: no send/socket/eval/exec/pickle/network imports/Docker
- Phase 5 additions: sensor security (no subprocess, no shell execution, sniff-only), API auth (hmac, no credential logging), WebSocket auth, no f-string SQL
- Security tests run as part of the standard test suite

## Live Sensor Security (Phase 5)

### Passive Capture Enforcement
- `sensor/capture.py` is the ONLY module that imports `scapy.sniff`
- No module in the project imports `send`, `sendp`, `sr`, `sr1`, or `AsyncSniffer`
- `capture.py` does NOT import `subprocess` or `os` — no shell command execution
- BPF filter strings are validated: `;`, `|`, `` ` ``, `$()`, `>`, `<`, `&`, `!` are rejected
- No privilege escalation — clear error message when capture permissions are insufficient

### API Authentication
- API key validated with `hmac.compare_digest()` (constant-time comparison)
- Empty, missing, and malformed keys are explicitly rejected
- API key is **never** logged, persisted, or included in error responses
- Only client IP is logged on auth failure

### WebSocket Authentication
- **Primary**: Auth-message-first flow
  1. Client connects
  2. Client sends `{"type": "auth", "api_key": "..."}`
  3. Server validates with `hmac.compare_digest()`
  4. On success: `{"type": "auth_ok"}`; on failure: `{"type": "auth_failed"}` + close
- **Fallback**: Query-param auth is **disabled by default** (`ws_query_param_auth=false`)
  - When enabled, credentials appear in URLs/logs/browser history — documented risk
- API key never appears in event payloads, heartbeat messages, or error responses

### Error Response Security
- Global exception handler returns generic "Internal server error" message
- Stack traces are **never** exposed to clients
- Internal paths, configuration values, and secrets are **never** in error responses

### Bounded Resources
- All queues (capture, detection, event) have configurable maximum sizes
- Queue overflow increments metrics counter; data is dropped, never silently lost
- Event storage has configurable retention (max count + max age)
- Response sizes bounded via pagination limits (1-200)
- Detection pipeline continues with zero WebSocket subscribers

### Database Security
- All SQL queries use parameterized `?` placeholders
- No f-string or string concatenation in SQL execution
- AST-based test verifies no `JoinedStr` (f-string) in any `execute()` call
- Raw payloads and decrypted content are **never** persisted

### Frontend Security (Phase 6)

The SOC frontend is a pure API consumer with no privileged access.

**Credential Handling**:
- API key stored in sessionStorage (per-tab only, cleared on tab close)
- API key passed via WebSocket auth message, **never** in URLs
- API key captured in API client closure, never in React state or DOM
- API key compared with `hmac.compare_digest()` on the backend
- Never logged, rendered, or included in error messages

**Content Security**:
- ❌ No `eval()`, `new Function()`, or `dangerouslySetInnerHTML` anywhere
- Backend text rendered as React text nodes only (safe by default)
- No raw HTML injection from backend data

**Data Integrity**:
- Frontend never duplicates: ML inference, anomaly scoring, threat classification, ATT&CK mapping, evidence generation
- All ATT&CK mappings displayed are backend-sourced only
- Empty/UNAVAILABLE states shown when backend data is absent — never fabricated
- Client-side event buffer bounded to 100 events with deduplication

**Network Security**:
- No scanning, probing, packet injection, or traffic modification controls
- Sensor view is observability/read-only
- WebSocket uses auth-message-first protocol (no credentials in URL)
- Exponential backoff reconnection to prevent reconnection storms

## Evaluation Security (Phase 7)

**Defensive Posture**:
- Evaluation framework uses ONLY offline data and synthetic fixtures
- No network operations during evaluation
- No dataset auto-download
- No exploit code, malware samples, or active scanning

**Data Integrity**:
- Evaluation protocol enforces locked state machine (OPEN → THRESHOLD_LOCKED → FINAL_EVALUATED)
- Final test data is immutable after evaluation begins
- Threshold selection uses VALIDATION partition only — never FINAL TEST
- Experiment manifests record dataset hash, split strategy, random seed, model, schema version
- Scenario-ID disjointness verified programmatically

**Honesty**:
- Synthetic results explicitly labeled as SOFTWARE TEST (not scientific evidence)
- Score types enforced: anomaly score ≠ classification score ≠ probability
- Isolation Forest anomaly scores are never treated as calibrated probabilities
- No fabricated metrics — "insufficient data" reported when data is unavailable
- Feature ablation results describe model dependence, not causal importance
- Perturbation tests are controlled experiments, not adversarial guarantees
