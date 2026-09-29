# Live passive launcher diagnosis and validation

## Observed failure, before changing behavior

The existing sensor was first run directly on authorized `en0` with its exact virtualenv, reviewed QA runtime and isolated database. Child stdout/stderr were preserved under ignored `.local/qa-recovery-work/live-diagnosis/direct-child.log`. Across 71 authenticated status samples spanning 6.28–79.28 seconds after launch, the process remained alive. Final counters were 31,236 observed packets, 31,170 parsed/processed, 91 flows created, 13 features/inferences/persisted events, and 66 `packets_malformed`. Capture, processing and persistence errors were zero. Lifecycle was DEGRADED, not FAILED. Before requested shutdown the process had no exit code; after shutdown its exit code was 0.

The wrapper was then reproduced with diagnostic-only stdout/stderr redirection and parser classification counters. The exact child log is `.local/qa-recovery-work/live-diagnosis/wrapper-child.log`; the last status is `wrapper-last-status.json`. A non-IP Ethernet frame, EtherType `0x88ca`, returned None from the IP parser. The existing processing pipeline counted that as `packets_malformed`, and the health monitor latched DEGRADED. The wrapper's `live_ready` incorrectly treated DEGRADED as a stopped/failed sensor and initiated shutdown. Wrapper exit was 1; child exit before wrapper cleanup was None and after cleanup was 0. There was no child traceback or spontaneous worker exit in this reproduction.

Diagnostic packet classification recorded 1,491 IPv6 packets, four IPv4 packets, and one unsupported non-IP Ethernet frame. IPv6 was not the cause. Code inspection confirms IPv6 parsing, address-independent flow keys, the existing IP-version feature and string address serialization. No IPv4-only BPF selection was added.

## Minimal correction

- Live capture counts unsupported Ethernet payloads in `packets_non_ip_skipped` before placing them on the IP processing queue. It does not change the BPF filter, device configuration or permissions. This is live-only: replay continues using its original source/parser path.
- Classification inspects the Ethernet header and at most two VLAN tags. Declared IPv4/IPv6, truncated headers and deeper VLAN nesting continue through existing processing/error handling. Malformed IP and worker failures are not silently reclassified as harmless skips.
- The wrapper keeps an active DEGRADED sensor available and prints an explicit warning. It only prints healthy live readiness for RUNNING. Failed/stopped/error states and wrong source/interface still fail closed. SOC health reasons remain intact.
- The SOC adds a live-only Non-IP Frames Skipped counter; unavailable data stays unavailable. Authentication, bootstrap, endpoints, process ownership and replay remain shared with the existing launcher.

Changed implementation: `src/sentinel_net/sensor/capture.py`, `src/sentinel_net/sensor/metrics.py`, `scripts/run_sih_demo.py`, `frontend/src/api/types.ts`, `frontend/src/pages/Sensor.tsx`. Tests extend capture, service, operator and browser/process verifiers. The operator guide is updated. No scientific implementation file was changed.

## Gates

- Operator/capture/service/passive-source/judge/offline-fixture suite: **98 passed, one existing Starlette deprecation warning, 15.78 seconds**.
- Parser/live-offline parity and RW2/DNS/encrypted delivery regressions: **17 passed, one existing warning, 14.26 seconds**.
- Frontend: **100 tests passed**; typecheck and production build passed.
- Python compilation, browser verifier JavaScript syntax and Git whitespace checks passed.
- All 23 protected scientific files, all seven trusted QA files, all 14 scientific candidate components, judge PCAP and frozen tag match their recorded hashes. No models, thresholds, canonical schema or frozen evidence changed. No commit, push or retag occurred.

### Actual en0 live results

Two sequential real-browser runs both remained RUNNING throughout more than 65 seconds of authenticated status observations. No active traffic was generated.

| Check | First live run | Immediate second live run |
| --- | ---: | ---: |
| Sustained RUNNING seconds | 65.330 | 65.764 |
| Status observations | 63 | 64 |
| Packets observed at final API read | 32,446 | 27,643 |
| Parsed / processed at last sustained sample | 32,066 / 32,066 | 27,331 / 27,331 |
| Flows created | 122 | 112 |
| Features / inferences / persisted results at sustained sample | 30 / 30 / 30 | 21 / 21 / 21 |
| Completed flows / persisted events at final API read | 31 / 31 | 21 / 21 |
| Non-IP frames skipped | 62 | 63 |
| Malformed / capture / processing / persistence errors | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| Automatic auth, REST, WebSocket, changing SOC counters | PASS | PASS |
| SIGINT cleanup, ports released, owned workspace removed | PASS | PASS |

Different final values reflect separate API reads while real capture continued, not substituted or fabricated counts. A read-only REST flow sample from the first live run contained 28 IPv6 flows and two IPv4 flows. Both runs rejected unauthenticated API access (401) and a repeated bootstrap grant (410); credential reuse and absence from checked logs/URLs/HTML passed. Occupied 8010 and 5174 both failed closed without terminating the existing listener.

A separate exact `./run-sih-demo.sh --interface en0` run opened the default browser, authenticated automatically and remained RUNNING. An independent authenticated WebSocket subscriber received **three real LIVE events** during 25 seconds, then disconnected before requested Ctrl+C. Cleanup released both ports. An earlier extra observer overlapped the harness's planned shutdown and received close code 1012; that overlapping probe was not used as successful event-delivery evidence.

Local results: `.local/qa-recovery-work/live-diagnosis/live-results.json` and `normal-live-result.json`. Child diagnostic logs were preserved before application changes. Logs and raw diagnostic databases remain ignored; this report contains derived evidence only.

### Deterministic replay regression

Both final replay browser/process cycles passed with exactly **191 packets / 72 completed flows / 72 events**. Automatic authentication, REST, WebSocket, 401 unauthorized access, 410 bootstrap reuse, stable credential, no key in checked outputs, Ctrl+C-equivalent cleanup, owned workspace removal, immediate restart and occupied-port checks all passed. No replay fallback was used in any live run. Both ports were released at completion. Replay evidence is retained in `.local/qa-recovery-work/live-diagnosis/replay-results.json` with both launch logs.

**Result: LIVE PASSIVE DEMO VERIFIED** for the observed en0 traffic and bounded runs above. Validation services have been stopped.

## Limits and operation

Run `./run-sih-demo.sh --interface en0` for authorized live observation. Omit the interface option for the unchanged deterministic replay. The runtime remains synthetic QA; predictions are not validated threat verdicts. No active probes, scans or synthetic network traffic were sent. No capture permission, chmod, group, sudo, Homebrew or BPF changes were made.

These are bounded host validation runs, not a sustained-load benchmark or proof for every link type/IPv6 extension combination. Existing scientific and resource-history limits remain. Diagnostic databases may contain observed network metadata and are ignored local investigation material; they are not included in this report. Normal launcher session storage is temporary and removed during cleanup.

Recommended commit, after all validation passes: `fix(sensor): distinguish non-IP live frames and preserve degraded operation`.
