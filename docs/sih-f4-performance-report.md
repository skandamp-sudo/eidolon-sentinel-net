# SIH-F4 measured operational comparison

F3 remains enabled in both conditions. DNS disabled versus DNS enabled: seven workloads, each in a fresh process for 30 seconds plus drain, disabled suite first and enabled suite second. The six original input SHA-256 values and frozen model identity match SIH-F3; the seventh is a deterministic DNS-heavy synthetic PCAP that is never transmitted. Both modes use identical inputs and final runtime source hashes. No validation tests or browser jobs ran concurrently with these final suites. An earlier incomplete disabled trial was stopped after a parent-window counter correction and is excluded.

Host: macOS-26.7-x86_64-i386-64bit; Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz; 8 physical / 16 logical cores; 16 GiB RAM. Python 3.12.14; NumPy 2.5.2, scikit-learn 1.9.0, XGBoost 3.4.1. Frozen QA bundle `runtime/1.0.0`, manifest `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f`. This is the same synthetic QA model used previously, not a calibrated production model.

**Interpretation:** single sequential runs are subject to thermal, scheduling, cache and storage variation. Rate changes are descriptive; neither small increases nor differences against historical F3 establish a causal improvement/regression. Disabled mode keeps the current schema/integration and skips DNS observation/enrichment; it is not byte-identical historical F3. These measurements do not establish universal throughput capacity.

## Throughput

| Workload | Historical F3 packets/s | DNS off packets/s | DNS on packets/s | On vs off | On flows/s | On Mbps |
|---|---:|---:|---:|---:|---:|---:|
| A_mixed | 397.79 | 396.54 | 389.82 | -1.69% | 49.25 | 0.4474 |
| B_cardinality | 89.88 | 88.97 | 86.61 | -2.66% | 84.56 | 0.1033 |
| C_long_tuple | 1484.41 | 1493.86 | 1453.18 | -2.72% | 0.03 | 1.7377 |
| D_burst | 286.91 | 290.16 | 276.22 | -4.81% | 69.05 | 0.1991 |
| E_slow_websocket | 263.22 | 257.98 | 227.53 | -11.81% | 56.88 | 0.2716 |
| F_slow_storage | 113.11 | 111.15 | 111.97 | +0.74% | 27.99 | 0.1335 |
| G_dns_heavy | New workload | 1193.74 | 1021.98 | -14.39% | 2.08 | 0.9927 |

## Monotonic latency

Milliseconds; each cell is p50 / p95 / p99, using the latest at most 4096 observations. `dns_processing` combines per-packet observation and per-flow enrichment, not DNS server response time. Packet processing includes synchronous downstream backpressure. The C long-tuple workload has only one finalized event; its finalization percentiles are N=1, not a tail distribution. G finalizes 64 flows at EOF; finalization-to-event includes waiting behind earlier events in that flush batch.

| Workload / mode | Packet processing | Finalization to event | DNS processing |
|---|---:|---:|---:|
| A_mixed / off | 0.5882 / 12.2227 / 19.8016 | 6.2387 / 8.6543 / 31.6243 | Disabled / unavailable |
| A_mixed / on | 0.6102 / 12.0702 / 16.0365 | 6.3141 / 8.3227 / 31.4866 | 0.0135 / 0.0185 / 0.0242 |
| B_cardinality / off | 9.4952 / 20.6385 / 33.0230 | 5.8010 / 8.2289 / 332.1266 | Disabled / unavailable |
| B_cardinality / on | 9.6988 / 20.5435 / 36.0827 | 5.9538 / 8.1564 / 433.3918 | 0.0169 / 0.0232 / 0.0328 |
| C_long_tuple / off | 0.3342 / 0.4647 / 0.5949 | 27.8946 / 27.8946 / 27.8946 | Disabled / unavailable |
| C_long_tuple / on | 0.3435 / 0.5334 / 0.7005 | 34.2958 / 34.2958 / 34.2958 | 0.0085 / 0.0104 / 0.0301 |
| D_burst / off | 0.6398 / 12.7715 / 23.2039 | 6.6068 / 8.5277 / 26.2842 | Disabled / unavailable |
| D_burst / on | 0.6804 / 13.7352 / 25.3809 | 6.9323 / 9.1081 / 26.1661 | 0.0141 / 0.0198 / 0.0258 |
| E_slow_websocket / off | 0.5577 / 12.4014 / 23.3128 | 6.2665 / 7.8522 / 25.3278 | Disabled / unavailable |
| E_slow_websocket / on | 0.6888 / 15.0978 / 29.3375 | 7.0981 / 9.1451 / 29.4360 | 0.0170 / 0.0216 / 0.0295 |
| F_slow_storage / off | 0.5990 / 31.7255 / 48.8476 | 6.3622 / 8.9503 / 25.2302 | Disabled / unavailable |
| F_slow_storage / on | 0.6102 / 31.3336 / 45.9516 | 6.3466 / 8.8175 / 24.3418 | 0.0140 / 0.0195 / 0.0277 |
| G_dns_heavy / off | 0.4159 / 0.5867 / 0.7154 | 335.6926 / 644.9214 / 668.7061 | Disabled / unavailable |
| G_dns_heavy / on | 0.5488 / 0.8608 / 1.1715 | 371.3797 / 656.2713 / 679.6931 | 0.1867 / 0.3452 / 0.4728 |

## Resident memory

MiB, measured process RSS. Sampled peak is every 0.5 seconds; OS process-lifetime peak also includes model/startup work. Memory differences are whole-process observations, not isolated DNS heap attribution.

| Workload / mode | Initial | Sampled peak | Final | OS lifetime peak |
|---|---:|---:|---:|---:|
| A_mixed / off | 213.89 | 220.86 | 220.86 | 220.88 |
| A_mixed / on | 213.98 | 221.18 | 221.18 | 221.19 |
| B_cardinality / off | 213.94 | 221.03 | 221.03 | 221.04 |
| B_cardinality / on | 214.16 | 221.21 | 221.21 | 221.24 |
| C_long_tuple / off | 214.00 | 222.07 | 222.07 | 222.20 |
| C_long_tuple / on | 214.07 | 221.79 | 221.79 | 221.86 |
| D_burst / off | 214.18 | 220.82 | 220.82 | 220.84 |
| D_burst / on | 214.15 | 221.32 | 221.30 | 221.32 |
| E_slow_websocket / off | 229.27 | 240.27 | 240.26 | 240.28 |
| E_slow_websocket / on | 229.34 | 236.67 | 236.66 | 236.68 |
| F_slow_storage / off | 214.00 | 220.12 | 220.12 | 220.14 |
| F_slow_storage / on | 214.09 | 220.60 | 220.59 | 220.61 |
| G_dns_heavy / off | 214.09 | 223.93 | 223.93 | 223.99 |
| G_dns_heavy / on | 214.10 | 223.92 | 223.92 | 223.99 |

## DNS state and results

| Workload | Parsed messages | Key peak | Bucket/key peak | Identity/dimension peak | Transaction peak | Observation peak | Evictions | Emitted signals | DNS errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A_mixed | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| B_cardinality | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| C_long_tuple | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| D_burst | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| E_slow_websocket | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| F_slow_storage | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| G_dns_heavy | 31373 | 45 | 2 | 128 | 1 | 64 | 0 | 239 | 0 |

## Workload scope and operational effects

- A: original mixed TCP/UDP replay; B: high canonical flow cardinality driven by ephemeral source ports; C: repeated long-lived tuple. These original workloads do not contain port-53 DNS messages. They measure non-DNS hook/contract cost, not parser-heavy capacity.
- D: intentional burst source saturates the application capture queue; recorded drops are expected stress behavior. E: authenticated localhost slow WebSocket consumer; timeout/output errors are separate from DNS errors. F: injected 20 ms persistence delay. Raw counters retain these distinctions.
- G: 1024 deterministic query/response packets with explicit documentation-range IPs/MACs, long encoded-looking safe fixture names, A/TXT queries and some NXDOMAIN replies. It repeats the historical capture times, exactly as the benchmark methodology does; no DNS requests are sent. Correlation works on the observable tuple/ID/question. The workload is synthetic and is not evidence of real malware.
- G reached the 128-identity dimension cap and recorded 11,719 censored membership updates; the affected identity counts/distributions are explicitly lower bounds. This is not 11,719 dropped packets. Key/transaction/observation maxima remained below their caps.
- Repeated PCAP timestamps occupy only a few event-time buckets; performance runs are not full-horizon state-saturation tests. Separate deterministic unit tests exercise complete sliding windows, identity caps, cache/key eviction, expiration and malformed bounds.
- The original exact canonical per-flow histories remain potentially growing; F4 bounds only its additive subsystem. Actual BPF capture remains NOT VERIFIED.
- Full rates, timings for every measured stage, per-stage sample counts, configuration, source/input/model hashes, memory/storage windows and operational counters are saved in the raw JSONs.

## Artifacts

- [DNS enabled](sih-f4-benchmark-enabled.json)
- [DNS disabled](sih-f4-benchmark-disabled.json)
- [Computed comparison](sih-f4-benchmark-comparison.json)
- [Enabled environment](sih-f4-environment-enabled.json)
- [Disabled environment](sih-f4-environment-disabled.json)
- [Historical F3](sih-f3-benchmark-enabled.json)
