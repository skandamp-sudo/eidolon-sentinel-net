# SIH-F5 performance comparison

Nine workloads, 30 seconds of input each, fresh process per workload; elapsed rates include drain. Sequential F5-disabled then F5-enabled runs, with F3/F4 enabled in both. All pairs have identical fixture PCAP, frozen model and source hashes; original A–G inputs match archived F4. H exercises split TLS ClientHello plus reverse ServerHello and close; I exercises QUIC v1 visible Initial/Handshake headers. Metadata connection cap is 64 to exercise eviction; production default is 256. No active target traffic was sent.

This is one run per condition, not a statistically significant capacity estimate. Host scheduling, inference, persistence and drain dominate some workloads. Latency distributions retain the last 4096 observations; C has only one finalization. Historical PCAP capture times repeat without rewriting. D intentionally stresses queue drops, E a slow loopback WebSocket subscriber, and F injects 20 ms persistence delay. Finalization latency can include batch waiting. Existing exact canonical histories remain a separate memory limitation.

The TLS-heavy pair measured −1.8% packets/s and QUIC-heavy +3.5%; the cross-workload range (−1.8% to +29.2%) shows substantial run-order/host variability and cannot isolate causal overhead. Dedicated TLS metadata p95 was 0.6301 ms and QUIC metadata p95 0.3735 ms. Both modes exercised the intended slow-WebSocket timeout; it is distinct from the zero F5 processing-error counts.

## Throughput

| Workload | packets/s off → on | flows/s off → on | Mbps off → on | packets/s change |
|---|---:|---:|---:|---:|
| A_mixed | 369.66 → 363.61 | 46.74 → 45.98 | 0.4240 → 0.4171 | -1.6% |
| B_cardinality | 68.98 → 71.14 | 66.94 → 69.10 | 0.0820 → 0.0848 | +3.1% |
| C_long_tuple | 1220.83 → 1330.51 | 0.03 → 0.03 | 1.4597 → 1.5907 | +9.0% |
| D_burst | 223.80 → 256.73 | 55.95 → 64.18 | 0.1609 → 0.1849 | +14.7% |
| E_slow_websocket | 183.17 → 202.11 | 45.79 → 50.54 | 0.2191 → 0.2412 | +10.3% |
| F_slow_storage | 95.94 → 102.11 | 23.99 → 25.53 | 0.1142 → 0.1220 | +6.4% |
| G_dns_heavy | 681.22 → 880.43 | 2.08 → 2.08 | 0.6617 → 0.8552 | +29.2% |
| H_tls_heavy | 185.39 → 182.10 | 46.35 → 45.52 | 0.1516 → 0.1490 | -1.8% |
| I_quic_headers | 68.23 → 70.60 | 60.06 → 62.46 | 0.0472 → 0.0489 | +3.5% |

## Packet processing latency (ms)

Triples are p50 / p95 / p99. Unavailable means no observations; disabled metadata is not measured zero.

| Workload | F5 disabled | F5 enabled |
|---|---:|---:|
| A_mixed | 0.6468 / 13.0742 / 22.3479 | 0.6856 / 12.5857 / 20.8542 |
| B_cardinality | 12.0172 / 26.2646 / 42.5148 | 12.1977 / 25.4540 / 42.5265 |
| C_long_tuple | 0.4010 / 0.6543 / 0.9285 | 0.3913 / 0.5769 / 0.7377 |
| D_burst | 0.8079 / 18.2733 / 34.6307 | 0.8496 / 14.5244 / 25.4460 |
| E_slow_websocket | 0.7858 / 18.5693 / 41.3209 | 0.9354 / 16.2882 / 39.8370 |
| F_slow_storage | 0.7940 / 36.3389 / 58.7542 | 0.8878 / 33.5650 / 54.0138 |
| G_dns_heavy | 0.7986 / 1.2183 / 1.6789 | 0.6663 / 0.8982 / 1.1400 |
| H_tls_heavy | 0.8577 / 19.5119 / 42.3162 | 1.1466 / 17.8191 / 38.7572 |
| I_quic_headers | 12.7690 / 27.6384 / 46.2196 | 12.5447 / 25.8920 / 45.0896 |

## Finalization to event latency (ms)

Triples are p50 / p95 / p99. Unavailable means no observations; disabled metadata is not measured zero.

| Workload | F5 disabled | F5 enabled |
|---|---:|---:|
| A_mixed | 6.6524 / 9.6056 / 34.8193 | 6.7306 / 9.5448 / 37.0385 |
| B_cardinality | 7.6262 / 11.1754 / 564.0694 | 7.8662 / 12.2862 / 621.1521 |
| C_long_tuple | 33.0545 / 33.0545 / 33.0545 | 41.8831 / 41.8831 / 41.8831 |
| D_burst | 8.3329 / 12.2077 / 34.3719 | 7.3479 / 9.5488 / 30.0226 |
| E_slow_websocket | 8.7056 / 12.3767 / 34.7374 | 7.8672 / 10.0799 / 31.1245 |
| F_slow_storage | 8.5657 / 12.4408 / 33.9749 | 7.4909 / 10.4582 / 26.7291 |
| G_dns_heavy | 431.9230 / 766.8749 / 795.2312 | 427.3763 / 782.2065 / 810.6024 |
| H_tls_heavy | 9.0485 / 12.7063 / 33.2260 | 7.6906 / 12.3234 / 29.7646 |
| I_quic_headers | 8.2078 / 29.0751 / 607.4621 | 7.9609 / 13.3372 / 740.1394 |

## TLS metadata latency (ms)

Triples are p50 / p95 / p99. Unavailable means no observations; disabled metadata is not measured zero.

| Workload | F5 disabled | F5 enabled |
|---|---:|---:|
| A_mixed | Unavailable | 0.0997 / 0.1512 / 0.2167 |
| B_cardinality | Unavailable | 0.4692 / 0.5804 / 0.7505 |
| C_long_tuple | Unavailable | 0.0353 / 0.0442 / 0.0898 |
| D_burst | Unavailable | 0.1407 / 0.1956 / 0.2501 |
| E_slow_websocket | Unavailable | 0.1805 / 0.2456 / 0.3225 |
| F_slow_storage | Unavailable | 0.1685 / 0.2356 / 0.3195 |
| G_dns_heavy | Unavailable | Unavailable |
| H_tls_heavy | Unavailable | 0.4243 / 0.6301 / 0.7889 |
| I_quic_headers | Unavailable | Unavailable |

## QUIC metadata latency (ms)

Triples are p50 / p95 / p99. Unavailable means no observations; disabled metadata is not measured zero.

| Workload | F5 disabled | F5 enabled |
|---|---:|---:|
| A_mixed | Unavailable | Unavailable |
| B_cardinality | Unavailable | Unavailable |
| C_long_tuple | Unavailable | Unavailable |
| D_burst | Unavailable | Unavailable |
| E_slow_websocket | Unavailable | Unavailable |
| F_slow_storage | Unavailable | Unavailable |
| G_dns_heavy | Unavailable | Unavailable |
| H_tls_heavy | Unavailable | Unavailable |
| I_quic_headers | Unavailable | 0.2797 / 0.3735 / 0.4910 |

## Memory and bounded metadata state

RSS is whole-process sampled peak, not F5-only allocation. Byte peak measures allocated reassembly arrays, excluding bounded objects/transient copies.

| Workload | RSS MiB off → on | State peak | Array byte peak | Cache evictions | TLS reassembly evictions | Metadata errors |
|---|---:|---:|---:|---:|---:|---:|
| A_mixed | 221.74 → 221.61 | 16 | 65536 | 0 | 0 | 0 |
| B_cardinality | 221.27 → 223.72 | 64 | 4194304 | 2136 | 2136 | 0 |
| C_long_tuple | 221.25 → 221.86 | 1 | 65536 | 0 | 0 | 0 |
| D_burst | 220.50 → 221.63 | 32 | 65536 | 0 | 0 | 0 |
| E_slow_websocket | 237.79 → 242.29 | 32 | 65536 | 0 | 0 | 0 |
| F_slow_storage | 220.88 → 220.92 | 32 | 65536 | 0 | 0 | 0 |
| G_dns_heavy | 223.53 → 224.68 | 0 | 0 | 0 | 0 | 0 |
| H_tls_heavy | 221.21 → 221.83 | 64 | 65536 | 1302 | 1302 | 0 |
| I_quic_headers | 221.31 → 221.60 | 64 | 0 | 2123 | 0 | 0 |

All measured metadata caches remained at or below the configured 64 connections; F5 processing errors were zero in all nine enabled runs. Protocol-malformed counters on non-TLS candidate-port bytes are parser outcomes, not malware findings. Transport drop/subscriber counters and every latency sample count are retained in the full benchmark JSON. No claim of statistical significance or production capacity follows from these observations.

Reproduction: `PYTHONPATH=src .venv/bin/python scripts/rw5b_benchmark.py --registry /tmp/sentinel-rw4-preview/registry --model runtime/1.0.0 --seconds 30 --output <directory>`; add `--encrypted-disabled` for control. Run separately without concurrent test/browser work. Environment manifests bind dependency/hardware/configuration/model details and benchmark file hashes.

Artifacts: [enabled](sih-f5-benchmark-enabled.json), [disabled](sih-f5-benchmark-disabled.json), [comparison](sih-f5-benchmark-comparison.json), [enabled environment](sih-f5-environment-enabled.json), [disabled environment](sih-f5-environment-disabled.json).
