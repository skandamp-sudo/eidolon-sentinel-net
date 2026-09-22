# SIH-F3 full-path operational comparison

All six RW-5B workloads ran for a predeclared 30 seconds plus drain with intelligence enabled, then disabled in the same code. Each workload used a fresh process. The archived RW-5B run is a third comparison. Source, input PCAP and model digests are recorded; each input SHA-256 and frozen-model identity matches across all three conditions. No validation tests ran concurrently with the measured suites.

Host: macOS-26.7-x86_64-i386-64bit; Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz; 8 physical / 16 logical cores; 16 GiB RAM. Python 3.12.14, NumPy 2.5.2, scikit-learn 1.9.0, XGBoost 3.4.1. Model: `runtime/1.0.0`, manifest `23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f`. This is the same small synthetic QA bundle, not a production accuracy or throughput claim.

**Interpretation:** these are single-run, sequential observations subject to scheduling, thermal and filesystem/cache variation. Reported differences are measured, but are not a statistically established overhead estimate. In particular, the 0.8% higher enabled throughput under injected slow storage is not evidence of an improvement. The historical RW-5B difference also includes changes to the event schema, instrumentation and host run conditions. Disabled mode retains the same current wire contract and timing hooks; it isolates most state/evidence work but is not a byte-for-byte RW-5B runtime.

## Throughput

| Workload | RW-5B packets/s | F3 disabled packets/s | F3 enabled packets/s | Enabled vs disabled | Enabled vs RW-5B | Enabled flows/s | Enabled Mbps |
|---|---:|---:|---:|---:|---:|---:|---:|
| A · mixed replay | 420.51 | 398.40 | 397.79 | -0.15% | -5.40% | 50.25 | 0.4563 |
| B · high cardinality | 103.99 | 94.03 | 89.88 | -4.41% | -13.57% | 87.82 | 0.1070 |
| C · long-lived tuple | 1579.48 | 1550.27 | 1484.41 | -4.25% | -6.02% | 0.03 | 1.7748 |
| D · bursty input | 315.43 | 312.48 | 286.91 | -8.18% | -9.04% | 71.69 | 0.2070 |
| E · slow WebSocket | 275.14 | 266.88 | 263.22 | -1.37% | -4.33% | 65.80 | 0.3144 |
| F · slow persistence | 112.56 | 112.21 | 113.11 | +0.80% | +0.48% | 28.28 | 0.1347 |

Rates use successfully processed packets/bytes and monotonic duration including final drain. Mbps counts captured-frame bytes ×8 / seconds /1e6, not link capacity. Exact completed-flow/event counts, input bytes, durations, all three flows/s and Mbps comparisons, and sampled windows are in the JSON artifacts.

## RSS and bounded intelligence state

RSS is MiB. Peak is OS process-lifetime peak (including setup); raw reports additionally retain sampled runtime peaks.

| Workload | RW-5B initial / peak / final | Disabled initial / peak / final | Enabled initial / peak / final | Key peak | Buckets/key peak | Members/dimension peak | Session samples/key peak | Signals generated |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A · mixed replay | 213.52 / 219.82 / 219.80 | 213.58 / 220.37 / 220.35 | 213.73 / 220.47 / 220.45 | 4 | 2 | 2 | 32 | 1751 |
| B · high cardinality | 213.36 / 219.72 / 219.62 | 213.86 / 220.30 / 220.26 | 213.70 / 220.48 / 220.46 | 3 | 2 | 1 | 32 | 5384 |
| C · long-lived tuple | 213.54 / 220.77 / 220.59 | 213.73 / 221.27 / 221.18 | 213.66 / 220.90 / 220.82 | 3 | 2 | 1 | 1 | 0 |
| D · bursty input | 213.39 / 219.39 / 219.38 | 213.71 / 220.27 / 220.25 | 213.69 / 220.18 / 220.17 | 3 | 1 | 1 | 32 | 2214 |
| E · slow WebSocket | 228.40 / 237.81 / 237.79 | 228.88 / 238.46 / 238.44 | 228.89 / 239.19 / 239.17 | 3 | 2 | 1 | 32 | 2483 |
| F · slow persistence | 213.40 / 218.68 / 218.66 | 213.72 / 219.54 / 219.51 | 213.74 / 219.64 / 219.61 | 3 | 2 | 1 | 32 | 1320 |

These RW-5B inputs have low source/destination diversity. B varies source ports; the intelligence session key intentionally excludes ephemeral source port and therefore collapses B to three keys. The measurements do not establish performance at the 1024-key/64-member/60-bucket ceiling. Deterministic bound tests separately exercise key eviction, member overflow, capped session histories and a full sliding bucket window.

All enabled runs recorded zero intelligence-processing errors. C emits one completed flow/event at drain; its flow/inference/persistence percentile rows are single observations, **not tail-latency distributions**. Canonical exact per-flow history still grows, independently of the capped intelligence history.

## Latency comparison

All cells are **p50 / p95 / p99 milliseconds**, over each stage’s most recent min(total,4096) observations. Raw JSON preserves sample and total counts. `stream_intelligence` combines timed packet-observation and finalized-flow enrichment calls, so its distribution is not a per-event-only distribution. Finalization-to-event now ends after behavioral evidence and provenance attachment; this intentionally includes F3 work. Inference and original ML evidence timing remain separate. Publication is serialization/queue publication, not remote client receipt.

### A · mixed replay

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 0.5380 / 11.2466 / 19.5986 | 0.6059 / 12.9481 / 21.1731 | 0.5796 / 12.0454 / 20.9653 |
| Finalization → complete DetectionEvent | 5.8127 / 7.9793 / 28.8784 | 6.1275 / 8.7359 / 29.1707 | 6.2618 / 8.2894 / 28.8971 |
| Inference excluding ML evidence | 4.2438 / 5.6174 / 21.2117 | 4.4318 / 5.9966 / 22.8849 | 4.2808 / 5.5958 / 22.4747 |
| ML evidence enrichment | 0.4782 / 0.7784 / 0.9369 | 0.5086 / 0.7526 / 0.9664 | 0.4902 / 0.7626 / 0.9697 |
| Streaming observation / enrichment | Not present | 0.0016 / 0.0145 / 0.0170 | 0.0302 / 0.3055 / 0.3477 |
| Persistence | 2.2767 / 5.9527 / 14.7160 | 2.3845 / 11.1599 / 26.8782 | 2.5372 / 6.4032 / 16.8885 |
| Publication | 0.2812 / 0.3580 / 0.4557 | 0.3114 / 0.3913 / 0.4955 | 0.3464 / 0.4438 / 0.5112 |

### B · high cardinality

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 8.2212 / 18.9978 / 30.8334 | 9.0364 / 20.4547 / 35.2130 | 9.3754 / 20.4687 / 33.3019 |
| Finalization → complete DetectionEvent | 5.1574 / 6.9069 / 297.1135 | 5.6649 / 7.8343 / 406.6153 | 5.7530 / 7.8078 / 343.8763 |
| Inference excluding ML evidence | 4.0318 / 5.1293 / 20.0785 | 4.3817 / 5.7104 / 19.4137 | 4.1826 / 5.3303 / 21.1527 |
| ML evidence enrichment | 0.3891 / 0.4950 / 0.7971 | 0.4226 / 0.5505 / 0.8628 | 0.3966 / 0.4828 / 0.7550 |
| Streaming observation / enrichment | Not present | 0.0109 / 0.0166 / 0.0303 | 0.2454 / 0.3586 / 0.6068 |
| Persistence | 1.9321 / 11.3737 / 14.1823 | 2.1230 / 12.0256 / 23.0834 | 2.3884 / 12.0938 / 18.9891 |
| Publication | 0.2350 / 0.3130 / 0.3958 | 0.2749 / 0.3695 / 0.4655 | 0.3339 / 0.4170 / 0.5182 |

### C · long-lived tuple

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 0.3077 / 0.4750 / 0.5977 | 0.3178 / 0.4354 / 0.5666 | 0.3380 / 0.4873 / 0.6132 |
| Finalization → complete DetectionEvent | 41.8594 / 41.8594 / 41.8594 | 28.3220 / 28.3220 / 28.3220 | 28.0130 / 28.0130 / 28.0130 |
| Inference excluding ML evidence | 5.4055 / 5.4055 / 5.4055 | 5.9292 / 5.9292 / 5.9292 | 5.6426 / 5.6426 / 5.6426 |
| ML evidence enrichment | 15.1924 / 15.1924 / 15.1924 | 2.4690 / 2.4690 / 2.4690 | 2.3212 / 2.3212 / 2.3212 |
| Streaming observation / enrichment | Not present | 0.0009 / 0.0012 / 0.0017 | 0.0179 / 0.0223 / 0.0275 |
| Persistence | 13.0688 / 13.0688 / 13.0688 | 13.9374 / 13.9374 / 13.9374 | 12.3312 / 12.3312 / 12.3312 |
| Publication | 0.3244 / 0.3244 / 0.3244 | 0.3344 / 0.3344 / 0.3344 | 0.4003 / 0.4003 / 0.4003 |

### D · bursty input

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 0.5814 / 11.4188 / 22.6609 | 0.5932 / 11.4802 / 22.1952 | 0.6573 / 13.2211 / 24.3035 |
| Finalization → complete DetectionEvent | 5.6284 / 8.0231 / 23.5348 | 5.7206 / 8.0942 / 25.1725 | 6.6263 / 8.7552 / 25.9029 |
| Inference excluding ML evidence | 4.2021 / 6.2686 / 21.6820 | 4.2398 / 6.2988 / 22.7988 | 4.6514 / 6.5185 / 22.8017 |
| ML evidence enrichment | 0.4751 / 0.6783 / 0.8972 | 0.4756 / 0.6637 / 0.9354 | 0.4812 / 0.5952 / 0.8383 |
| Streaming observation / enrichment | Not present | 0.0014 / 0.0134 / 0.0157 | 0.0284 / 0.2756 / 0.4622 |
| Persistence | 2.2790 / 10.8642 / 22.4239 | 2.3252 / 11.4515 / 16.4010 | 2.3654 / 12.4226 / 17.1633 |
| Publication | 0.2784 / 0.3571 / 0.4222 | 0.3012 / 0.3804 / 0.4436 | 0.3345 / 0.4311 / 0.5317 |

### E · slow WebSocket

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 0.5348 / 12.4271 / 24.4227 | 0.5515 / 13.2335 / 25.0636 | 0.5550 / 12.4253 / 24.7945 |
| Finalization → complete DetectionEvent | 5.8540 / 7.6128 / 24.1698 | 6.0278 / 7.8327 / 24.9152 | 6.1166 / 7.6683 / 25.3355 |
| Inference excluding ML evidence | 4.3951 / 5.6787 / 22.2738 | 4.4974 / 5.8309 / 22.8262 | 4.2934 / 5.4673 / 22.6253 |
| ML evidence enrichment | 0.5004 / 0.6113 / 0.8121 | 0.5003 / 0.6278 / 0.8757 | 0.4832 / 0.5876 / 0.8132 |
| Streaming observation / enrichment | Not present | 0.0018 / 0.0155 / 0.0193 | 0.0303 / 0.3111 / 0.3539 |
| Persistence | 2.2449 / 11.6309 / 23.4610 | 2.3568 / 11.5673 / 23.4070 | 2.4531 / 12.2562 / 24.6244 |
| Publication | 0.2939 / 0.3693 / 0.4478 | 0.3260 / 0.4090 / 0.4820 | 0.3530 / 0.4491 / 0.5222 |

### F · slow persistence

| Stage | RW-5B p50 / p95 / p99 | Disabled p50 / p95 / p99 | Enabled p50 / p95 / p99 |
|---|---:|---:|---:|
| Packet processing | 0.5537 / 31.2293 / 47.3459 | 0.5633 / 31.2417 / 48.7854 | 0.5697 / 31.1631 / 46.1316 |
| Finalization → complete DetectionEvent | 6.2588 / 8.7189 / 25.3569 | 6.3190 / 8.8086 / 25.7868 | 6.1381 / 8.5693 / 24.3730 |
| Inference excluding ML evidence | 4.7107 / 6.5349 / 23.5323 | 4.7269 / 6.4885 / 23.8321 | 4.3903 / 6.2116 / 21.7767 |
| ML evidence enrichment | 0.5267 / 0.6313 / 0.7696 | 0.5229 / 0.6353 / 0.8136 | 0.4811 / 0.5804 / 0.7587 |
| Streaming observation / enrichment | Not present | 0.0017 / 0.0154 / 0.0277 | 0.0309 / 0.3260 / 0.4222 |
| Persistence | 22.7367 / 31.6080 / 43.4451 | 22.7807 / 32.2056 / 45.2844 | 22.8258 / 32.3538 / 41.9903 |
| Publication | 0.3024 / 0.3820 / 0.4426 | 0.3246 / 0.4086 / 0.4923 | 0.3552 / 0.4469 / 0.5370 |

## Pressure and interpretation

| Workload (enabled) | Processed packets | Flows/events | Packet drops | Delivery-copy drops | Intelligence errors | Canonical exact-history sample peak |
|---|---:|---:|---:|---:|---:|---:|
| A · mixed replay | 12,008 | 1,517 / 1,517 | 0 | 0 | 0 | 376 |
| B · high cardinality | 2,755 | 2,692 / 2,692 | 0 | 0 | 0 | 2 |
| C · long-lived tuple | 44,596 | 1 / 1 | 0 | 0 | 0 | 44,596 |
| D · bursty input | 8,772 | 2,192 / 2,192 | 310,716 | 0 | 0 | 7 |
| E · slow WebSocket | 7,900 | 1,975 / 1,975 | 0 | 1,424 | 0 | 4 |
| F · slow persistence | 3,396 | 849 / 849 | 0 | 0 | 0 | 4 |

D remains an intentionally overloaded 128-entry raw-packet queue; E remains a real loopback slow reader with a 16-entry subscriber queue and send timeout. E’s output timeout is expected operational pressure, not an intelligence or scientific error. F injects 20 ms per persistence call. No persistence or retention failures occurred in either suite. The same count-based/eventual retention policy remains in force; event totals may exceed the retention target between bounded cleanup cycles. These observations do not resolve real-interface BPF access, long-term memory behavior or deployment policy calibration.

## Reproduction and artifacts

From the repository root, using the same approved artifact (or record the different model identity):

```sh
PYTHONPATH=src .venv/bin/python scripts/rw5b_benchmark.py \
  --registry /path/to/registry --model runtime/1.0.0 \
  --seconds 30 --output /tmp/sih-f3-new-enabled
PYTHONPATH=src .venv/bin/python scripts/rw5b_benchmark.py \
  --registry /path/to/registry --model runtime/1.0.0 \
  --seconds 30 --output /tmp/sih-f3-new-disabled --intelligence-disabled
PYTHONPATH=src .venv/bin/python scripts/rw5b_environment.py \
  --benchmark /tmp/sih-f3-new-enabled/benchmark.json \
  --output /tmp/sih-f3-new-enabled/environment.json
```

Input templates are generated offline with explicit Ethernet addresses and documentation-range IPs; they are never transmitted. Only E opens a loopback WebSocket for event delivery. Resource/RSS access may require execution outside the desktop sandbox. No capture privilege or external network generation is used.

- [Enabled raw measurements](sih-f3-benchmark-enabled.json) / [environment](sih-f3-environment-enabled.json)
- [Disabled raw measurements](sih-f3-benchmark-disabled.json) / [environment](sih-f3-environment-disabled.json)
- [Computed comparison](sih-f3-benchmark-comparison.json)
- [Archived RW-5B benchmark](rw5b-benchmark.json)
- [Architecture, bounds and semantics](sih-f3-architecture.md)
