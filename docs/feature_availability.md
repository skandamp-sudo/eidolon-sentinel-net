# Feature Availability Matrix

## CICIDS2017 → Sentinel-NET 52-Feature Schema

| # | Sentinel Feature | Availability | Source Column(s) | Transformation | Unit Conv |
|---|-----------------|-------------|------------------|----------------|-----------|
| 0 | duration_sec | DIRECT | Flow Duration | ÷ 1,000,000 | μs → s |
| 1 | total_packets | DERIVED | Total Fwd Packets + Total Backward Packets | sum | — |
| 2 | total_bytes | DERIVED | Fwd Packets Length Total + Bwd Packets Length Total | sum | — |
| 3 | packets_per_sec | DIRECT | Flow Packets/s | identity | — |
| 4 | bytes_per_sec | DIRECT | Flow Bytes/s | identity | — |
| 5 | forward_packets | DIRECT | Total Fwd Packets | identity | — |
| 6 | reverse_packets | DIRECT | Total Backward Packets | identity | — |
| 7 | forward_bytes | DIRECT | Fwd Packets Length Total | identity | — |
| 8 | reverse_bytes | DIRECT | Bwd Packets Length Total | identity | — |
| 9 | fwd_rev_packet_ratio | DERIVED | fwd / max(rev, 1) | safe division | — |
| 10 | fwd_rev_byte_ratio | DERIVED | fwd / max(rev, 1) | safe division | — |
| 11 | pkt_size_mean | DIRECT | Packet Length Mean | identity | — |
| 12 | pkt_size_std | DIRECT | Packet Length Std | identity | — |
| 13 | pkt_size_min | DIRECT | Packet Length Min | identity | — |
| 14 | pkt_size_max | DIRECT | Packet Length Max | identity | — |
| 15 | pkt_size_median | **MISSING** | — | NaN | — |
| 16 | pkt_size_p25 | **MISSING** | — | NaN | — |
| 17 | pkt_size_p75 | **MISSING** | — | NaN | — |
| 18 | pkt_size_p90 | **MISSING** | — | NaN | — |
| 19 | iat_mean | DIRECT | Flow IAT Mean | ÷ 1,000,000 | μs → s |
| 20 | iat_std | DIRECT | Flow IAT Std | ÷ 1,000,000 | μs → s |
| 21 | iat_min | DIRECT | Flow IAT Min | ÷ 1,000,000 | μs → s |
| 22 | iat_max | DIRECT | Flow IAT Max | ÷ 1,000,000 | μs → s |
| 23 | iat_median | **MISSING** | — | NaN | — |
| 24 | fwd_iat_mean | DIRECT | Fwd IAT Mean | ÷ 1,000,000 | μs → s |
| 25 | fwd_iat_std | DIRECT | Fwd IAT Std | ÷ 1,000,000 | μs → s |
| 26 | fwd_iat_min | DIRECT | Fwd IAT Min | ÷ 1,000,000 | μs → s |
| 27 | fwd_iat_max | DIRECT | Fwd IAT Max | ÷ 1,000,000 | μs → s |
| 28 | rev_iat_mean | DIRECT | Bwd IAT Mean | ÷ 1,000,000 | μs → s |
| 29 | rev_iat_std | DIRECT | Bwd IAT Std | ÷ 1,000,000 | μs → s |
| 30 | rev_iat_min | DIRECT | Bwd IAT Min | ÷ 1,000,000 | μs → s |
| 31 | rev_iat_max | DIRECT | Bwd IAT Max | ÷ 1,000,000 | μs → s |
| 32 | syn_count | DIRECT | SYN Flag Count | identity | — |
| 33 | syn_ack_count | **MISSING** | — | NaN | — |
| 34 | ack_count | DIRECT | ACK Flag Count | identity | — |
| 35 | fin_count | DIRECT | FIN Flag Count | identity | — |
| 36 | rst_count | DIRECT | RST Flag Count | identity | — |
| 37 | psh_count | DIRECT | PSH Flag Count | identity | — |
| 38 | syn_ratio | DERIVED | SYN / max(total_pkts, 1) | safe division | — |
| 39 | ack_ratio | DERIVED | ACK / max(total_pkts, 1) | safe division | — |
| 40 | fin_ratio | DERIVED | FIN / max(total_pkts, 1) | safe division | — |
| 41 | rst_ratio | DERIVED | RST / max(total_pkts, 1) | safe division | — |
| 42 | psh_ratio | DERIVED | PSH / max(total_pkts, 1) | safe division | — |
| 43 | protocol | DIRECT | Protocol | identity | — |
| 44 | ip_version | **MISSING** | — | NaN | — |
| 45 | is_tcp | DERIVED | Protocol == 6 | boolean | — |
| 46 | is_udp | DERIVED | Protocol == 17 | boolean | — |
| 47 | is_icmp | DERIVED | Protocol == 1 | boolean | — |
| 48 | payload_bytes_total | **MISSING** | — | NaN | — |
| 49 | forward_payload_bytes | **MISSING** | — | NaN | — |
| 50 | reverse_payload_bytes | **MISSING** | — | NaN | — |
| 51 | payload_ratio | **MISSING** | — | NaN | — |

**Summary**: 29 DIRECT + 12 DERIVED + 0 PROXY + 11 MISSING = 52

---

## UNSW-NB15 → Sentinel-NET 52-Feature Schema

| # | Sentinel Feature | Availability | Source Column(s) | Transformation |
|---|-----------------|-------------|------------------|----------------|
| 0 | duration_sec | DIRECT | dur | identity |
| 1 | total_packets | DERIVED | spkts + dpkts | sum |
| 2 | total_bytes | DERIVED | sbytes + dbytes | sum |
| 3 | packets_per_sec | DERIVED | total / max(dur, 1e-6) | safe division |
| 4 | bytes_per_sec | **PROXY** | rate | ~bytes/sec |
| 5 | forward_packets | DIRECT | spkts | identity |
| 6 | reverse_packets | DIRECT | dpkts | identity |
| 7 | forward_bytes | DIRECT | sbytes | identity |
| 8 | reverse_bytes | DIRECT | dbytes | identity |
| 9 | fwd_rev_packet_ratio | DERIVED | spkts / max(dpkts, 1) | safe division |
| 10 | fwd_rev_byte_ratio | DERIVED | sbytes / max(dbytes, 1) | safe division |
| 11–18 | pkt_size_* | **MISSING** | — | NaN |
| 19–23 | iat_* | **MISSING** | — | NaN |
| 24 | fwd_iat_mean | **PROXY** | sinpkt | ≈ fwd IAT |
| 25–27 | fwd_iat_std/min/max | **MISSING** | — | NaN |
| 28 | rev_iat_mean | **PROXY** | dinpkt | ≈ rev IAT |
| 29–31 | rev_iat_std/min/max | **MISSING** | — | NaN |
| 32–42 | TCP flags (all) | **MISSING** | — | NaN |
| 43 | protocol | DIRECT | proto | str→int encoding |
| 44 | ip_version | **MISSING** | — | NaN |
| 45 | is_tcp | DERIVED | proto == 'tcp' | boolean |
| 46 | is_udp | DERIVED | proto == 'udp' | boolean |
| 47 | is_icmp | DERIVED | proto == 'icmp' | boolean |
| 48–51 | payload_* | **MISSING** | — | NaN |

**Summary**: 6 DIRECT + 8 DERIVED + 3 PROXY + 35 MISSING = 52

> **CRITICAL**: Only 17/52 features (33%) have data for UNSW-NB15.
> Models trained on the full 52-feature schema receive NaN for 67% of inputs.
> After imputation (median from training), these 35 features become
> constant values — contributing zero discriminative signal and potentially
> dominating the model if not properly handled.

---

## Missing Feature Handling

### In Adapter
Missing features are represented as `np.nan`. No fabrication, no silent zeros.

### In Preprocessor
`FeaturePreprocessor` applies:
1. `SimpleImputer(strategy='median')` — NaN → training set median
2. `StandardScaler()` — center and scale

For all-NaN columns, the imputed value will be 0.0 (median of empty after filling
with initial median estimate). After scaling, these become 0.0 (constant).

### Scientific Implication
Imputed features carry no signal. The model treats them as training-distribution
average. This is acceptable if:
- The model was also trained with these features as NaN/imputed
- The evaluation explicitly documents which features were available

This is NOT acceptable if:
- The model was trained on features from PCAP extraction (where these features had real values)
- The evaluation presents results as if all 52 features were available
