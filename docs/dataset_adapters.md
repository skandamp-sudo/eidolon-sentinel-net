# Dataset Adapters

## Overview

Sentinel-NET dataset adapters transform external network intrusion detection datasets
into the canonical 52-feature schema defined in `FEATURE_SCHEMA`. Each adapter produces
a `(X, labels, scenarios)` tuple compatible with the existing `DatasetBuilder` and
`FeaturePreprocessor` pipeline.

## Architecture

```
External Dataset (CSV/Parquet)
        │
        ▼
  ┌──────────────┐
  │  Adapter      │  CICIDSAdapter / UNSWAdapter
  │  .load_all()  │
  └──────┬───────┘
         │  (X: ndarray[n, 52], labels: ndarray[n], scenarios: ndarray[n])
         ▼
  ┌──────────────┐
  │  DatasetBuilder│  .scenario_aware_split()
  └──────┬───────┘
         │  DatasetSplit
         ▼
  ┌──────────────┐
  │  Preprocessor │  FeaturePreprocessor.fit_transform()
  └──────┬───────┘  NaN → median imputation, StandardScaler
         │
         ▼
       Model
```

## CICIDS2017 Adapter

**Module**: `sentinel_net.evaluation.adapters.CICIDSAdapter`

**Source**: University of New Brunswick, Canadian Institute for Cybersecurity (2017)

**Input**: Parquet files from `~/Datasets/CICIDS2017/` (8 scenario-day files)

**Feature availability**: 29 DIRECT + 12 DERIVED + 11 MISSING = 52

### Label Mapping

| Raw CICIDS2017 Label | Sentinel-NET Category |
|---------------------|----------------------|
| Benign / BENIGN | benign |
| DoS Hulk, DoS GoldenEye, DoS Slowhttptest, DoS slowloris, Heartbleed, DDoS | ddos |
| FTP-Patator, SSH-Patator | brute_force |
| PortScan | reconnaissance |
| Bot | c2 |
| Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection | other |
| Infiltration | exfiltration |

Note: Web Attack labels may contain mojibake (replacement character `\ufffd`) or
en-dash (`\u2013`) instead of hyphens. All variants are handled.

### Scenario Model

| Scenario | Day | Attack Types |
|----------|-----|-------------|
| Benign-Monday | Monday | Benign only |
| Bruteforce-Tuesday | Tuesday | FTP-Patator, SSH-Patator |
| DoS-Wednesday | Wednesday | DoS GoldenEye/Hulk/Slowhttptest/slowloris, Heartbleed |
| Infiltration-Thursday | Thursday | Infiltration |
| WebAttacks-Thursday | Thursday | Web Attack variants |
| Botnet-Friday | Friday | Bot |
| Portscan-Friday | Friday | PortScan |
| DDoS-Friday | Friday | DDoS |

### Unit Conversions

| Feature | Source Unit | Target Unit | Conversion |
|---------|-----------|-------------|------------|
| duration_sec | microseconds | seconds | ÷ 1,000,000 |
| iat_mean/std/min/max | microseconds | seconds | ÷ 1,000,000 |
| fwd_iat_mean/std/min/max | microseconds | seconds | ÷ 1,000,000 |
| rev_iat_mean/std/min/max | microseconds | seconds | ÷ 1,000,000 |

### Missing Features (NaN)

- pkt_size_median, pkt_size_p25, pkt_size_p75, pkt_size_p90 — CICFlowMeter does not compute percentiles
- iat_median — not available in CICFlowMeter
- syn_ack_count — CICFlowMeter does not separate SYN-ACK from SYN
- ip_version — not in CICFlowMeter output
- payload_bytes_total, forward_payload_bytes, reverse_payload_bytes, payload_ratio — CICFlowMeter does not separate payload from header bytes

## UNSW-NB15 Adapter

**Module**: `sentinel_net.evaluation.adapters.UNSWAdapter`

**Source**: UNSW Canberra, Australian Centre for Cyber Security (2015)

**Input**: CSV files from `~/Datasets/UNSW-NB15/`

**Feature availability**: 6 DIRECT + 8 DERIVED + 3 PROXY + 35 MISSING = 52

> **WARNING**: Only 17 of 52 features have data. 35 features are NaN.
> This means over 67% of the feature space is empty.
> Models trained on the full 52-feature schema cannot be meaningfully
> evaluated on UNSW-NB15 without this caveat.

### Label Mapping

| Raw UNSW-NB15 Category | Sentinel-NET Category |
|------------------------|----------------------|
| Normal | benign |
| DoS | ddos |
| Reconnaissance, Analysis | reconnaissance |
| Backdoor, Shellcode | c2 |
| Exploits, Fuzzers, Generic, Worms | other |

### Proxy Features

| Sentinel Feature | UNSW Column | Justification |
|-----------------|-------------|---------------|
| bytes_per_sec | rate | Close proxy — `rate` is total bits/sec |
| fwd_iat_mean | sinpkt | Source inter-packet time ≈ forward IAT mean |
| rev_iat_mean | dinpkt | Dest inter-packet time ≈ reverse IAT mean |

These are NOT exact equivalents. Document in any evaluation.

## Usage

```python
from pathlib import Path
from sentinel_net.evaluation.adapters import CICIDSAdapter, UNSWAdapter

# Load CICIDS2017
X, labels, scenarios = CICIDSAdapter.load_all(Path.home() / "Datasets" / "CICIDS2017")
# X.shape = (2_313_810, 52), labels.shape = (2_313_810,)

# Load UNSW-NB15
X, labels, scenarios = UNSWAdapter.load_all(Path.home() / "Datasets" / "UNSW-NB15")
# X.shape = (257_673, 52), labels.shape = (257_673,)
```
