# Dataset Provenance — EIDOLON // SENTINEL-NET

This document describes research datasets suitable for training and evaluating the
SENTINEL-NET detection pipeline. Datasets are NOT auto-downloaded. Users must
explicitly obtain, configure, and place dataset files.

> **Important**: Do not assume dataset schemas or labels are identical. Each dataset
> requires a dedicated adapter (`LabelMapper`) that maps dataset-specific labels
> to the canonical SENTINEL-NET threat categories.

## Canonical Threat Categories

| Category | Description |
|----------|-------------|
| `benign` | Normal/legitimate traffic |
| `ddos` | Distributed denial of service |
| `reconnaissance` | Port scanning, network probing |
| `c2` | Command and control communication |
| `dns_tunneling` | DNS-based data exfiltration channels |
| `exfiltration` | Data theft / unauthorized data transfer |
| `brute_force` | Credential guessing attacks |
| `other` | Attack types not mapped to a specific category |
| `unknown` | Unlabeled or unmapped traffic |

---

## CIC-IDS2017

- **Source**: Canadian Institute for Cybersecurity, University of New Brunswick
- **URL**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Format**: PCAP files + CSV flow features
- **License**: Available for research use. Cite: Sharafaldin et al., 2018
- **Capture Period**: Monday–Friday, July 3–7, 2017
- **Known Limitations**:
  - Captured in a controlled lab environment (not production traffic)
  - Class imbalance: benign traffic dominates
  - Some attack scenarios are short-lived
  - CSV features may not match our 52-feature schema exactly
  - Timestamps are in local time, not UTC
  - Duplicate flow entries have been reported in the CSVs

### Label Mapping (CIC-IDS2017 → SENTINEL-NET)

| CIC-IDS2017 Label | SENTINEL-NET Label |
|--------------------|-------------------|
| BENIGN | benign |
| DoS Hulk | ddos |
| DoS GoldenEye | ddos |
| DoS Slowhttptest | ddos |
| DoS slowloris | ddos |
| Heartbleed | ddos |
| DDoS | ddos |
| FTP-Patator | brute_force |
| SSH-Patator | brute_force |
| PortScan | reconnaissance |
| Bot | c2 |
| Infiltration | exfiltration |
| Web Attack – Brute Force | other |
| Web Attack – XSS | other |
| Web Attack – Sql Injection | other |

### Preprocessing Decisions
- Strip whitespace from label strings (CSV labels contain leading/trailing spaces)
- Drop rows with NaN/inf in critical flow fields
- Deduplication by flow key + timestamp if needed
- Feature re-extraction from PCAPs preferred over using pre-computed CSVs

---

## UNSW-NB15

- **Source**: Cyber Range Lab, UNSW Canberra at ADFA
- **URL**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Format**: PCAP files + CSV features
- **License**: Available for research use. Cite: Moustafa & Slay, 2015
- **Capture Period**: 2015
- **Known Limitations**:
  - 9 attack categories with varying sample counts
  - Some categories (Worms) have very few samples
  - Synthetic traffic mixed with real background traffic
  - Feature extraction methodology differs from SENTINEL-NET
  - Labels are based on the IXIA PerfectStorm tool configuration

### Label Mapping (UNSW-NB15 → SENTINEL-NET)

| UNSW-NB15 Label | SENTINEL-NET Label |
|-----------------|-------------------|
| Normal | benign |
| DoS | ddos |
| Reconnaissance | reconnaissance |
| Analysis | reconnaissance |
| Backdoor / Backdoors | c2 |
| Shellcode | c2 |
| Exploits | other |
| Fuzzers | other |
| Generic | other |
| Worms | other |

### Preprocessing Decisions
- Normalize label casing
- Handle dual naming: "Backdoor" vs "Backdoors"
- Very small classes (Worms: ~174 samples) may need to be merged or excluded
- Feature re-extraction from PCAPs preferred over using pre-computed CSVs

---

## Dataset Usage

### Configuring a Dataset

```python
from sentinel_net.detection.dataset import LabelMapper, DatasetBuilder

# For CIC-IDS2017
mapper = LabelMapper.for_cicids2017()
mapped_labels = mapper.map_array(raw_labels)

# For UNSW-NB15
mapper = LabelMapper.for_unsw_nb15()
mapped_labels = mapper.map_array(raw_labels)
```

### Creating a Dataset from PCAPs (Preferred)

```python
from sentinel_net.pipeline import PcapPipeline
from sentinel_net.detection.dataset import DatasetBuilder

pipeline = PcapPipeline()
result = pipeline.process(Path("dataset.pcap"))
builder = DatasetBuilder()
X, y, scenarios = builder.from_feature_vectors(
    result.feature_vectors,
    labels=mapped_labels,
    source="CIC-IDS2017",
)
```

### Data Leakage Prevention

Datasets are split by **scenario/source**, not by individual flow. Flows from the
same PCAP or attack scenario remain in the same split partition.

```python
split = builder.scenario_aware_split(X, y, scenarios, random_state=42)
# split.X_train, split.X_val, split.X_test are disjoint by scenario
```

---

## Adding New Datasets

To add a new dataset:

1. Create a `LabelMapper` with the dataset's label → SENTINEL-NET mapping
2. Document the dataset in this file (source, license, limitations, mapping)
3. Implement any necessary CSV/PCAP parsing in a dataset-specific adapter
4. Do NOT assume schema compatibility with existing datasets
5. Do NOT auto-download dataset files

---

## Unsupported Threat Classes

If a dataset does not contain examples of a particular threat class, that class
is marked as **UNSUPPORTED** in the trained model. The classifier will not predict
unsupported classes. This is intentional — fabricating training data for missing
classes would produce unreliable models.
