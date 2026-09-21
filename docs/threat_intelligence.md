# EIDOLON // SENTINEL-NET — Threat Intelligence

## MITRE ATT&CK Mapping

### Architecture

```
Threat Classification (model output)
        ↓
ATTACKMapper (static mapping table)
        ↓
ATTACKMapping[] (qualified potential techniques)
        ↓
Qualification (confidence-based)
```

### Key Distinction

| Concept | Source | Meaning |
|---------|--------|---------|
| **Model Classification** | ML classifier output | "The model predicts this flow is DDoS" |
| **ATT&CK Mapping** | Static mapping table | "DDoS flows are potentially associated with T1498" |

These are NOT the same thing. A model classification is a statistical prediction. An ATT&CK mapping is a potential association that requires further investigation.

### Qualification Levels

| Model Confidence | Qualification |
|-----------------|---------------|
| ≥ 0.8 | "likely" |
| ≥ 0.5 | "observed indicators consistent with" |
| < 0.5 | "possible" |

### Supported Mappings

| Threat Type | ATT&CK Technique(s) | Tactic |
|-------------|---------------------|--------|
| ddos | T1498 Network DoS, T1499 Endpoint DoS | Impact |
| c2 | T1071 Application Layer Protocol, T1573 Encrypted Channel | Command and Control |
| reconnaissance | T1046 Network Service Scanning, T1595 Active Scanning | Discovery / Reconnaissance |
| scan | T1046 Network Service Scanning | Discovery |
| exfiltration | T1041 Exfiltration Over C2, T1048 Alt Protocol | Exfiltration |
| brute_force | T1110 Brute Force | Credential Access |
| dns_tunneling | T1071.004 DNS Protocol | Command and Control |

### Limitations

- Mappings are research-grade, not exhaustive
- No external threat intelligence feeds integrated
- No IOC (Indicator of Compromise) matching
- Single classifier label may map to multiple techniques
- No temporal correlation across multiple flows
- Qualification is based on model confidence alone, not corroborating evidence

### Customization

The `ATTACKMapper` accepts a custom mapping table:

```python
custom_table = {
    "custom_threat": [{
        "technique_id": "T9999",
        "technique_name": "Custom Technique",
        "tactic": "Custom Tactic",
        "rationale": "Custom rationale",
        "applicability": "high",
    }]
}
mapper = ATTACKMapper(mapping_table=custom_table)
```

## Future Work

- [ ] IOC integration (IP reputation, domain intelligence)
- [ ] Multi-flow correlation for campaign detection
- [ ] Temporal pattern analysis for APT detection
- [ ] STIX/TAXII output format
- [ ] Integration with external threat intelligence platforms
