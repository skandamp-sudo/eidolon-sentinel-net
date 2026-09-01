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

1. **Import Restrictions**: The ingestion modules (`parser.py`, `replay.py`) import ONLY read-only functions from scapy:
   - ✅ `scapy.all.Ether`, `scapy.all.raw` — packet decoding
   - ✅ `scapy.layers.inet.IP`, `.TCP`, `.UDP`, `.ICMP` — layer access
   - ✅ `scapy.utils.PcapReader` — file reading
   - ❌ Never imports: `send`, `sendp`, `sr`, `sr1`, `AsyncSniffer`, `sniff`

2. **File-Only Input**: `PcapReplay` only accepts filesystem paths. It validates file existence, readability, and extension before processing.

3. **No Socket Operations**: The ingestion layer never opens network sockets, never binds to interfaces, never creates raw sockets.

### Verification

To verify passive compliance, run:

```bash
# Search for any sending function imports
grep -rn "from scapy.*import.*send\|sendp\|sr\b\|sr1\b\|sniff\b\|AsyncSniffer" src/sentinel_net/ingestion/

# Should return no results
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
