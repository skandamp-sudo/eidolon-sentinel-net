# Preflight

From the repository root, with a private `SENTINEL_API_KEY` (at least 16 characters) in the environment:

```zsh
PYTHONPATH=src:. .venv/bin/python scripts/judge_demo.py preflight --registry /tmp/sentinel-rw4-preview/registry
```

Checks Python/dependency availability, an existing production frontend build, key presence, a writable temporary-workspace parent, pinned PCAP SHA-256, pinned approved runtime manifest, all bundle checksums/approval/schema through the frozen loader, all 23 protected source hashes, and free loopback ports 8010/5174. The loader verifies 52 ordered features and schema 2.0.0 before inference. It never approves a candidate. Errors print the failed check label without secret values or local paths. Exit 0/DEMO READY only if every check passes; otherwise exit 1/DEMO NOT READY.

Run before starting either demo process. Port checks are point-in-time; startup remains authoritative. A port conflict is treated as occupied without inspecting or killing another user's process. `--port` changes only API port; frontend remains 5174. The frontend uses `--strictPort`, so it cannot silently move to a different origin.

DEMO READY means prerequisites passed, not that replay finished. Confirm REPLAY COMPLETE and expected counts after startup. Runtime file checks do not establish scientific suitability or digital signatures. This pinned bundle is synthetic QA only.

No dependency install, download, sudo or host permission changes occur. The exact target machine must already have the reviewed bundle and build. If its temporary registry has disappeared, stop; do not train or publish a substitute.
