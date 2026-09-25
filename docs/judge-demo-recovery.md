# Recovery

These are bounded operator procedures; two-minute targets are reasonable for configuration errors, not missing artifacts or storage damage. Recovery times were not comprehensively timed.

| Failure | Exact recovery |
|---|---|
| Backend already running / API collision | Stop only the foreground demo you own with Ctrl-C. Wait for shutdown to finish, then re-run preflight. For an unrelated occupied 8010 use `--port 8011` on both preflight/run and enter port 8011 in browser Settings. Never kill arbitrary processes. |
| Frontend already running / 5174 collision | Stop only your owned foreground preview; rerun preflight, backend and the documented strict-port preview. Do not reuse an unknown server. |
| Wrong key | In Settings enter the same private key supplied to the backend and Connect. If unknown, stop the owned demo, enter a new private key in the shell and start a fresh run. Never reveal it on a projector or in a URL. |
| Corrupted demo DB | Stop the owned backend, restart `run`: a new private temporary DB is created. Preserve the corrupt workspace for investigation; no deletion/repair of arbitrary DBs. |
| Wrong PCAP hash | Stop. Regenerate with `scripts/generate_judge_demo.py`, then preflight; proceed only if the pinned hash matches. Do not alter the expected hash to accept unknown bytes. |
| Missing model | Stop. Restore only the previously reviewed trusted bundle through the operator's artifact process. No automatic download/training/publication. |
| Model checksum failure | Stop and quarantine for operator investigation. Never change checksums, disable validation or substitute the unapproved candidate. |
| WebSocket disconnect | Confirm API reachable, key and endpoint; refresh browser or reconnect in Settings. REST still shows retained committed records. No exactly-once WS history claim. |
| Browser refresh | Same-tab sessionStorage normally preserves configuration; otherwise reconnect in Settings. Open current retained events, not a previous run's UUID. |
| Replay interrupted | STOPPED is incomplete; never call it REPLAY COMPLETE. Accepted packets drain. Preserve partial evidence if needed, stop owned servers and start a fresh `run`; compare 191/72 counts. |
| Stale demo DB / old event URL | Launcher never reuses a DB. Refresh Detections after new backend is ready and select by documented source/ports. A stale UUID should return unavailable, not be fabricated. |
| Background replay exception | API reachability alone is insufficient. Inspect local logs privately, require REPLAY COMPLETE and zero error counters; address the failed prerequisite and rerun fresh. |

Verified interruption: bounded paced replay was stopped after acceptance began; accepted packets were parsed, active flows persisted, REST/export remained usable, lifecycle was STOPPED, and the subsequent clean replay matched all stable outputs. No arbitrary database cleanup is provided.
