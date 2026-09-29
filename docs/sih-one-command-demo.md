# One-command local SIH demo

This is **post-freeze operator tooling**, not a change to application authentication or detection behavior. The frozen tag remains `sih26145-code-freeze-2026-09-25`.

**Current status: ONE-COMMAND SIH DEMO READY. Exact trusted QA bundle recovered.** All seven files match the frozen judge-demo SHA-256 values. The launcher uses the stable ignored `.local/sentinel-qa-registry/` location. See [recovery verification](qa-runtime-recovery.md).

## Presentation day

Stop any earlier manual backend/frontend in their own Terminal tabs first. Then use one Terminal:

```sh
cd "/Users/skandamp/Desktop/Eidolon Sentinel-NET"
./run-sih-demo.sh
```

Leave this Terminal running. The launcher opens the browser after backend replay and frontend readiness. Use the newly opened tab: no API endpoint entry, key copying or Connect button is needed. Wait for **DEMO READY**, which requires bootstrap consumption and an authenticated WebSocket subscriber. Press **Control+C** in this Terminal to stop the demo.

URLs: frontend `http://127.0.0.1:5174`; API `http://127.0.0.1:8010`. Port 8000 is not used. Opening the API directly without authentication still returns 401.

## Architecture and prerequisites

The launcher requires the existing `.venv`, existing `frontend/dist` production build and the trusted synthetic QA registry at `.local/sentinel-qa-registry/`. It installs nothing, trains nothing and never substitutes the scientific candidate. macOS `open` is used to open the default browser. If opening fails, the services remain running and the printed frontend URL can be opened manually.

The backend command is unchanged:

```sh
PYTHONPATH=src:. .venv/bin/python scripts/judge_demo.py run --registry .local/sentinel-qa-registry
```

Backend environment is scoped to the owned child. The wrapper lets the existing judge launcher run its integrity/preflight checks, then verifies authenticated status and event responses: replay_complete, exactly **191 packets / 72 completed flows / 72 persisted events**.

Per the explicit bootstrap authorization, a small standard-library loopback HTTP server serves the **existing production build** instead of Vite preview. npm is not a runtime dependency of this wrapper; it is needed only if the build must be prepared separately. No frontend source or build file is rewritten. The root response is temporarily replaced in memory with bootstrap logic; all normal application assets remain unchanged. Frontend routes then use the original built index.

## Credential and one-time bootstrap

`.sentinel-demo.local` is gitignored. On first use the launcher exclusively creates it with a strong random credential and mode 0600. Later launches reuse exactly that value. Existing files must be owner-owned regular files with one valid entry; symlinks/FIFOs are rejected. It is parsed as data, never sourced as shell code.

This credential is **DEMO ONLY**, not production credential management, and must never be reused outside the local SIH demo. Production deployments must continue using an externally provided secret.

The initial bootstrap page contains only logic, never the API key. It receives an ephemeral HttpOnly, SameSite=Strict cookie scoped to the bootstrap path. Its same-origin POST to `/__eidolon_demo_bootstrap` must present:

- loopback peer address and exact `Host: 127.0.0.1:5174`;
- exact `Origin: http://127.0.0.1:5174`;
- `Sec-Fetch-Site: same-origin`;
- the per-launch cookie capability;
- an empty request body.

The credential is returned once in a transient JSON response with `Cache-Control: no-store`, no CORS headers, and no access logging. The single-threaded server consumes the grant before responding; another valid request returns 410. The server clears its credential response state after consumption. No credential is inserted into static HTML, a URL, source code or logs. The browser writes the existing keys:

```text
sentinel_api_url = http://127.0.0.1:8010
sentinel_api_key = [the local credential; never printed]
sentinel_configured = true
```

After an authenticated API check it navigates to `/sensor`. The unchanged app restores these values and performs its existing WebSocket auth-message exchange. The API's normal authentication is not weakened. Launcher API checks ignore ambient proxies and reject redirects rather than forwarding the credential elsewhere.

## Process ownership, shutdown and restart

Both ports are checked before credential creation/startup. An occupied listener causes an actionable failure; the launcher does not kill it or choose a different port. All backend processes run in a launcher-owned process group. SIGINT, SIGTERM and terminal hangup request cleanup: stop the frontend, send SIGTERM to the backend group, wait up to ten seconds, then use SIGKILL only as a bounded fallback for that owned group. Only the launcher's own temporary workspace is removed.

The frozen judge preflight uses a non-reuse socket bind. Even after listeners close, macOS TCP TIME_WAIT can temporarily prevent that bind. The wrapper reports this and waits up to 60 seconds for the kernel state to settle during startup/cleanup, without changing or bypassing the frozen preflight. Wait for both port-release messages and the shell prompt before relaunching. A real unrelated listener fails immediately and is never terminated.

SIGKILL, machine shutdown or forcibly terminating the controlling tool cannot guarantee cleanup. A subsequent launch detects remaining listeners and asks the operator to stop the earlier process. It never uses broad pkill/killall or sudo.

## Operational limitations

- One bootstrap grant per launch. Refreshing the authenticated tab works through sessionStorage; a new independent tab after consumption is not automatically granted the key. Restart the launcher for a new grant.
- Browser storage denial or a failed transfer after consumption requires a restart; the grant is not silently reissued.
- Loopback restrictions are not a defense against another malicious process running as the same local user. Such a process may read local credentials or emulate browser requests. This is not production authentication infrastructure.
- Cookie/storage behavior and browser extensions may affect startup. The readiness line is withheld until a real authenticated subscriber is observed. Only one demo session should own these ports.
- The default HTTP server is for local operator convenience, not internet deployment or a load-tested web server.
- The synthetic QA runtime labels all 72 demo events DDoS. These labels demonstrate pipeline execution, **not scientific accuracy or 72 validated attacks**.
- The scientific candidate remains NOT APPROVED / NOT PUBLISHED. Existing science, native-interface, physical-diode, JA4, encrypted-DNS and resource-history limitations remain unchanged.

## Verification

Boundary tests (no production changes):

```sh
PYTHONPATH=src:. .venv/bin/python -m pytest tests/operator/test_sih_launcher.py -q
```

Optional real-browser/process integration uses an already installed Playwright Node package and Chrome; these are verification-only, not launcher dependencies. It installs nothing, requires free ports, launches two sessions and cleans its owned processes:

```sh
.venv/bin/python tests/operator/verify_sih_demo.py
```

### Recovery verification

The exact historical QA generation procedure and original manifest metadata were recovered from local task history. Reconstructing with the historical source and original dependency versions reproduced all seven frozen hashes. No replacement identity, training choice, threshold or approval metadata was introduced. The reconstruction is a recovery operation; normal launches never train or publish models.

Current results and limitations are in [qa-runtime-recovery.md](qa-runtime-recovery.md). The local registry is ignored by Git, so another checkout requires a verified copy of these exact seven files. The `/tmp/sentinel-rw4-preview/registry` compatibility symlink may disappear when macOS clears temporary storage; the one-command launcher does not depend on it.

Changed paths: `.gitignore`, `scripts/run_sih_demo.py`, executable `run-sih-demo.sh`, this guide, the recovery report and `tests/operator/`. No application or frontend source was changed. No commits, pushes or tag changes.

Recommended commit: `feat(tools): add local one-command SIH demo bootstrap`.

## Optional live passive interface

Use the same launcher and bootstrap for an interface you are authorized to monitor:

```sh
./run-sih-demo.sh --interface en0
```

Omitting `--interface` retains the deterministic replay command and its 191/72/72 checks. The live option delegates to the existing `sentinel-net sensor` command through `scripts/live_sih_sensor.py`; it does not implement another capture pipeline or authentication system. The reviewed QA registry, credential file, loopback endpoints, frontend, browser bootstrap, process ownership and cleanup are shared. No fallback from failed live capture to replay occurs.

The live adapter verifies the same pinned assets before loading, validates the interface, removes ambient SENTINEL overrides, uses a fresh temporary database, and starts from a fresh directory so a project `.env` cannot override the configuration. Existing capture defaults remain non-promiscuous and receive-only. No privilege changes, active traffic, external reputation queries, decryption or model training are added. Live session data is removed with the owned workspace on cleanup, as in the demo wrapper; it is not durable investigation storage.

Live readiness requires the selected interface, `live_passive_sensor` mode, running sensor state and an authenticated WebSocket subscriber. It has no fixed traffic-count requirement. Terminal readiness reads `LIVE PASSIVE READY — SYNTHETIC QA MODEL`. Failed, stopped or error sensor status causes the wrapper to stop its owned services. An active degraded sensor stays available with an explicit warning and SOC health reasons; the launcher does not label it healthy or confuse it with a crashed worker.

The recovered runtime remains synthetic QA: using real packets does not validate its predictions or make them confirmed attacks. Counts depend on naturally observed traffic; flows may not emit immediately because existing idle timeouts apply.

### Live validation on this host

The earlier capture permission blocker has been resolved by the operator. No additional system/BPF changes were made. The subsequent exit was reproduced and traced to unsupported non-IP frames being counted as malformed, then the wrapper treating DEGRADED as a crash. See [live diagnosis and current validation](live-passive-diagnosis.md) for exact evidence, changes, tests and limits.

Live capture now counts unsupported non-IP Ethernet frames separately as `packets_non_ip_skipped`. The SOC shows this counter only for live operation. Declared IP packets and truncated headers still use the existing parser/error path. Replay processing is unchanged. The existing wrapper authentication/bootstrap is reused.

The opt-in browser/process verifier can now check the authorized interface for two runs, each requiring at least 65 seconds of RUNNING state and changing SOC counters:

```sh
.venv/bin/python tests/operator/verify_sih_demo.py --live-interface en0
```

This observes existing traffic only; it does not generate packets. No inference output is treated as scientific validation of the synthetic QA model. Bounded testing does not establish long-duration or arbitrary-load behavior. Normal Ctrl+C cleanup removes this launcher's temporary database; local diagnostic logs and databases retained during investigation are ignored and may contain network metadata.

Recommended commit: `fix(sensor): distinguish non-IP live frames and preserve degraded operation`.
