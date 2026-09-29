"""Post-freeze local SIH operator tooling. Never use this bootstrap in production."""
from __future__ import annotations

import argparse
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[1]
API = 'http://127.0.0.1:8010'
FRONTEND = 'http://127.0.0.1:5174'
REGISTRY = ROOT / '.local/sentinel-qa-registry'
COOKIE = 'eidolon_demo_bootstrap'
BOOTSTRAP = '/__eidolon_demo_bootstrap'
# No credential or capability is embedded in this HTML; the cookie is HttpOnly.
BOOT_HTML = b'''<!doctype html><html><head><meta charset="utf-8"><title>Local SIH demo</title></head>
<body><h1>LOCAL SIH DEMO</h1><p id="status">Connecting to the local demonstration...</p>
<script>
(async () => {
 try {
  if (location.origin !== 'http://127.0.0.1:5174') throw new Error();
  const r = await fetch('/__eidolon_demo_bootstrap', {method:'POST', credentials:'same-origin', cache:'no-store'});
  if (!r.ok) throw new Error();
  const {key} = await r.json();
  const check = await fetch('http://127.0.0.1:8010/api/v1/status', {headers:{'X-API-Key':key}, cache:'no-store'});
  if (!check.ok) throw new Error();
  sessionStorage.setItem('sentinel_api_url', 'http://127.0.0.1:8010');
  sessionStorage.setItem('sentinel_api_key', key);
  sessionStorage.setItem('sentinel_configured', 'true');
  location.replace('/sensor');
 } catch (_) {
  document.getElementById('status').textContent = 'Bootstrap unavailable. Restart the launcher, then use its browser tab. No credential was printed.';
 }
})();
</script></body></html>'''


class DemoError(Exception):
    """Only operator-safe messages belong in this exception."""


def credential(path: Path) -> str:
    """Create once without following links or sourcing arbitrary shell content."""
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | flags)
        with os.fdopen(fd, 'r') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise DemoError('Credential file must be a regular file owned by you.')
            os.fchmod(stream.fileno(), 0o600)
            value = stream.read(4097)
        match = re.fullmatch(r'SENTINEL_API_KEY=([A-Za-z0-9_-]{32,128})\n?', value)
        if not match:
            raise DemoError('Invalid .sentinel-demo.local format; expected one SENTINEL_API_KEY entry (32–128 URL-safe characters).')
        return match[1]
    else:
        key = secrets.token_urlsafe(48)
        with os.fdopen(fd, 'w') as stream:
            stream.write('SENTINEL_API_KEY=' + key + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        return key


def free_port(port: int) -> None:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('127.0.0.1', port))
        except OSError:
            raise DemoError(f'Port {port} unavailable. Stop the earlier demo in its Terminal (Ctrl+C); inspect with lsof -nP -iTCP:{port} -sTCP:LISTEN. No process was killed.') from None


def settle_ports(timeout=60):
    """Match the frozen judge's non-reuse bind, including TCP TIME_WAIT."""
    deadline = time.monotonic() + timeout
    announced = False
    while True:
        waiting = False
        for port in (8010, 5174):
            free_port(port)  # A real listener always fails immediately.
            with socket.socket() as sock:
                try:
                    sock.bind(('127.0.0.1', port))
                except OSError:
                    waiting = True
        if not waiting:
            return
        if not announced:
            print('[WAIT] Local TCP connections settling for the unchanged judge preflight (up to 60 seconds).', flush=True)
            announced = True
        if time.monotonic() >= deadline:
            raise DemoError('Local TCP ports have not settled; wait briefly and retry. No listener was killed.')
        time.sleep(.2)


class DemoServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, dist: Path, key: str, address=('127.0.0.1', 5174)):
        if address[0] != '127.0.0.1':
            raise DemoError('Bootstrap server must bind to 127.0.0.1.')
        self.dist = dist.resolve()
        self.key = key
        self.nonce = secrets.token_urlsafe(32)
        self.consumed = False
        super().__init__(address, DemoHandler)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(2)
        return sock, addr

    def handle_error(self, request, client_address):
        # Never log request headers, bodies or credential-bearing exceptions.
        pass


class DemoHandler(BaseHTTPRequestHandler):
    server: DemoServer

    def log_message(self, *_):
        pass

    def valid_host(self):
        return self.client_address[0] == '127.0.0.1' and self.headers.get_all('Host') == ['127.0.0.1:5174']

    def reply(self, code, body=b'', mime='text/plain', cookie=False):
        self.send_response(code)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Connection', 'close')
        if cookie:
            self.send_header('Set-Cookie', f'{COOKIE}={self.server.nonce}; HttpOnly; SameSite=Strict; Path={BOOTSTRAP}')
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_POST(self):
        if not self.valid_host():
            return self.reply(403)
        if self.path != BOOTSTRAP:
            return self.reply(404)
        if self.headers.get_all('Origin') != [FRONTEND] or self.headers.get('Sec-Fetch-Site') != 'same-origin':
            return self.reply(403)
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
            return self.reply(400)
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
            supplied = cookies[COOKIE].value
        except (KeyError, ValueError):
            return self.reply(403)
        if not hmac.compare_digest(supplied, self.server.nonce):
            return self.reply(403)
        # Single-threaded HTTPServer makes check-and-consume atomic.
        if self.server.consumed:
            return self.reply(410)
        self.server.consumed = True
        body = json.dumps({'key': self.server.key}).encode()
        self.server.key = ''
        return self.reply(200, body, 'application/json')

    def do_GET(self):
        if not self.valid_host():
            return self.reply(403)
        path = unquote(urlsplit(self.path).path)
        if path == BOOTSTRAP:
            return self.reply(404)
        if path == '/__eidolon_demo_health':
            return self.reply(200, b'local-demo')
        if path in ('/', '/index.html') and not self.server.consumed:
            if self.headers.get('Sec-Fetch-Site', 'none') not in ('none', 'same-origin'):
                return self.reply(403)
            return self.reply(200, BOOT_HTML, 'text/html; charset=utf-8', cookie=True)
        candidate = (self.server.dist / path.lstrip('/')).resolve()
        if not candidate.is_relative_to(self.server.dist):
            return self.reply(404)
        if not candidate.is_file():
            # Known SPA routes only; never expose files outside the built assets.
            if path.split('/')[1] not in ('', 'sensor', 'settings', 'flows', 'detections', 'intelligence', 'product'):
                return self.reply(404)
            candidate = self.server.dist / 'index.html'
        return self.reply(200, candidate.read_bytes(), mimetypes.guess_type(str(candidate))[0] or 'application/octet-stream')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise DemoError('Unexpected API redirect rejected; credential stays on loopback.')


def api_json(path: str, key: str):
    request = Request(API + path, headers={'X-API-Key': key})
    # Do not send local credentials through an ambient HTTP proxy.
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=2) as response:
        return json.load(response)


def stop_child(child):
    if child is None:
        return
    # Group was created with start_new_session; only this launch owns it.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def interface_name(value: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}', value):
        raise argparse.ArgumentTypeError('Use an explicit local interface name (1–64 characters).')
    return value


def live_ready(status: dict, interface: str) -> bool:
    if status.get('sensor_state') in ('failed', 'stopped', 'stopping', 'error'):
        raise DemoError('Live sensor stopped or failed; inspect sensor health and child diagnostics. No replay fallback was used.')
    return (status.get('sensor_state') in ('running', 'degraded')
            and status.get('sensor_mode') == 'live_passive_sensor'
            and status.get('capture_interface') == interface)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-browser', action='store_true', help='For verification: wait for a browser to open the printed URL.')
    parser.add_argument('--interface', type=interface_name, help='Observe this authorized interface passively instead of deterministic replay.')
    args = parser.parse_args()
    backend = server = thread = None
    workspace = None
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, lambda *_: stop.set())
    print('EIDOLON // SENTINEL-NET — LOCAL SIH DEMO', flush=True)
    try:
        python = ROOT / '.venv/bin/python'
        if not python.is_file():
            raise DemoError('Missing .venv/bin/python. Provision the existing offline dependencies first.')
        if not (ROOT / 'frontend/dist/index.html').is_file():
            raise DemoError('Missing frontend build. Run npm --prefix frontend run build first.')
        if not (REGISTRY / 'runtime/1.0.0/manifest.json').is_file():
            raise DemoError('Missing trusted QA registry at .local/sentinel-qa-registry. Restore the reviewed QA bundle; do not use the scientific candidate.')
        for port in (8010, 5174):
            free_port(port)
            print(f'[PASS] Port {port} available', flush=True)
        settle_ports()
        if stop.is_set():
            return 0
        key = credential(ROOT / '.sentinel-demo.local')
        print('[PASS] Stable local demo credential loaded (DEMO ONLY)', flush=True)
        workspace = Path(tempfile.mkdtemp(prefix='sentinel-one-command-'))
        env = {k: v for k, v in os.environ.items() if not k.startswith('SENTINEL_')}
        env.update(PYTHONPATH='src:.', SENTINEL_API_KEY=key, TMPDIR=str(workspace))
        command = [str(python), 'scripts/judge_demo.py', 'run', '--registry', str(REGISTRY)]
        if args.interface:
            command = [str(python), 'scripts/live_sih_sensor.py', '--interface', args.interface, '--registry', str(REGISTRY)]
            print('LIVE PASSIVE MODE — synthetic QA model; predictions are not validated threat verdicts.', flush=True)
        backend = subprocess.Popen(command, cwd=ROOT, env=env, start_new_session=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        while not stop.is_set():
            if backend.poll() is not None:
                if args.interface:
                    raise DemoError('Live sensor startup failed. Check the selected interface, existing capture permissions and trusted QA registry. No privileges were elevated and no replay fallback was used.')
                raise DemoError('Judge startup/preflight failed. Check the trusted registry checksums, offline dependencies and port availability. No model was substituted.')
            try:
                status = api_json('/api/v1/status', key)
                events = api_json('/api/v1/events?limit=1', key)
                if args.interface:
                    if live_ready(status, args.interface):
                        break
                elif status['sensor_state'] == 'replay_complete':
                    if (status['metrics']['packets_observed'] != 191
                            or status['metrics']['flows_completed'] != 72
                            or events['total'] != 72):
                        raise DemoError('Replay mismatch: expected 191 packets / 72 events. Do not change expected values.')
                    break
            except (OSError, ValueError, KeyError):
                pass
            if time.monotonic() >= deadline:
                raise DemoError('Live sensor readiness timed out after 60 seconds.' if args.interface else 'API/replay readiness timed out after 60 seconds.')
            stop.wait(.2)
        if stop.is_set():
            return 0
        if args.interface:
            print(f'[PASS] Live passive sensor {status["sensor_state"]} on {args.interface}; authenticated API reachable', flush=True)
        else:
            print('[PASS] Judge preflight; replay complete — 191 packets / 72 events\n[PASS] Authenticated API reachable', flush=True)
        server = DemoServer(ROOT / 'frontend/dist', key)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f'[PASS] Frontend reachable\nFrontend: {FRONTEND}\nAPI: {API}', flush=True)
        if not args.no_browser:
            try:
                result = subprocess.run(['open', FRONTEND], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                if result.returncode:
                    raise OSError()
                print('[PASS] Browser open request accepted', flush=True)
            except (OSError, subprocess.TimeoutExpired):
                print(f'[WARN] Browser opening failed. Open {FRONTEND} manually; services remain running.', flush=True)
        if args.interface:
            print('LIVE PASSIVE SENSOR: observing only; traffic counts depend on the interface.\nSynthetic QA model — not scientific accuracy evidence.\nSession data is temporary and removed on shutdown.\nCtrl+C stops this session.', flush=True)
        else:
            print('Waiting for automatic browser authentication. Use the newly opened tab.\nSynthetic QA runtime — pipeline demonstration only.\n72 DDoS labels are NOT scientific accuracy evidence.\nCtrl+C stops this demo.', flush=True)
        ready = False
        last_live_state = None
        while not stop.wait(.5):
            if backend.poll() is not None or not thread.is_alive():
                raise DemoError('An owned service exited; shutting down the demo.')
            if args.interface:
                try:
                    status = api_json('/api/v1/status', key)
                    if not live_ready(status, args.interface):
                        raise DemoError('Live sensor is no longer active on the selected interface.')
                    state = status['sensor_state']
                    if state != last_live_state and state == 'degraded':
                        print('[WARN] LIVE PASSIVE DEGRADED — sensor remains active; inspect operational health in the SOC.', flush=True)
                    last_live_state = state
                except (OSError, ValueError, KeyError):
                    raise DemoError('Live sensor status unavailable; shutting down owned services.') from None
            if server.consumed and not ready:
                try:
                    if api_json('/api/v1/status', key)['websocket_subscribers'] > 0:
                        print('[PASS] Browser bootstrap consumed\n[PASS] Authenticated WebSocket subscriber connected\n' + (('LIVE PASSIVE DEGRADED — SYNTHETIC QA MODEL' if last_live_state == 'degraded' else 'LIVE PASSIVE READY — SYNTHETIC QA MODEL') if args.interface else 'DEMO READY'), flush=True)
                        ready = True
                except (OSError, ValueError, KeyError):
                    pass
        return 0
    except (DemoError, OSError) as exc:
        print('[FAIL] ' + (str(exc) if isinstance(exc, DemoError) else 'Local resource operation failed; check file ownership, permissions and ports.'), flush=True)
        return 1
    finally:
        if server:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        stop_child(backend)
        if workspace:
            shutil.rmtree(workspace)
        if backend:
            try:
                settle_ports()
            except DemoError as exc:
                print('[WARN] ' + str(exc), flush=True)
            for port in (5174, 8010):
                try:
                    free_port(port)
                    print(f'[PASS] Shutdown: port {port} released', flush=True)
                except DemoError:
                    print(f'[WARN] Port {port} occupied after owned-process shutdown; no unrelated process was killed.', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
