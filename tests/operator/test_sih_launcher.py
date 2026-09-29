"""Boundary tests for post-freeze operator tooling only."""
import http.client
import json
import os
from pathlib import Path
import stat
import threading

import pytest

from scripts.run_sih_demo import BOOT_HTML, BOOTSTRAP, COOKIE, FRONTEND, DemoError, DemoServer, credential


def test_credential_stable_owner_only_and_link_rejected(tmp_path):
    path = tmp_path / 'credential'
    key = credential(path)
    assert len(key) >= 32 and credential(path) == key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(OSError):
        credential(link)
    path.write_text('SENTINEL_API_KEY=short\n')
    with pytest.raises(DemoError):
        credential(path)


def test_bootstrap_one_use_host_origin_cookie_and_no_static_key(tmp_path):
    key = 'x' * 48
    (tmp_path / 'index.html').write_text('<html>normal unchanged app</html>')
    server = DemoServer(tmp_path, key, ('127.0.0.1', 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def request(method, path, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        connection.request(method, path, headers={'Host':'127.0.0.1:5174', **(headers or {})})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result
    try:
        status, headers, html = request('GET', '/')
        assert status == 200 and html == BOOT_HTML and key.encode() not in html
        assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
        cookie = headers['Set-Cookie'].split(';')[0]
        good = {'Cookie':cookie, 'Origin':FRONTEND, 'Sec-Fetch-Site':'same-origin'}
        assert request('POST', BOOTSTRAP)[0] == 403
        assert request('POST', BOOTSTRAP, {**good, 'Origin':'http://evil.test'})[0] == 403
        assert request('POST', BOOTSTRAP, {**good, 'Host':'evil.test'})[0] == 403
        assert request('POST', BOOTSTRAP, {**good, 'Cookie':COOKIE+'=wrong'})[0] == 403
        assert request('GET', '/%2e%2e/outside')[0] == 404
        status, headers, body = request('POST', BOOTSTRAP, good)
        assert status == 200 and json.loads(body) == {'key':key}
        assert headers['Cache-Control'] == 'no-store'
        assert 'Access-Control-Allow-Origin' not in headers
        assert server.key == ''
        assert request('POST', BOOTSTRAP, good)[0] == 410
        assert request('GET', BOOTSTRAP)[0] == 404
        assert request('GET', '/')[2] == b'<html>normal unchanged app</html>'
        assert all(key.encode() not in p.read_bytes() for p in tmp_path.iterdir())
    finally:
        server.shutdown();server.server_close();thread.join()


def test_nonloopback_bind_rejected(tmp_path):
    with pytest.raises(DemoError):
        DemoServer(tmp_path, 'x'*48, ('0.0.0.0',0))


@pytest.mark.parametrize('missing,expected', [
    ('python', 'Missing .venv'), ('build', 'Missing frontend build'),
    ('registry', 'Missing trusted QA registry'),
])
def test_missing_prerequisites_fail_before_start(tmp_path, monkeypatch, capsys, missing, expected):
    from scripts import run_sih_demo as demo
    python = tmp_path / '.venv/bin/python'
    build = tmp_path / 'frontend/dist/index.html'
    registry = tmp_path / 'registry'
    for path in (python, build, registry/'runtime/1.0.0/manifest.json'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture')
    {'python':python, 'build':build, 'registry':registry/'runtime/1.0.0/manifest.json'}[missing].unlink()
    monkeypatch.setattr(demo, 'ROOT', tmp_path)
    monkeypatch.setattr(demo, 'REGISTRY', registry)
    monkeypatch.setattr(demo.sys, 'argv', ['run_sih_demo'])
    monkeypatch.setattr(demo.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(demo.subprocess, 'Popen', lambda *args, **kwargs: pytest.fail('must not spawn'))
    assert demo.main() == 1
    assert expected in capsys.readouterr().out
    assert not (tmp_path/'.sentinel-demo.local').exists()


def test_redirect_is_not_allowed_to_forward_key():
    from scripts.run_sih_demo import NoRedirect
    with pytest.raises(DemoError):
        NoRedirect().redirect_request(None, None, 302, 'redirect', {}, 'https://example.com')


def test_fifo_credential_rejected_without_blocking(tmp_path):
    fifo = tmp_path/'credential'
    os.mkfifo(fifo)
    with pytest.raises(DemoError):
        credential(fifo)


@pytest.mark.parametrize('value', ['', ' en0', '../en0', 'en0;whoami', 'en0\n', 'x' * 65])
def test_live_interface_rejects_malformed_names(value):
    import argparse
    from scripts.run_sih_demo import interface_name
    with pytest.raises(argparse.ArgumentTypeError):
        interface_name(value)


def test_live_readiness_requires_selected_running_source():
    from scripts.run_sih_demo import interface_name, live_ready
    status = dict(sensor_state='running', sensor_mode='live_passive_sensor', capture_interface='en0')
    assert interface_name('en0') == 'en0'
    assert live_ready(status, 'en0')
    assert not live_ready(status, 'lo0')
    assert not live_ready({**status, 'sensor_mode': 'recorded_traffic_replay'}, 'en0')
    assert not live_ready({**status, 'sensor_state': 'starting'}, 'en0')
    assert live_ready({**status, 'sensor_state': 'degraded'}, 'en0')
    for state in ('failed', 'stopped', 'stopping', 'error'):
        with pytest.raises(DemoError):
            live_ready({**status, 'sensor_state': state}, 'en0')


def test_live_failed_integrity_never_validates_capture(monkeypatch, tmp_path):
    from scripts import live_sih_sensor
    from sentinel_net.sensor.capture import PassiveCaptureSource
    monkeypatch.setattr(live_sih_sensor, 'preflight', lambda _: False)
    def unexpected(_):
        raise AssertionError('Capture reached after failed integrity')
    monkeypatch.setattr(PassiveCaptureSource, 'validate_interface', unexpected)
    assert live_sih_sensor.run('en0', tmp_path) == 1


def test_live_missing_interface_never_starts_sensor(monkeypatch, tmp_path):
    from scripts import live_sih_sensor
    from sentinel_net.sensor.capture import PassiveCaptureSource
    monkeypatch.setattr(live_sih_sensor, 'preflight', lambda _: True)
    def reject(_):
        raise ValueError('unavailable')
    monkeypatch.setattr(PassiveCaptureSource, 'validate_interface', reject)
    assert live_sih_sensor.run('absent0', tmp_path) == 1
