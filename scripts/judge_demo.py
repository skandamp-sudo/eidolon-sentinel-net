"""Fail-closed, loopback-only demo launcher. No training, publication or cleanup."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / 'data/judge-demo/judge-demo.pcap'
PCAP_SHA = 'ef1e195076dd9610ccd160eed288b1e30c83142df34e58463c32bbc9aea7deb7'
MODEL = 'runtime/1.0.0'
MODEL_CHECKSUMS_SHA = '1c2d606d9ac707e0bc2c2570bf520a8a39fb2ac217a9c48fc6ce59e296b52ce0'
MODEL_SHA = '23457a635f7c6acb1b5e017ef1b59ecf9aae6db654102a7a36f6118bed0fd06f'


def verify_assets(registry):
    if hashlib.sha256(PCAP.read_bytes()).hexdigest() != PCAP_SHA:
        raise ValueError('PCAP checksum mismatch')
    manifest = Path(registry) / MODEL / 'manifest.json'
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != MODEL_SHA:
        raise ValueError('Runtime manifest is not the reviewed demo bundle')
    ledger = Path(registry) / MODEL / 'checksums.json'
    if hashlib.sha256(ledger.read_bytes()).hexdigest() != MODEL_CHECKSUMS_SHA:
        raise ValueError('Runtime checksum ledger is not the reviewed bundle')
    from sentinel_net.sensor.runtime_model import load_runtime_model
    model = load_runtime_model(MODEL, registry=Path(registry))
    baseline = json.loads((ROOT/'docs/sci-corr-2-scientific-integrity.json').read_text())
    if any(hashlib.sha256((ROOT/p).read_bytes()).hexdigest() != h for p,h in baseline['sha256'].items()):
        raise ValueError('Scientific baseline mismatch')
    return model


def port_available(port):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))


def preflight(registry, port=8010):
    checks = [
        ('Python >=3.12', lambda: sys.version_info >= (3,12)),
        ('Dependencies installed', lambda: all(importlib.util.find_spec(m) for m in ('scapy','uvicorn','fastapi','aiosqlite','xgboost'))),
        ('Frontend production build', lambda: (ROOT/'frontend/dist/index.html').is_file()),
        ('Private API key configured', lambda: len(os.environ.get('SENTINEL_API_KEY','')) >= 16 and os.environ.get('SENTINEL_API_KEY') != 'changeme-dev'),
        ('Dedicated fresh database location available', lambda: Path(tempfile.gettempdir()).is_dir() and os.access(tempfile.gettempdir(), os.W_OK)),
        ('Pinned PCAP, approved model, checksums and schema; 23 protected files', lambda: bool(verify_assets(registry))),
        ('Loopback API port available', lambda: port_available(port) is None),
        ('Loopback frontend port 5174 available', lambda: port_available(5174) is None),
    ]
    ok = True
    for label, check in checks:
        try:
            passed = bool(check())
        except Exception:
            passed = False  # Never print exceptions containing paths or secrets.
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        ok = ok and passed
    print('DEMO READY' if ok else 'DEMO NOT READY', flush=True)
    return ok


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['preflight','run'])
    parser.add_argument('--registry',type=Path,required=True)
    parser.add_argument('--port',type=int,default=8010,choices=range(1024,65536),metavar='PORT')
    args=parser.parse_args()
    if not preflight(args.registry,args.port):
        return 1
    if args.action == 'preflight':
        return 0
    workspace=Path(tempfile.mkdtemp(prefix='sentinel-judge-'))
    # Explicit clean defaults prevent ambient detector or retention overrides.
    from sentinel_net.cli import main as cli
    for key in list(os.environ):
        if key.startswith('SENTINEL_') and key != 'SENTINEL_API_KEY':
            del os.environ[key]
    os.environ.update(SENTINEL_DATABASE_PATH=str(workspace/'events.db'),
                      SENTINEL_MODEL_REGISTRY=str(args.registry.resolve()),
                      SENTINEL_CORS_ORIGINS='http://127.0.0.1:5174',
                      SENTINEL_ENV='production')
    # CLI reads .env from cwd. Fresh cwd prevents local overrides; absolute assets.
    (workspace/'judge-demo.pcap').write_bytes(PCAP.read_bytes())
    os.chdir(workspace)
    print('Synthetic QA runtime only; NOT the evaluated scientific candidate.', flush=True)
    print(f'API: http://127.0.0.1:{args.port} — fresh isolated demo database.', flush=True)
    sys.argv=['sentinel-net','replay','--pcap','judge-demo.pcap','--model',MODEL,'--host','127.0.0.1','--port',str(args.port)]
    cli()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
