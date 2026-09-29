"""Operator adapter for the existing passive sensor; no auth or capture implementation."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from scripts.judge_demo import MODEL, preflight


def run(interface: str, registry: Path) -> int:
    # Verify the exact reviewed QA artifacts before the sensor can deserialize them.
    if not preflight(registry):
        return 1
    from sentinel_net.sensor.capture import PassiveCaptureSource
    try:
        PassiveCaptureSource.validate_interface(interface)
    except Exception:
        print('FAIL Capture interface unavailable; no capture started.', flush=True)
        return 1
    registry = registry.resolve()
    workspace = Path(tempfile.mkdtemp(prefix='sentinel-live-'))
    # Parent owns TMPDIR and cleanup. No project .env or ambient detector overrides.
    for key in list(os.environ):
        if key.startswith('SENTINEL_') and key != 'SENTINEL_API_KEY':
            del os.environ[key]
    os.environ.update(
        SENTINEL_DATABASE_PATH=str(workspace / 'events.db'),
        SENTINEL_MODEL_REGISTRY=str(registry),
        SENTINEL_CORS_ORIGINS='http://127.0.0.1:5174',
        SENTINEL_ENV='production',
    )
    os.chdir(workspace)
    from sentinel_net.cli import main
    sys.argv = ['sentinel-net', 'sensor', '--interface', interface,
                '--model', MODEL, '--host', '127.0.0.1', '--port', '8010']
    main()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--registry', required=True, type=Path)
    args = parser.parse_args()
    return run(args.interface, args.registry)


if __name__ == '__main__':
    raise SystemExit(main())
