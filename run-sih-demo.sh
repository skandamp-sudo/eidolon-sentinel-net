#!/bin/sh
exec "$(dirname "$0")/.venv/bin/python" "$(dirname "$0")/scripts/run_sih_demo.py" "$@"
