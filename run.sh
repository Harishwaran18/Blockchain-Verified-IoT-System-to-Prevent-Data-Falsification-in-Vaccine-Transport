#!/usr/bin/env bash
# Start VChain with the embedded broker, simulated fleet and dashboard.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="${PYTHONPATH:-}:$PWD"
exec python -m vchain "$@"
