#!/usr/bin/env bash
# Start the Threat Hunting Factory platform.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}
VENV=${VENV:-.venv}
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8000}

# Fail early and clearly rather than part way through an install.
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python was not found. Set PYTHON to your interpreter, for example PYTHON=python3.12 ./run.sh" >&2
  exit 1
fi
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required, found $("$PYTHON" -V 2>&1)." >&2
  echo "Install a newer interpreter and run PYTHON=python3.12 ./run.sh" >&2
  exit 1
fi

if [ ! -d "$VENV" ]; then
  echo "Creating the virtual environment in $VENV"
  "$PYTHON" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r requirements.txt
fi

echo "Threat Hunting Factory is starting on http://$HOST:$PORT"
echo "Sign in to the demonstration workspace with demo / analyst@demo.local / HuntFactory2026"
exec "$VENV/bin/uvicorn" app.main:app --host "$HOST" --port "$PORT" "$@"
