#!/usr/bin/env bash
# Start the Threat Hunting Factory platform.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON=${PYTHON:-python3}
VENV=${VENV:-.venv}
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8000}

if [ ! -d "$VENV" ]; then
  echo "Creating the virtual environment in $VENV"
  "$PYTHON" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r requirements.txt
fi

echo "Threat Hunting Factory is starting on http://$HOST:$PORT"
exec "$VENV/bin/uvicorn" app.main:app --host "$HOST" --port "$PORT" "$@"
