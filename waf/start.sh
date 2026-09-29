#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

export PYTHONPATH="$DIR:$PYTHONPATH"

if [ -f "$DIR/venv/bin/python3" ]; then
    exec "$DIR/venv/bin/python3" main.py "$@"
elif [ -f "$DIR/.venv/bin/python3" ]; then
    exec "$DIR/.venv/bin/python3" main.py "$@"
else
    exec python3 main.py "$@"
fi
