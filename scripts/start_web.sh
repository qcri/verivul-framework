#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/src/web/frontend"

echo "==> Installing frontend dependencies..."
cd "$FRONTEND"
npm install --silent

echo "==> Building React app..."
npm run build

echo "==> Starting API server (http://0.0.0.0:${VERIVUL_WEB_PORT:-54333})..."
cd "$ROOT"
exec python src/web/main.py
