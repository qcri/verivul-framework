#!/usr/bin/env bash
# setup.sh — pull all required Docker images and build the ESBMC image.
# Run once before starting the pipeline.
#
# Usage:
#   bash scripts/setup.sh          # pull + build everything
#   bash scripts/setup.sh --no-esbmc   # skip ESBMC build (already built)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_ESBMC=true

for arg in "$@"; do
  [[ "$arg" == "--no-esbmc" ]] && BUILD_ESBMC=false
done

echo "=== VeriVul Docker Setup ==="
echo

# ---------------------------------------------------------------------------
# 1. Compiler images
# Language → image mapping:
#   C / C++    → gcc:latest
#   Java*      → eclipse-temurin:21  (*seeds only; generation targets Kotlin)
#   Python     → python:3.12-slim
#   Kotlin     → esbmc:8.4        (kotlinc is inside the ESBMC image)
#   Solidity   → esbmc:8.4        (solc static binary is inside the ESBMC image)
# ---------------------------------------------------------------------------
echo "--- Pulling compiler images ---"

IMAGES=(
  "gcc:latest"
  "eclipse-temurin:21"
  "python:3.12-slim"
)

for img in "${IMAGES[@]}"; do
  echo "  Pulling $img ..."
  docker pull "$img"
done

echo

# ---------------------------------------------------------------------------
# 2. Infrastructure images (started via docker-compose.yml)
# ---------------------------------------------------------------------------
echo "--- Pulling RabbitMQ / PostgreSQL / pgbouncer ---"
docker pull rabbitmq:3-management
docker pull postgres:16
docker pull pgbouncer/pgbouncer:latest
echo

# ---------------------------------------------------------------------------
# 3. ESBMC (built locally from Dockerfile)
# ---------------------------------------------------------------------------
if $BUILD_ESBMC; then
  echo "--- Building ESBMC image (this may take several minutes) ---"
  echo "    Includes: esbmc 8.4, gcc/g++, java 17, kotlinc, python3,"
  echo "              ast2json + mypy (Python frontend), solc, soot.jar"
  docker build -t esbmc:8.4 -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR"
  echo "  ESBMC image built: esbmc:8.4"
else
  echo "--- Skipping ESBMC build (--no-esbmc) ---"
fi

echo

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
echo "=== Setup complete. Images available: ==="
docker images --format "  {{.Repository}}:{{.Tag}}\t{{.Size}}" \
  | grep -E "gcc|eclipse-temurin|python|esbmc|rabbitmq" \
  | sort
echo
echo "Next steps:"
echo "  1. Start RabbitMQ, PostgreSQL and pgbouncer (docker-compose.yml is the single source of truth):"
echo "       docker compose up -d"
echo "     Host ports: PostgreSQL 54329, pgbouncer 54330, RabbitMQ 54331 (UI 54332)."
echo "  2. Point the app at them (e.g. in .env):"
echo "       export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=54330"
echo "       export RABBITMQ_HOST=127.0.0.1 RABBITMQ_PORT=54331"
echo "     Use the same POSTGRES_*/RABBITMQ_* credentials when running compose and the app."
echo "  3. Run the pipeline:"
echo "       conda run -n verivul python main.py data/seeds/seeds.jsonl"
