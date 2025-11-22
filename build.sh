#!/usr/bin/env bash

set -Eeuo pipefail

# MP4Recover Build & Start Script (Linux/macOS)

echo "=========================================="
echo "     MP4Recover Build & Start Script"
echo "=========================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker is not running or not installed."
    echo "Please start Docker Desktop or the Docker daemon and try again."
    exit 1
fi

echo "[INFO] Docker is running."

# Helper function for docker compose
compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "[ERROR] docker compose (or docker-compose) is not available" >&2
    exit 1
  fi
}

MP4_REPAIR_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# Stop and remove existing containers
echo ""
echo "[1/3] Stopping and cleaning up old containers..."
(
  cd "${MP4_REPAIR_DIR}"
  compose down -v --remove-orphans || echo "[WARNING] Failed to clean up some resources. Continuing..."
)

# Build and start containers
echo ""
echo "[2/3] Building and starting containers..."
(
  cd "${MP4_REPAIR_DIR}"
  if ! compose up -d --build --force-recreate --remove-orphans; then
    echo "[ERROR] Failed to build or start containers."
    exit 1
  fi
)

# Show status
echo ""
echo "[3/3] Checking container status..."
(
  cd "${MP4_REPAIR_DIR}"
  compose ps
)

echo ""
echo "=========================================="
echo "     SUCCESS! System is up and running"
echo "=========================================="
echo "Orchestrator: http://localhost:8000"
echo "Web Interface: http://localhost:8080"
echo ""
