#!/usr/bin/env bash
set -euo pipefail

echo "=================================================================="
echo "  AegisQA — Blast Radius Zero Provisioner for Vultr Cloud Compute "
echo "=================================================================="

if ! command -v docker &> /dev/null; then
  echo "[1/3] Installing Docker Engine on Vultr VM..."
  apt-get update -y && apt-get install -y docker.io docker-compose-v2
  systemctl enable --now docker
fi

echo "[2/3] Building unprivileged isolated sandbox image (aegisqa-sandbox:latest)..."
docker build -t aegisqa-sandbox:latest -f sandbox/Dockerfile.sandbox sandbox/

echo "[3/3] Starting AegisQA Control Plane on port 8000..."
docker compose up -d

PUBLIC_IP=$(hostname -I | awk '{print $1}')
echo "=================================================================="
echo "✅ AegisQA is live at: http://${PUBLIC_IP}:8000"
echo "🛡️ Containment guarantees active: --network none, 256MB RAM cap, 0 secrets"
echo "=================================================================="
