#!/usr/bin/env bash
# AegisQA deploy — reflects what was actually done on the Vultr VM.
# Debian 13, host route (not docker-compose): FastAPI runs on the host,
# Docker is only used for the sandbox image.
set -euo pipefail
apt-get update -y
apt-get install -y docker.io python3-fastapi python3-uvicorn python3-pydantic
systemctl enable --now docker
docker build -t aegisqa-sandbox:latest -f sandbox/Dockerfile.sandbox sandbox/
# Set the key in this terminal first, then export it:
#   read -s VULTR_INFERENCE_API_KEY
#   export VULTR_INFERENCE_API_KEY
# Then start the control plane from backend/:
#   cd backend
#   nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /root/uvicorn.log 2>&1 &
#   curl -s http://localhost:8000/api/health
# Open port 8000 if the public URL is unreachable:
#   ufw allow 8000/tcp
# Public URL is http://<your-public-IPv4>:8000/ — do NOT use hostname -I,
# that prints the internal address.
echo "Deploy steps done. Start uvicorn from backend/ as shown above."
