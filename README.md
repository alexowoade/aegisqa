# AegisQA — Blast Radius Zero Control Plane on Vultr

A web-based QA agent for Vultr Challenge 1 (Blast Radius Zero). A Vultr VM
orchestrator plans an audit, dispatches work to an isolated Docker sandbox,
and returns a verifiable receipt with a SHA-256 hash.

Live demo: http://64.177.42.65:8000/
Health: http://64.177.42.65:8000/api/health

## What it does

- Plan: Vultr Serverless Inference plans the audit.
  Model: `deepseek-v4.1-flash-1017`, live-proven via chat completion.
  Provider in a live audit dispatch: `vultr-serverless-inference (live)`.
- Pattern A: sandboxed code execution in Docker.
  `docker run --rm --network none --memory 256m --cpus 0.5
  --pids-limit 64 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m
  --security-opt no-new-privileges:true --cap-drop ALL`
  Zero host secrets are mounted in the sandbox.
- Pattern B / containment test: sandboxed headless HTTP probe inside an
  isolated container. This is NOT Playwright/Chromium and NOT browser
  automation. The probe makes a real HTTP request with urllib; the
  `--network none` policy blocks it, so it returns `UNREACHABLE` with
  `Network is unreachable` — proof the sandbox is air-gapped from the
  target. Pattern A (sandboxed code execution) is fully implemented.
  Pattern B (browser automation) is out of scope for this MVP;
  Challenge 1 permits one or both.
- Containment Moment Lab: four rogue payloads, all contained on the live VM
  on 2026-11-07, each with a SHA-256 receipt:
  - secrets: /etc/shadow blocked, Permission denied, contained true
  - memory: 1 GB allocation caught at the 256 MB cgroup ceiling, contained true
  - network: outbound socket blocked, Network is unreachable, contained true
  - filesystem: read-only rootfs blocked deletion, Read-only file system, contained true
- Receipt: SHA-256 of container | exit code | stdout | stderr | duration.
  The dashboard's Containment Lab calls the real backend
  `POST /api/sandbox/containment-demo` and shows the real container ID,
  exit code, contained flag, duration, and receipt.

## Architecture

- Vultr Cloud Compute VM, 1 vCPU / 1 GB RAM, Debian 13, Atlanta.
  Public IPv4: 64.177.42.65. Control plane: FastAPI on the host, port 8000.
- Vultr Serverless Inference (OpenAI-compatible),
  https://api.vultrinference.com/v1, model deepseek-v4.1-flash-1017.
  The inference API key never enters a sandbox container.
- Docker sandbox image `aegisqa-sandbox:latest`, built from
  `sandbox/Dockerfile.sandbox` (python:3.12-slim, unprivileged user 10001).
- No gVisor / runsc is used. No Playwright is used.

## Run it

On the VM, in this folder:

```
apt-get install -y docker.io python3-fastapi python3-uvicorn python3-pydantic
docker build -t aegisqa-sandbox:latest -f sandbox/Dockerfile.sandbox sandbox/
```

Set the inference key in the terminal only (never in chat, never in a file):

```
read -s VULTR_INFERENCE_API_KEY
export VULTR_INFERENCE_API_KEY
```

Then start the control plane from `backend/`:

```
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /root/uvicorn.log 2>&1 &
curl -s http://localhost:8000/api/health
```

Require `status: online` and `host_api_key_configured: true` before
claiming the demo works. Open port 8000 in the host firewall
(`ufw allow 8000/tcp`) if the public URL is unreachable.

## API

- `GET /` — dashboard
- `GET /api/health` — status, model, host_api_key_configured
- `POST /api/audit/dispatch` — `{"target_url": "...", "goal": "..."}`
- `POST /api/sandbox/exec` — `{"code": "...", "timeout_sec": 12}`
- `POST /api/sandbox/containment-demo` — `{"attack_type": "secrets|memory|network|filesystem"}`

Note: `/api/sandbox/exec` runs arbitrary code in the sandbox. It is open
with no auth in this prototype — do not expose it beyond the demo, and
gate it before any wide sharing.

## Scope

MVP: one own test fixture scenario (finflow), one audit → patch → re-verify
flow, plus the containment lab. Not a general QA tool for any site.

Built for the Vultr Agent Rush Hackathon (LabLab x Vultr), Challenge 1.
