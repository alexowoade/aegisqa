# AegisQA — Blast Radius Zero Control Plane on Vultr

A web-based QA and security verification agent for Vultr Challenge 1 (Blast Radius Zero). A Vultr VM orchestrator plans an audit via Vultr Serverless Inference, dispatches both sandboxed Python verification (Pattern A) and isolated Playwright browser probes (Pattern B), verifies fixes across vulnerable and patched targets, and mints verifiable SHA-256 execution receipts.

Live demo: http://64.177.42.65:8000/
Health: http://64.177.42.65:8000/api/health

## What it does

- **Plan & Explain (`deepseek-v4.1-flash-1017`):** Vultr Serverless Inference plans the audit (`/api/audit/plan`) and explains real sandbox outputs (`/api/audit/explain`). The API key remains strictly on the host control plane and never enters any container.
- **Pattern A — AI Test Generation & Sandboxed Code Execution:**
  - The model inspects `demo_target/vulnerable.py`, writes a standalone Python test importing `process_promo` from `/workspace/app.py`, and executes it inside `aegisqa-sandbox:latest` (`--network none --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --security-opt no-new-privileges:true --cap-drop ALL`, UID `10001:10001`).
  - **Fix Verification (`/api/audit/fix`) & AI Auto-Patch (`/api/audit/autopatch`):** Runs the verification suite against both `vulnerable.py` (reproducing the XSS bug, exit `1`) and `fixed.py` / AI-patched source (confirming XSS neutralization, exit `0`) with separate SHA-256 container receipts.
- **Pattern B — Dual Containment & Real Playwright Browser Lab:**
  - **Air-Gap Containment Probe:** Inside the `--network none` code sandbox, an HTTP probe attempts to reach the target via `urllib` and proves the container is air-gapped (`UNREACHABLE` / `Network is unreachable`).
  - **Browser Lab (`/api/browser/probe`):** Runs headless Chromium inside `aegisqa-playwright:latest` on an isolated Docker network (`aegisqa-browser-net`) where only the FinFlow Flask target (`aegisqa-browser-target:5000/checkout`) is reachable. Playwright fills `#promo` with an XSS payload, submits the form, captures a full-page screenshot + DOM snippet, passes the screenshot to Vultr Serverless Inference for vision verification, and pauses at a Human-in-the-Loop approval gate before minting a SHA-256 receipt.
- **Containment Moment Lab (`/api/sandbox/containment-demo`):** Four live adversarial payloads (`secrets`, `memory`, `network`, `filesystem`) trapped inside the sandbox with zero host impact and SHA-256 receipts.

## Architecture

- **Control Plane:** Vultr Cloud Compute VM (Debian 13, Atlanta, `64.177.42.65:8000`), FastAPI on the host.
- **Inference:** Vultr Serverless Inference (`https://api.vultrinference.com/v1`, model `deepseek-v4.1-flash-1017`).
- **Sandboxes:**
  - `aegisqa-sandbox:latest` (`sandbox/Dockerfile.sandbox`, `python:3.12-slim`, UID `10001:10001`, `--network none`).
  - `aegisqa-playwright:latest` (`sandbox/Dockerfile.playwright`, Chromium + Playwright, UID `10001:10001`, `--network aegisqa-browser-net`).
  - `aegisqa-browser-target` (`docker-compose.browser.yml`, Flask vulnerable checkout target on `aegisqa-browser-net`).

## Run it

```bash
apt-get update -y
apt-get install -y docker.io docker-compose-plugin python3-fastapi python3-uvicorn python3-pydantic
docker build -t aegisqa-sandbox:latest -f sandbox/Dockerfile.sandbox sandbox/
docker build -t aegisqa-playwright:latest -f sandbox/Dockerfile.playwright sandbox/
docker compose -f docker-compose.browser.yml up -d
```

Set the inference key in the terminal only and start the control plane:

```bash
read -s VULTR_INFERENCE_API_KEY
export VULTR_INFERENCE_API_KEY
export AEGISQA_EXEC_TOKEN="aegisqa-demo-2026"
cd backend
nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > /root/uvicorn.log 2>&1 &
curl -s http://localhost:8000/api/health
```

Require `status: online` and `host_api_key_configured: true` before claiming the demo works. Open port 8000 in the host firewall (`ufw allow 8000/tcp`) if the public URL is unreachable.

## API

- `GET /` — 5-tab interactive glass-box dashboard
- `GET /api/health` — status, model, host_api_key_configured
- `POST /api/audit/plan` — Vultr Serverless Inference threat plan
- `POST /api/audit/dispatch` — AI test generation + Pattern A sandbox execution (plus air-gap probe)
- `POST /api/audit/fix` — Vulnerable vs. Fixed container verification
- `POST /api/audit/autopatch` — AI patch synthesis + sandbox test verification
- `POST /api/audit/explain` — Vultr Serverless Inference explanation of real container output
- `POST /api/browser/probe` — Isolated Playwright Chromium probe + screenshot vision verification
- `POST /api/sandbox/exec` — Custom Python execution in `--network none` sandbox
- `POST /api/sandbox/containment-demo` — `{"attack_type": "secrets|memory|network|filesystem"}`

Note: `/api/sandbox/exec` and `/api/browser/probe` require the `X-AegisQA-Token` header matching `AEGISQA_EXEC_TOKEN` when it is set on the host. The token is a demo-grade gate (it is also sent by the frontend), not strong authentication — do not present it as such, and do not expose the demo URL beyond the submission.

## Scope

MVP: one own test fixture scenario (FinFlow checkout), one audit → patch → re-verify flow, plus the containment lab and the autonomous break-it / fix-it loop. Not a general QA tool for any site.

Built for the Vultr Agent Rush Hackathon (LabLab x Vultr), Challenge 1.
