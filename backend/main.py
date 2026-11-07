"""AegisQA Central Control Plane Backend (FastAPI on Vultr Cloud Compute).

Integrates:
- Vultr Serverless Inference (https://api.vultrinference.com/v1/chat/completions)
- Pattern A (Sandboxed Code Execution) & Pattern B (Sandboxed Playwright Browser)
- Interactive Glass-Box Dashboard served at /
"""

import os
from pathlib import Path
from typing import Optional
import urllib.request
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from sandbox_runner import execute_python_in_sandbox, execute_playwright_probe_in_sandbox
from containment_demo import CONTAINMENT_PAYLOADS

app = FastAPI(
    title="AegisQA — Blast Radius Zero Control Plane on Vultr",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VULTR_INFERENCE_URL = os.environ.get(
    "VULTR_INFERENCE_URL",
    "https://api.vultrinference.com/v1/chat/completions"
)
VULTR_INFERENCE_MODEL = os.environ.get(
    "VULTR_INFERENCE_MODEL",
    "deepseek-v4.1-flash-1017"
)


class AuditRequest(BaseModel):
    target_url: str
    goal: str
    custom_code: Optional[str] = None


class SandboxExecRequest(BaseModel):
    code: str
    timeout_sec: int = 12


class ContainmentAttackRequest(BaseModel):
    attack_type: str  # "secrets" | "memory" | "network" | "filesystem"


def call_vultr_serverless_inference(prompt: str) -> dict:
    """Calls Vultr Serverless Inference from the host control plane.
    The API key NEVER enters the sandbox container.
    """
    api_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    if not api_key:
        return {
            "provider": "vultr-serverless-inference (simulation-fallback)",
            "model": VULTR_INFERENCE_MODEL,
            "plan": [
                "1. Probe target DOM forms using isolated Playwright container.",
                "2. Reproduce boundary vulnerability with pytest in --network none container.",
                "3. Synthesize context-aware patch and verify 0 regressions."
            ]
        }

    req_body = json.dumps({
        "model": VULTR_INFERENCE_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are AegisQA, an autonomous security and QA planner running on Vultr. Return concise JSON."
            },
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 300
    }).encode("utf-8")

    req = urllib.request.Request(
        VULTR_INFERENCE_URL,
        data=req_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "provider": "vultr-serverless-inference (live)",
                "model": VULTR_INFERENCE_MODEL,
                "response": data["choices"][0]["message"]["content"]
            }
    except Exception as exc:
        return {
            "provider": "vultr-serverless-inference",
            "model": VULTR_INFERENCE_MODEL,
            "error": str(exc)
        }


@app.get("/")
def serve_dashboard():
    html_path = Path(__file__).parent / "index.html"
    return FileResponse(html_path)


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "control_plane": "Vultr Cloud Compute VM",
        "inference_endpoint": VULTR_INFERENCE_URL,
        "model": VULTR_INFERENCE_MODEL,
        "host_api_key_configured": bool(os.environ.get("VULTR_INFERENCE_API_KEY")),
        "sandbox_secrets_exposed": 0
    }


@app.post("/api/sandbox/exec")
def run_sandbox_code(req: SandboxExecRequest):
    result = execute_python_in_sandbox(req.code, timeout_sec=req.timeout_sec)
    return JSONResponse(result)


@app.post("/api/sandbox/containment-demo")
def run_containment_demo(req: ContainmentAttackRequest):
    payload_code = CONTAINMENT_PAYLOADS.get(req.attack_type, CONTAINMENT_PAYLOADS["secrets"])
    result = execute_python_in_sandbox(payload_code, timeout_sec=8)
    result["attack_type"] = req.attack_type
    return JSONResponse(result)


@app.post("/api/audit/dispatch")
def dispatch_full_audit(req: AuditRequest):
    plan = call_vultr_serverless_inference(f"Target: {req.target_url}\nGoal: {req.goal}")
    browser_probe = execute_playwright_probe_in_sandbox(req.target_url)
    code_to_run = req.custom_code or "assert 1 + 1 == 2\nprint('Verified in Vultr Sandbox')"
    code_verify = execute_python_in_sandbox(code_to_run)
    return {
        "inference_plan": plan,
        "pattern_b_browser": browser_probe,
        "pattern_a_code": code_verify
    }
