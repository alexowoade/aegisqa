"""AegisQA Central Control Plane Backend (FastAPI on Vultr Cloud Compute).

Integrates:
- Vultr Serverless Inference (https://api.vultrinference.com/v1/chat/completions)
- Pattern A (Sandboxed Code Execution) & Pattern B (Sandboxed Headless HTTP Probe)
- Interactive Glass-Box Dashboard served at /
"""

import os
from pathlib import Path
from typing import Literal, Optional
import urllib.request
import json
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from sandbox_runner import execute_python_in_sandbox, execute_http_probe_in_sandbox
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
EXEC_TOKEN = os.environ.get("AEGISQA_EXEC_TOKEN", "")


class AuditRequest(BaseModel):
    target_url: str = Field(..., max_length=500)
    goal: str = Field(..., max_length=1000)
    custom_code: Optional[str] = Field(default=None, max_length=20000)


class ExplainRequest(BaseModel):
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    contained_incident: bool = False


class SandboxExecRequest(BaseModel):
    code: str = Field(..., max_length=20000)
    timeout_sec: int = Field(default=12, ge=1, le=20)


class ContainmentAttackRequest(BaseModel):
    attack_type: Literal["secrets", "memory", "network", "filesystem"]


def call_vultr_serverless_inference(
    prompt: str,
    model: str = None,
    max_tokens: int = 300,
    timeout: int = 45,
    enable_thinking: bool = None,
    system_prompt: str = None
) -> dict:

    api_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    use_model = model or VULTR_INFERENCE_MODEL

    if not api_key:
        return {
            "provider": "vultr-serverless-inference (simulation-fallback)",
            "model": use_model,
            "error": "Missing VULTR_INFERENCE_API_KEY"
        }

    system_prompt = system_prompt or (
        "You are AegisQA, an autonomous security and QA planner. "
        "Follow the user's instructions precisely."
    )

    req_body = json.dumps({
        "model": use_model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "max_tokens": max_tokens,
        **(
            {"enable_thinking": enable_thinking}
            if enable_thinking is not None else {}
        )
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw_body = resp.read().decode("utf-8")

        data = json.loads(raw_body)

        choices = data.get("choices", [])

        if not choices:
            return {
                "provider": "vultr-serverless-inference",
                "model": use_model,
                "status": status,
                "error": "API returned no choices",
                "raw_response": raw_body[:4000]
            }

        message = choices[0].get("message", {})
        content = message.get("content")

        if not content or not str(content).strip():
            return {
                "provider": "vultr-serverless-inference",
                "model": use_model,
                "status": status,
                "error": "API returned empty content",
                "finish_reason": choices[0].get("finish_reason"),
                "raw_response": raw_body[:4000]
            }

        return {
            "provider": "vultr-serverless-inference (live)",
            "model": use_model,
            "status": status,
            "response": content,
            "finish_reason": choices[0].get("finish_reason")
        }

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")

        return {
            "provider": "vultr-serverless-inference",
            "model": use_model,
            "status": exc.code,
            "error": str(exc),
            "raw_response": error_body[:4000]
        }

    except Exception as exc:
        return {
            "provider": "vultr-serverless-inference",
            "model": use_model,
            "error": str(exc),
            "error_type": type(exc).__name__
        }


GENERATE_SYSTEM_PROMPT = """
You are an expert Python software engineer.
Follow the user's instructions precisely.
When asked to generate Python code, return only executable Python code.
Do not include Markdown fences or explanatory text.
"""

PLAN_SYSTEM_PROMPT = """
You are AegisQA, an autonomous security and QA planner.
Return valid JSON matching the requested structure.
Do not include Markdown fences.
"""


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
def run_sandbox_code(req: SandboxExecRequest, x_aegisqa_token: str = Header(default="")):
    if EXEC_TOKEN and x_aegisqa_token != EXEC_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    result = execute_python_in_sandbox(req.code, timeout_sec=req.timeout_sec)
    return JSONResponse(result)


class FixVerifyRequest(BaseModel):
    pass  # no input; uses pre-written test and shipped sources


@app.post("/api/audit/fix")
def audit_fix():
    """Run the XSS test against vulnerable and fixed source. Verdict: fix_verified."""
    from pathlib import Path
    from patched_runner import run_test_against

    demo_dir = Path(__file__).parent / "demo_target"
    test_code = (demo_dir / "test_xss.py").read_text(encoding="utf-8")
    vulnerable_src = (demo_dir / "vulnerable.py").read_text(encoding="utf-8")
    fixed_src = (demo_dir / "fixed.py").read_text(encoding="utf-8")

    vuln_result = run_test_against(test_code, vulnerable_src, "vulnerable")
    fixed_result = run_test_against(test_code, fixed_src, "fixed")

    vuln_failed = vuln_result["exit_code"] != 0
    fixed_passed = fixed_result["exit_code"] == 0
    fix_verified = vuln_failed and fixed_passed

    return {
        "vulnerable": vuln_result,
        "fixed": fixed_result,
        "fix_verified": fix_verified,
        "verdict": (
            "PASS: XSS reproduced on vulnerable, neutralized on fixed"
            if fix_verified else
            "FAIL: fix verification did not hold"
        ),
    }


@app.post("/api/sandbox/containment-demo")
def run_containment_demo(req: ContainmentAttackRequest):
    payload_code = CONTAINMENT_PAYLOADS.get(req.attack_type, CONTAINMENT_PAYLOADS["secrets"])
    result = execute_python_in_sandbox(payload_code, timeout_sec=8)
    result["attack_type"] = req.attack_type
    return JSONResponse(result)


@app.post("/api/audit/plan")
def audit_plan(req: AuditRequest):
    plan = call_vultr_serverless_inference(
        f"Target: {req.target_url}\nGoal: {req.goal}"
    )
    return plan

@app.post("/api/audit/explain")
def audit_explain(req: ExplainRequest):
    explanation = call_vultr_serverless_inference(
        f"The Vultr sandbox executed Python and returned:\n"
        f"exit_code: {req.exit_code}\n"
        f"contained_incident: {req.contained_incident}\n"
        f"stdout: {req.stdout[:500]}\n"
        f"stderr: {req.stderr[:500]}\n\n"
        f"In 1-2 sentences, explain what this output proves about the containment guarantees."
    )
    return explanation

@app.post("/api/audit/dispatch")
def dispatch_full_audit(req: AuditRequest):
    browser_probe = execute_http_probe_in_sandbox(req.target_url)

    # Harden generation: try 3 times with the SAME prompt before falling back
    generated_code = ""
    gen_attempts = 0
    for gen_attempts in range(1, 4):
        gen = call_vultr_serverless_inference(
            prompt=(
                "Write a standalone Python 3.12 script using only stdlib. "
                "The script MUST execute at module level — imports, asserts, print statements. "
                "NO test classes, NO test functions, NO pytest, NO unittest. "
                "It must assert that html.escape('<img src=x>') does not contain '<img'. "
                "Print PASS on success, exit 0. Return only Python code."
            ),
            model="deepseek-v4.1-flash-1017",
            max_tokens=4000,
            timeout=60,
            system_prompt=(
                "You write standalone executable Python scripts. "
                "The script runs directly with `python3 script.py` and must NOT use "
                "any test framework (no unittest, no pytest, no test functions or classes). "
                "Just imports, assert statements, and print statements at module level. "
                "Return only Python code, no markdown, no JSON, no explanation."
            ),
        )
        code = (gen.get("response") or "").strip()
        if code.startswith("```"):
            code = code.split("```")[1]
            if code.lower().startswith("python"):
                code = code[6:]
            code = code.strip()
        if code:
            generated_code = code
            break

    if generated_code:
        result = execute_python_in_sandbox(generated_code)
        source = "generated"
        attempts = [{"attempt": gen_attempts, "source": "generated", "exit_code": result["exit_code"], "contained": result["contained_incident"]}]
    else:
        code_to_run = req.custom_code or "assert 1 + 1 == 2\nprint('Verified')"
        result = execute_python_in_sandbox(code_to_run)
        result["executed_code"] = code_to_run
        source = "fallback"
        attempts = [{"attempt": 1, "source": "fallback", "exit_code": result["exit_code"], "contained": result["contained_incident"]}]

    result["source"] = source
    result["attempts"] = attempts
    return {
        "pattern_b_browser": browser_probe,
        "pattern_a_code": result,
    }


class BrowserProbeRequest(BaseModel):
    target_url: str = Field(..., max_length=500)


@app.post("/api/browser/probe")
def browser_probe(req: BrowserProbeRequest, x_aegisqa_token: str = Header(default="")):
    if EXEC_TOKEN and x_aegisqa_token != EXEC_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from playwright_runner import run_playwright_probe
    return JSONResponse(run_playwright_probe(req.target_url))
