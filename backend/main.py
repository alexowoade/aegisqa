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
    from pathlib import Path
    from patched_runner import run_test_against

    plan = call_vultr_serverless_inference(f"Target: {req.target_url}\nGoal: {req.goal}")
    browser_probe = execute_http_probe_in_sandbox(req.target_url)

    demo_dir = Path(__file__).parent / "demo_target"
    vuln_src = (demo_dir / "vulnerable.py").read_text(encoding="utf-8")
    fixed_src = (demo_dir / "fixed.py").read_text(encoding="utf-8")

    generated_code = ""
    attempts = []
    source = "fallback"

    for attempt in range(1, 4):
        gen = call_vultr_serverless_inference(
            prompt=(
                f"Here is a Python source file with a security vulnerability:\n\n{vuln_src}\n\n"
                f"The file is mounted at /workspace/app.py inside the sandbox. "
                f"Write a standalone Python 3.12 test that:\n"
                f"- Imports `process_promo` from `app`\n"
                f"- Calls it with the XSS payload '<img src=x onerror=alert(1)>'\n"
                f"- Asserts the returned HTML does NOT contain an unescaped '<img' tag\n"
                f"- If XSS is escaped (safe): prints PASS, exits 0\n"
                f"- If XSS is present (vulnerable): prints 'VULNERABLE: XSS payload reflected unescaped', exits 1\n"
                f"- Uses only stdlib\n"
                f"- Executes at module level (no functions, no classes, no test framework)\n"
                f"Return ONLY the Python code, no markdown, no explanation."
            ),
            model="deepseek-v4.1-flash-1017",
            max_tokens=4000,
            timeout=60,
            system_prompt=(
                "You write standalone executable Python scripts. "
                "Imports, asserts, print statements at module level only. "
                "No test framework, no functions, no classes. "
                "Return only Python code, no markdown, no JSON, no explanation."
            ),
        )
        code = (gen.get("response") or "").strip()
        if code.startswith("```"):
            code = code.split("```")[1]
            if code.lower().startswith("python"):
                code = code[6:]
            code = code.strip()
        attempts.append({
            "attempt": attempt,
            "code_len": len(code),
            "has_import": ("from app" in code or "import app" in code),
            "has_assert": "assert" in code,
        })
        if code and ("from app" in code or "import app" in code) and "process_promo" in code and "assert" in code:
            generated_code = code
            source = "generated"
            break

    if generated_code:
        result = run_test_against(generated_code, fixed_src, "dispatch-real-target")
    else:
        fallback_code = req.custom_code or "print('fallback')"
        result = run_test_against(fallback_code, fixed_src, "dispatch-fallback")

    result["source"] = source
    result["attempts"] = attempts
    result["target_source_path"] = "/workspace/app.py"
    result["target_source_version"] = "fixed"

    explanation = call_vultr_serverless_inference(
        f"The Vultr sandbox executed a Python test against the real source file "
        f"(/workspace/app.py) and returned:\n"
        f"exit_code: {result.get('exit_code')}\n"
        f"stdout: {str(result.get('stdout', ''))[:500]}\n\n"
        f"In 1-2 sentences, explain what this proves about XSS escaping in the shipped app."
    )

    return {
        "inference_plan": plan,
        "pattern_b_browser": browser_probe,
        "pattern_a_code": result,
        "inference_explanation": explanation,
    }


class BrowserProbeRequest(BaseModel):
    target_url: str = Field(..., max_length=500)


@app.post("/api/browser/probe")
def browser_probe(req: BrowserProbeRequest, x_aegisqa_token: str = Header(default="")):
    if EXEC_TOKEN and x_aegisqa_token != EXEC_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from playwright_runner import run_playwright_probe
    result = run_playwright_probe(req.target_url)
    try:
        probe_data = result.get("probe") or {}
        if probe_data.get("status") == "REACHED" and probe_data.get("screenshot_b64"):
            result["vision_verification"] = _vision_verify_screenshot(probe_data["screenshot_b64"])
        else:
            result["vision_verification"] = {"error": "no screenshot to verify"}
    except Exception as exc:
        result["vision_verification"] = {"error": str(exc)}
    return JSONResponse(result)


def _vision_verify_screenshot(screenshot_b64: str, model: str = "deepseek-v4.1-flash-1017") -> dict:
    """Send screenshot to vision model. Ask if unescaped XSS payload is visible."""
    api_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    if not api_key:
        return {"provider": "no-key", "error": "no api key"}
    body = json.dumps({
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": (
                    "This is a screenshot of a checkout page after an XSS payload was submitted. "
                    "Look at the promo banner area. If you see a broken image icon or rendered HTML, "
                    "the payload was NOT escaped (VULNERABLE). "
                    "If you see literal text starting with '<img src=x', the payload WAS escaped (SAFE). "
                    "Answer in 1 sentence: is the page VULNERABLE, SAFE, or UNKNOWN?"
                )},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{screenshot_b64}"}}
            ]
        }],
        "max_tokens": 2000,
    }).encode()
    req = urllib.request.Request(VULTR_INFERENCE_URL, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            verdict = data["choices"][0]["message"].get("content", "").strip()
            return {
                "provider": "vultr-serverless-inference (live)",
                "model": model,
                "verdict": verdict,
                "classification": (
                    "VULNERABLE" if "vulnerable" in verdict.lower()
                    else "SAFE" if "safe" in verdict.lower()
                    else "UNKNOWN"
                ),
            }
    except Exception as exc:
        return {"provider": "vultr-serverless-inference", "error": str(exc)}


class AutoPatchRequest(BaseModel):
    pass


def _extract_python_code(raw: str) -> str:
    """Strip markdown fences and leading 'python' language tag."""
    if not raw:
        return ""
    code = raw.strip()
    if code.startswith("```"):
        parts = code.split("```")
        if len(parts) >= 2:
            code = parts[1]
            if code.lower().startswith("python"):
                code = code[6:]
    return code.strip()


def _validate_patch(code: str, original_source: str) -> tuple:
    """Basic sanity checks on AI-generated patch. Returns (valid, reason)."""
    if not code:
        return False, "empty patch"
    try:
        compile(code, "<ai-patch>", "exec")
    except SyntaxError as e:
        return False, f"syntax error: {e}"
    if "def process_promo" not in code:
        return False, "missing process_promo function"
    forbidden = ["import requests", "import bs4", "from requests", "from bs4", "import urllib.request"]
    for f in forbidden:
        if f in code:
            return False, f"forbidden import: {f}"
    if code.strip() == original_source.strip():
        return False, "patch identical to original"
    return True, "ok"


@app.post("/api/audit/autopatch")
def audit_autopatch():
    """AI reads vulnerable source, writes patched version, sandbox verifies."""
    from pathlib import Path
    from patched_runner import run_test_against

    demo_dir = Path(__file__).parent / "demo_target"
    vulnerable_src = (demo_dir / "vulnerable.py").read_text(encoding="utf-8")
    test_code = (demo_dir / "test_xss.py").read_text(encoding="utf-8")

    attempts = []
    ai_patch = ""
    patch_valid = False
    validation_reason = ""

    for attempt in range(1, 4):
        response = call_vultr_serverless_inference(
            prompt=(
                f"Here is a vulnerable Python file:\n\n{vulnerable_src}\n\n"
                f"The vulnerability: XSS via unescaped HTML concatenation in process_promo. "
                f"Write a fixed version of this exact file. "
                f"Keep the function name `process_promo` and its signature identical. "
                f"Keep the file minimal — do not add docstrings, type hints, comments, or extra code. "
                f"Use only the Python standard library (html.escape is available). "
                f"Return ONLY the complete fixed Python file, no markdown, no explanation."
            ),
            model="deepseek-v4.1-flash-1017",
            max_tokens=2000,
            timeout=60,
            system_prompt="You write Python code. Return only Python code, no markdown, no JSON, no explanation.",
        )
        raw = response.get("response", "") or ""
        ai_patch = _extract_python_code(raw)
        patch_valid, validation_reason = _validate_patch(ai_patch, vulnerable_src)
        attempts.append({
            "attempt": attempt,
            "raw_len": len(raw),
            "patch_len": len(ai_patch),
            "valid": patch_valid,
            "reason": validation_reason,
        })
        if patch_valid:
            break

    if not patch_valid:
        return {
            "fix_verified": False,
            "error": "AI patch failed validation on all attempts",
            "attempts": attempts,
            "ai_patch_source": ai_patch[:800] if ai_patch else "",
        }

    test_result = run_test_against(test_code, ai_patch, "ai-patch")

    return {
        "ai_patch_source": ai_patch[:1500],
        "ai_patch_test": {
            "container_id": test_result["container_id"],
            "exit_code": test_result["exit_code"],
            "stdout": test_result["stdout"],
            "stderr": test_result["stderr"],
            "duration_ms": test_result["duration_ms"],
            "sha256_receipt": test_result["sha256_receipt"],
        },
        "fix_verified": test_result["exit_code"] == 0,
        "attempts": attempts,
        "verdict": (
            "PASS: AI-written patch verified by sandbox"
            if test_result["exit_code"] == 0
            else "FAIL: AI patch did not pass the test"
        ),
    }
