"""AegisQA Ephemeral Sandbox Execution Engine for Vultr Cloud Compute.

Enforces all four Challenge 1 (Blast Radius Zero) containment pillars:
1. Process isolation: Ephemeral Docker container per task, --pids-limit 64, --security-opt no-new-privileges
2. Secret hygiene: Zero host environment variables or API keys passed into container (-e flags omitted)
3. Resource limits: --memory 256m --memory-swap 256m --cpus 0.5 + strict wall-clock timeout
4. Lifecycle discipline: --read-only rootfs, noexec /tmp, and unconditional `docker rm -f` teardown
"""

import hashlib
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict


SANDBOX_IMAGE = "aegisqa-sandbox:latest"


def execute_python_in_sandbox(code: str, timeout_sec: int = 12) -> Dict[str, Any]:
    """Runs untrusted Python verification/patch code inside a locked-down container."""
    container_id = f"sb-vultr-{uuid.uuid4().hex[:8]}"
    start_ts = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = Path(tmpdir) / "task_verify.py"
        script_path.write_text(code, encoding="utf-8")
        script_path.chmod(0o644)

        cmd = [
            "docker", "run",
            "--name", container_id,
            "--rm",
            "--network", "none",                          # Zero outbound network egress
            "--memory", "256m",                           # Hard 256 MB RAM ceiling
            "--memory-swap", "256m",                      # Disable swap abuse
            "--cpus", "0.5",                              # 0.5 vCPU cap
            "--pids-limit", "64",                         # Block fork bombs
            "--read-only",                                # Immutable root filesystem
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # Scratch space without binary execution
            "--security-opt", "no-new-privileges:true",   # Prevent privilege escalation
            "--cap-drop", "ALL",                          # Drop all Linux capabilities
            "-v", f"{script_path}:/workspace/task_verify.py:ro",
            "-w", "/workspace",
            SANDBOX_IMAGE,
            "python3", "-I", "/workspace/task_verify.py"
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}  # Strip host secrets!
            )
            exit_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
            combined_out = f"{stdout}\n{stderr}"
            contained = (
                exit_code in (126, 137, 139)
                or any(
                    marker in combined_out
                    for marker in (
                        "[CONTAINED]",
                        "PermissionError",
                        "MemoryError",
                        "Read-only",
                        "Network is unreachable",
                        "ENETUNREACH",
                        "Temporary failure in name resolution",
                    )
                )
            )
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            raw_out = exc.stdout or ""
            raw_err = exc.stderr or ""
            stdout = raw_out.decode("utf-8", errors="replace") if isinstance(raw_out, bytes) else raw_out
            stderr = (raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else raw_err) + f"\n[CONTAINMENT] Killed after {timeout_sec}s wall-clock cap."
            contained = True
        finally:
            # Unconditional teardown guarantee
            subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)

    duration_ms = round((time.time() - start_ts) * 1000, 1)
    receipt_payload = f"{container_id}|{exit_code}|{stdout}|{stderr}|{duration_ms}"
    sha256_receipt = hashlib.sha256(receipt_payload.encode("utf-8")).hexdigest()

    return {
        "container_id": container_id,
        "executed_code": code,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
        "contained_incident": contained,
        "policy": {
            "network": "none",
            "memory_limit": "256m",
            "cpus": "0.5",
            "pids_limit": 64,
            "read_only_rootfs": True,
            "secrets_mounted": 0
        },
        "sha256_receipt": sha256_receipt
    }


def execute_http_probe_in_sandbox(target_url: str, timeout_sec: int = 20) -> Dict[str, Any]:
    """Pattern B: headless HTTP probe inside an isolated container. NOT Playwright.
    Attempts a real HTTP request; the --network none policy will block it,
    which itself is a meaningful containment test: the sandbox is air-gapped
    from the target. Status is UNREACHABLE when blocked, REACHED if it ever
    succeeds. This is NOT browser automation."""
    probe_script = f"""
import json, urllib.request, urllib.error
result = {{"target": {json.dumps(target_url)}, "attempted": True}}
try:
    with urllib.request.urlopen({json.dumps(target_url)}, timeout=3) as r:
        result["status"] = "REACHED"
        result["http_status"] = r.status
        result["bytes"] = len(r.read())
except Exception as e:
    result["status"] = "UNREACHABLE"
    result["error"] = f"{{type(e).__name__}}: {{e}}"
    result["contained"] = "Network is unreachable" in str(e) or "ENETUNREACH" in str(e) or "Temporary failure in name resolution" in str(e) or "Name or service not known" in str(e)
print(json.dumps(result))
"""
    return execute_python_in_sandbox(probe_script, timeout_sec=timeout_sec)
