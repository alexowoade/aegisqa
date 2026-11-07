"""Runs a test against vulnerable and fixed source. Real containers, real receipts."""
import hashlib
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

SANDBOX_IMAGE = "aegisqa-sandbox:latest"


def run_test_against(test_code: str, source_code: str, label: str, timeout_sec: int = 15) -> dict:
    """Run test against a source file. Returns result dict with receipt."""
    cid = f"sb-vultr-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory() as tmpdir:
        test_path = Path(tmpdir) / "test.py"
        test_path.write_text(test_code, encoding="utf-8")
        test_path.chmod(0o644)
        src_path = Path(tmpdir) / "app.py"
        src_path.write_text(source_code, encoding="utf-8")
        src_path.chmod(0o644)
        cmd = [
            "docker", "run", "--name", cid, "--rm",
            "--network", "none", "--memory", "256m", "--memory-swap", "256m",
            "--cpus", "0.5", "--pids-limit", "64", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
            "-v", f"{test_path}:/workspace/test.py:ro",
            "-v", f"{src_path}:/workspace/app.py:ro",
            "-w", "/workspace",
            SANDBOX_IMAGE,
            # NOTE: python3 -I (isolated) drops the script dir from sys.path,
            # so "from app import ..." fails. runpy with an explicit path insert
            # keeps the test running as __main__ with /workspace importable.
            "python3", "-c",
            "import runpy, sys; sys.path.insert(0, '/workspace'); runpy.run_path('/workspace/test.py', run_name='__main__')",
        ]
        start = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_sec,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
            )
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            raw_out = exc.stdout or ""
            raw_err = exc.stderr or ""
            stdout = raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else raw_out
            stderr = (raw_err.decode("utf-8", "replace") if isinstance(raw_err, bytes) else raw_err) + "\n[CONTAINMENT] Timeout"
        finally:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
        duration = round((time.time() - start) * 1000, 1)
        receipt = hashlib.sha256(f"{cid}|{exit_code}|{stdout}|{stderr}|{duration}".encode()).hexdigest()
        return {
            "label": label,
            "container_id": cid,
            "executed_code": test_code,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration,
            "sha256_receipt": receipt,
        }
