"""Pattern B: real Playwright browser probe inside an isolated container.

The browser runs inside its own container on the aegisqa-browser-net network,
where the only reachable host is the FinFlow target app. It loads the real
/checkout page, fills the promo field with an XSS payload, submits it, and
reports whether the payload was reflected unescaped in the DOM. Real browser,
real page, real observation — not a simulated screenshot.
"""
import hashlib
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

PLAYWRIGHT_IMAGE = "aegisqa-playwright:latest"
TARGET_NETWORK = "aegisqa-browser-net"


def run_playwright_probe(target_url: str, timeout_sec: int = 30) -> dict:
    cid = f"sb-brw-{uuid.uuid4().hex[:8]}"
    lines = [
        "import json, base64",
        "from playwright.sync_api import sync_playwright",
        "payload = '<img src=x onerror=alert(1)>'",
        "out = {}",
        "with sync_playwright() as p:",
        "    browser = p.chromium.launch(headless=True)",
        "    page = browser.new_page()",
        "    try:",
        "        page.goto(" + json.dumps(target_url) + ", timeout=10000)",
        "        page.fill('#promo', payload)",
        "        page.click('#submit')",
        "        page.wait_for_timeout(800)",
        "        content = page.content()",
        "        shot = page.screenshot(full_page=True, animations=\"disabled\")",
        "        out = {",
        "            'status': 'REACHED',",
        "            'title': page.title(),",
        "            'url': page.url,",
        "            'xss_reflected': '<img' in content and '&lt;img' not in content,",
        "            'dom_snippet': content[:500],",
        "            'screenshot_b64': base64.b64encode(shot).decode(),",
        "        }",
        "    except Exception as e:",
        "        out = {'status': 'UNREACHABLE', 'error': str(e)}",
        "    finally:",
        "        browser.close()",
        "print(json.dumps(out))",
    ]
    probe_script = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = Path(tmpdir) / "probe.py"
        script_path.write_text(probe_script, encoding="utf-8")
        script_path.chmod(0o644)
        cmd = [
            "docker", "run", "--name", cid, "--rm",
            "--network", TARGET_NETWORK,
            "--memory", "512m", "--memory-swap", "512m",
            "--cpus", "1.0", "--pids-limit", "128",
            "--shm-size", "256m",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
            "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
            "-v", f"{script_path}:/workspace/probe.py:ro",
            "-w", "/workspace",
            PLAYWRIGHT_IMAGE,
            "python3", "-I", "/workspace/probe.py",
        ]
        start = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_sec,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            exit_code, stdout, stderr = 124, "", "[CONTAINMENT] Timeout"
        finally:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    duration = round((time.time() - start) * 1000, 1)
    receipt = hashlib.sha256(f"{cid}|{exit_code}|{stdout}|{stderr}|{duration}".encode()).hexdigest()
    try:
        probe = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except Exception:
        probe = {}
    return {
        "container_id": cid,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration,
        "sha256_receipt": receipt,
        "network": TARGET_NETWORK,
        "image": PLAYWRIGHT_IMAGE,
        "probe": probe,
    }
