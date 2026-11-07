"""Verification test — imports process_promo from app.py in the working dir."""
from app import process_promo

payload = "<img src=x onerror=alert(1)>"
result = process_promo(payload)

# The vulnerability is proven if the payload appears unescaped in the output
if "<img" in result and "&lt;img" not in result:
    print("VULNERABLE: XSS payload appears unescaped")
    print(f"Output: {result}")
    raise SystemExit(1)

# If the payload is escaped, the fix is working
print("SAFE: XSS payload neutralized")
print(f"Output: {result}")
raise SystemExit(0)
