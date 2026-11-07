"""Vulnerable FinFlow checkout handler. XSS sink at process_promo."""


def process_promo(raw_code: str) -> str:
    # VULNERABLE: raw HTML concatenation, no escaping
    return f"<div>Promo applied: {raw_code}</div>"
