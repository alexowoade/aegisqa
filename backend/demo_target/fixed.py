"""Fixed FinFlow checkout handler. Context-aware escaping."""
from html import escape


def process_promo(raw_code: str) -> str:
    # FIXED: context-aware HTML escaping
    safe_code = escape(raw_code.strip(), quote=True)
    return f"<div>Promo applied: {safe_code}</div>"
