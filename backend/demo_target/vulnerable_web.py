"""Real FinFlow checkout target for Pattern B browser probes.

Serves /checkout with a promo form (#promo input, #submit button).
POST echoes the promo code into the page WITHOUT escaping — the XSS sink.
The browser probe fills the payload, submits, and observes the reflection.
"""
from flask import Flask, request

app = Flask(__name__)


def page(promo_html: str = "") -> str:
    return f"""<!doctype html>
<html><head><title>FinFlow Checkout</title></head>
<body>
<h1>FinFlow Checkout</h1>
<form method="post" action="/checkout">
  <label>Promo code: <input id="promo" name="promo" type="text"></label>
  <button id="submit" type="submit">Apply promo</button>
</form>
<div id="result">Promo applied: {promo_html}</div>
</body></html>"""


@app.route("/")
def index():
    return page()


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    promo = request.form.get("promo", "") if request.method == "POST" else ""
    # VULNERABLE: raw promo echoed into the page, no escaping
    return page(promo)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
