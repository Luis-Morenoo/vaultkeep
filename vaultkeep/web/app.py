"""Flask application factory for the VaultKeep web interface"""

from flask import Flask, jsonify
from .auth import get_secret_key
from .limiter import limiter
from .routes import vault_bp

# Strict CSP: scripts only from our own /static files, no inline code, no framing
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; "
    "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def create_app(config: dict | None = None) -> Flask:
    """Create the Flask app. Fails at startup if the signing key is missing or weak."""

    # No CSRF tokens on purpose: the API authenticates with a Bearer JWT in the Authorization
    # header, never a cookie, so a cross-site request carries no credentials to abuse.
    app = Flask(__name__)

    # Fail closed: get_secret_key() raises if VAULTKEEP_SECRET_KEY is missing or too short
    app.config["SECRET_KEY"] = get_secret_key()
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # vault requests are tiny; reject huge bodies
    if config:
        app.config.update(config)

    limiter.init_app(app)
    app.register_blueprint(vault_bp)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"  # never cache vault data or tokens
        return response

    # JSON errors, so the browser code can read them (Flask's defaults are HTML)
    @app.errorhandler(429)
    def too_many_requests(_e):
        return jsonify({"error": "Too many attempts. Wait a minute and try again."}), 429

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify({"error": "Request too large"}), 413

    return app
