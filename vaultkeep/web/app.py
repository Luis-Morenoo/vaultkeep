"""Flask application factory for the VaultKeep web interface"""

import os
from flask import Flask
from .limiter import limiter
from .routes import vault_bp


def create_app() -> Flask:
    """Create app for flask application"""

    # Create the flask app
    app = Flask(__name__)

    # Set the secret key from environment
    app.config["SECRET_KEY"] = os.environ.get(
        "VAULTKEEP_SECRET_KEY", "dev-secret-change-in-production"
    )

    # Init the limiter with the app
    limiter.init_app(app)

    # Register the blueprint
    app.register_blueprint(vault_bp)

    # Return the app
    return app

