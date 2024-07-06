from flask import Flask
from extensions import db
from auth import auth_bp  # Import the Blueprint

def create_app():
    app = Flask(__name__)

    # Configure your app (e.g., database URI, secret key, etc.)

    # Initialize extensions
    db.init_app(app)

    # Register Blueprints
    app.register_blueprint(auth_bp)

    return app
