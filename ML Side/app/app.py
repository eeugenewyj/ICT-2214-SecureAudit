from flask import Flask
from core.analyzer import VulnerabilityAnalyzer
from app.routes import api
import os


def create_app():

    app = Flask(__name__)

    model_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "model",
        "vulnerability_model.pkl"
    )

    analyzer = VulnerabilityAnalyzer(model_path)

    # Store analyzer in app config
    app.config["ANALYZER"] = analyzer

    # Register routes
    app.register_blueprint(api)

    return app