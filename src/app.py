from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from flask_mail import Mail

load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object("src.config.Config")  

    db.init_app(app)
    jwt.init_app(app)

    CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

    @app.after_request
    def apply_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
        return response

    from src.routes import api
    app.register_blueprint(api, url_prefix="/api")

    app.config.update(
        MAIL_SERVER=os.getenv("MAIL_SERVER"),
        MAIL_PORT=os.getenv("MAIL_PORT"),
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "true").lower() in ["true", "1"],
        MAIL_USE_SSL=os.getenv("MAIL_USE_SSL", "false").lower() in ["true", "1"]
    )
    mail.init_app(app)

    return app

app = create_app()
