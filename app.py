from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from flask_mail import Mail
import sys

load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()
mail = Mail()


print("PYTHON VERSION:", sys.version)


def create_app():
    app = Flask(__name__)
    app.config.from_object("src.config.Config")  

    db.init_app(app)
    jwt.init_app(app)


    CORS(app, supports_credentials=True, origins=[
        "http://localhost:3000",
        "https://zesty-phoenix-8cec46.netlify.app"
    ])

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
