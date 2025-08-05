import os
from dotenv import load_dotenv
load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret")
    SQLALCHEMY_DATABASE_URI = "postgresql://cookbook_db_vn7f_user:VtUER8pZnIeUWqQAiZmQLR4mAPgluImc@dpg-d2963obuibrs73e8jhcg-a/cookbook_db_vn7f"
    # SQLALCHEMY_DATABASE_URI = "sqlite:///../instance/db.sqlite3"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_COOKIE_NAME = "access_token_cookie"
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_SECURE = True  # True ONLY if using HTTPS
    JWT_ACCESS_COOKIE_PATH = "/"

