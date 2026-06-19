import os


SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-this-secret-key")

SOAP_HOST = os.getenv("SOAP_HOST", "127.0.0.1")
SOAP_PORT = int(os.getenv("SOAP_PORT", "7878"))
SOAP_USER = os.getenv("SOAP_USER", "websoap")
SOAP_PASS = os.getenv("SOAP_PASS", "change-me")
SOAP_TIMEOUT_SECONDS = float(os.getenv("SOAP_TIMEOUT_SECONDS", "8"))

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "acore")
MYSQL_PASS = os.getenv("MYSQL_PASS", "change-me")
MYSQL_AUTH_DB = os.getenv("MYSQL_AUTH_DB", "acore_auth")
MYSQL_CHARACTERS_DB = os.getenv("MYSQL_CHARACTERS_DB", "acore_characters")

SITE_TITLE = os.getenv("SITE_TITLE", "My WoW Server")
REALMLIST = os.getenv("REALMLIST", "wow.example.com")

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "3"))

GM_DOWNLOAD_LEVEL = int(os.getenv("GM_DOWNLOAD_LEVEL", "3"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

DEBUG = os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
