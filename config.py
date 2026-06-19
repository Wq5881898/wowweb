import os
from pathlib import Path


def load_dotenv(path=".env"):
    env_path = Path(__file__).resolve().parent / path
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_dotenv()


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
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "3"))

GM_DOWNLOAD_LEVEL = int(os.getenv("GM_DOWNLOAD_LEVEL", "3"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
SMTP_TIMEOUT_SECONDS = float(os.getenv("SMTP_TIMEOUT_SECONDS", "10"))

PASSWORD_RESET_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "30"))
PASSWORD_RESET_RATE_WINDOW_SECONDS = int(
    os.getenv("PASSWORD_RESET_RATE_WINDOW_SECONDS", "900")
)
PASSWORD_RESET_RATE_MAX_ATTEMPTS = int(
    os.getenv("PASSWORD_RESET_RATE_MAX_ATTEMPTS", "3")
)

DEBUG = os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
