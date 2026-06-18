import os


SOAP_HOST = os.getenv("SOAP_HOST", "127.0.0.1")
SOAP_PORT = int(os.getenv("SOAP_PORT", "7878"))
SOAP_USER = os.getenv("SOAP_USER", "websoap")
SOAP_PASS = os.getenv("SOAP_PASS", "change-me")
SOAP_TIMEOUT_SECONDS = float(os.getenv("SOAP_TIMEOUT_SECONDS", "8"))

SITE_TITLE = os.getenv("SITE_TITLE", "My WoW Server")
REALMLIST = os.getenv("REALMLIST", "wow.example.com")

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "3"))

DEBUG = os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
