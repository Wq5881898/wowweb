import logging
import re
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape as xml_escape

import requests
from flask import Flask, jsonify, render_template, request
from requests import RequestException

import config


BASE_DIR = Path(__file__).resolve().parent
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

app = Flask(__name__)
app.config.from_object(config)

registration_attempts = defaultdict(deque)


def setup_logging():
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / "app.log",
        maxBytes=1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def rate_limit_ok(ip_address):
    now = time.time()
    window_start = now - app.config["RATE_LIMIT_WINDOW_SECONDS"]
    attempts = registration_attempts[ip_address]

    while attempts and attempts[0] < window_start:
        attempts.popleft()

    if len(attempts) >= app.config["RATE_LIMIT_MAX_ATTEMPTS"]:
        return False

    attempts.append(now)
    return True


def validate_registration(data):
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    confirm_password = data.get("confirm_password") or ""
    email = (data.get("email") or "").strip()

    if not USERNAME_RE.fullmatch(username):
        return None, "账号名必须为 3 到 16 位，只能包含英文字母、数字和下划线。"

    if not 6 <= len(password) <= 32 or any(char.isspace() for char in password):
        return None, "密码必须为 6 到 32 位，并且不能包含空格。"

    if password != confirm_password:
        return None, "两次输入的密码不一致。"

    if email and (any(char.isspace() for char in email) or not EMAIL_RE.fullmatch(email)):
        return None, "邮箱格式不正确。"

    return {"username": username, "password": password, "email": email}, None


def soap_envelope(command):
    escaped_command = xml_escape(command)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:ns1="urn:AC">
  <SOAP-ENV:Body>
    <ns1:executeCommand>
      <command>{escaped_command}</command>
    </ns1:executeCommand>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""


def parse_soap_response(text):
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return text.strip()

    fault = root.find(".//faultstring")
    if fault is not None and fault.text:
        return fault.text.strip()

    for element in root.iter():
        if element.text and element.text.strip():
            return element.text.strip()

    return ""


def execute_soap_command(command):
    url = f"http://{app.config['SOAP_HOST']}:{app.config['SOAP_PORT']}/"
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "urn:AC#executeCommand",
    }
    response = requests.post(
        url,
        data=soap_envelope(command).encode("utf-8"),
        headers=headers,
        auth=(app.config["SOAP_USER"], app.config["SOAP_PASS"]),
        timeout=app.config["SOAP_TIMEOUT_SECONDS"],
    )
    parsed_response = parse_soap_response(response.text)
    if response.status_code >= 400 and response.status_code not in {401, 403} and parsed_response:
        raise ValueError(parsed_response)

    response.raise_for_status()
    return parsed_response


def classify_registration_error(error):
    text = str(error).lower()

    if isinstance(error, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)):
        return "服务器响应超时，请稍后再试。"

    if isinstance(error, requests.exceptions.ConnectionError):
        return "服务器注册服务暂时不可用。"

    if isinstance(error, requests.exceptions.HTTPError):
        status_code = error.response.status_code if error.response is not None else 0
        if status_code in {401, 403}:
            return "后台 SOAP 账号或权限配置错误。"

    if "already exist" in text or "already exists" in text or "account exists" in text:
        return "这个账号已经存在，请换一个账号名。"

    if "permission" in text or "security" in text:
        return "后台账号权限不足。"

    return "注册失败，请联系管理员。"


@app.get("/")
def index():
    return render_template(
        "index.html",
        site_title=app.config["SITE_TITLE"],
        realmlist=app.config["REALMLIST"],
    )


@app.post("/register")
def register():
    ip_address = client_ip()
    if not rate_limit_ok(ip_address):
        return jsonify({"ok": False, "message": "提交太频繁，请稍后再试。"}), 429

    payload, validation_error = validate_registration(request.form)
    if validation_error:
        return jsonify({"ok": False, "message": validation_error}), 400

    command = f"account create {payload['username']} {payload['password']}"

    try:
        result = execute_soap_command(command)
        normalized_result = result.lower()
        if any(marker in normalized_result for marker in ("already exist", "already exists")):
            raise ValueError("account already exists")
    except (RequestException, ValueError) as exc:
        public_message = classify_registration_error(exc)
        app.logger.warning(
            "Registration failed for username=%s ip=%s reason=%s",
            payload["username"],
            ip_address,
            public_message,
        )
        return jsonify({"ok": False, "message": public_message}), 400
    except Exception:
        app.logger.exception(
            "Unexpected registration error for username=%s ip=%s",
            payload["username"],
            ip_address,
        )
        return jsonify({"ok": False, "message": "注册失败，请联系管理员。"}), 500

    app.logger.info("Registration succeeded for username=%s ip=%s", payload["username"], ip_address)
    return jsonify(
        {
            "ok": True,
            "message": "注册成功！现在可以进入游戏登录。",
            "realmlist": app.config["REALMLIST"],
        }
    )


setup_logging()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=app.config["DEBUG"])
