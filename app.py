import hashlib
import logging
import os
import random
import re
import secrets
import smtplib
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from email.message import EmailMessage
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape as xml_escape

import pymysql
import requests
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from requests import RequestException
from werkzeug.utils import secure_filename

import config


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "issues"
SITE_DB_PATH = DATA_DIR / "wowweb.db"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ISSUE_STATUSES = {
    "open": "待处理",
    "in_progress": "处理中",
    "resolved": "已解决",
    "closed": "已关闭",
}

SRP6_N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
SRP6_G = 7

app = Flask(__name__)
app.config.from_object(config)
app.secret_key = app.config["SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_MB"] * 1024 * 1024

registration_attempts = defaultdict(deque)
password_reset_attempts = defaultdict(deque)


def setup_logging():
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / "app.log",
        maxBytes=1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def init_site_db():
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(SITE_DB_PATH) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS download_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                image_path TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                gm_reply TEXT,
                replied_by TEXT,
                replied_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                request_ip TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_password_reset_account ON password_reset_tokens(account_id)"
        )
        existing_issue_columns = {
            row[1] for row in db.execute("PRAGMA table_info(issues)").fetchall()
        }
        migrations = {
            "status": "ALTER TABLE issues ADD COLUMN status TEXT NOT NULL DEFAULT 'open'",
            "gm_reply": "ALTER TABLE issues ADD COLUMN gm_reply TEXT",
            "replied_by": "ALTER TABLE issues ADD COLUMN replied_by TEXT",
            "replied_at": "ALTER TABLE issues ADD COLUMN replied_at TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing_issue_columns:
                db.execute(statement)
        db.commit()


def site_db():
    db = sqlite3.connect(SITE_DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def auth_db():
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        port=app.config["MYSQL_PORT"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASS"],
        database=app.config["MYSQL_AUTH_DB"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def characters_db():
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        port=app.config["MYSQL_PORT"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASS"],
        database=app.config["MYSQL_CHARACTERS_DB"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def normalize_account_text(value):
    return (value or "").strip().upper()


def calculate_srp6_verifier(username, password, salt):
    safe_username = normalize_account_text(username)
    safe_password = normalize_account_text(password)
    identity_hash = hashlib.sha1(f"{safe_username}:{safe_password}".encode("utf-8")).digest()
    x_hash = hashlib.sha1(salt + identity_hash).digest()
    x = int.from_bytes(x_hash, "little")
    return pow(SRP6_G, x, SRP6_N).to_bytes(32, "little")


def make_srp6_registration_data(username, password):
    salt = os.urandom(32)
    verifier = calculate_srp6_verifier(username, password, salt)
    return salt, verifier


def get_account(username):
    safe_username = normalize_account_text(username)
    with auth_db() as db:
        with db.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    a.id,
                    a.username,
                    a.email,
                    a.joindate,
                    a.last_login,
                    a.expansion,
                    a.salt,
                    a.verifier,
                    COALESCE(MAX(aa.gmlevel), 0) AS gmlevel
                FROM account a
                LEFT JOIN account_access aa ON aa.id = a.id AND aa.RealmID = -1
                WHERE a.username = %s
                GROUP BY a.id
                """,
                (safe_username,),
            )
            return cursor.fetchone()


def get_account_by_id(account_id, include_secret=False):
    secret_columns = ", a.salt, a.verifier" if include_secret else ""
    with auth_db() as db:
        with db.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    a.id,
                    a.username,
                    a.email,
                    a.joindate,
                    a.last_login,
                    a.expansion,
                    COALESCE(MAX(aa.gmlevel), 0) AS gmlevel
                    {secret_columns}
                FROM account a
                LEFT JOIN account_access aa ON aa.id = a.id AND aa.RealmID = -1
                WHERE a.id = %s
                GROUP BY a.id
                """,
                (account_id,),
            )
            return cursor.fetchone()


def check_account_password(account, password):
    expected = calculate_srp6_verifier(account["username"], password, account["salt"])
    return expected == account["verifier"]


def update_account_password(account_id, username, new_password):
    salt, verifier = make_srp6_registration_data(username, new_password)
    with auth_db() as db:
        with db.cursor() as cursor:
            cursor.execute(
                "UPDATE account SET salt = %s, verifier = %s, session_key = NULL WHERE id = %s",
                (salt, verifier, account_id),
            )
        db.commit()


def update_account_email(account_id, email):
    normalized_email = email.strip().upper()
    with auth_db() as db:
        with db.cursor() as cursor:
            cursor.execute(
                "UPDATE account SET email = %s, reg_mail = %s WHERE id = %s",
                (normalized_email, normalized_email, account_id),
            )
        db.commit()


def find_account_for_reset(username, email):
    safe_username = normalize_account_text(username)
    safe_email = (email or "").strip().upper()
    with auth_db() as db:
        with db.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, email
                FROM account
                WHERE username = %s AND UPPER(email) = %s AND email <> ''
                """,
                (safe_username, safe_email),
            )
            return cursor.fetchone()


def count_user_characters(account_id):
    with characters_db() as db:
        with db.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM characters WHERE account = %s", (account_id,))
            row = cursor.fetchone()
            return int(row["total"] or 0)


def count_online_players():
    with characters_db() as db:
        with db.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM characters WHERE online = 1")
            row = cursor.fetchone()
            return int(row["total"] or 0)


def server_status_snapshot():
    status = {
        "online": False,
        "message": "worldserver 暂时不可用",
        "players": None,
        "uptime": None,
        "db_online_players": None,
    }

    try:
        info = execute_soap_command("server info")
        status["online"] = True
        status["message"] = "worldserver 在线"
        player_match = re.search(r"Connected players:\s*(\d+)", info)
        uptime_match = re.search(r"Server uptime:\s*([^\r\n]+)", info)
        if player_match:
            status["players"] = int(player_match.group(1))
        if uptime_match:
            status["uptime"] = uptime_match.group(1).strip()
    except Exception:
        app.logger.warning("Server status SOAP query failed", exc_info=True)

    try:
        status["db_online_players"] = count_online_players()
    except pymysql.MySQLError:
        app.logger.warning("Online count query failed", exc_info=True)

    return status


def current_user():
    account_id = session.get("account_id")
    if not account_id:
        return None
    return get_account_by_id(account_id)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("account_id"):
            flash("请先登录。", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


def gm_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or int(user["gmlevel"] or 0) < app.config["GM_DOWNLOAD_LEVEL"]:
            flash("需要 GM 权限。", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "site_title": app.config["SITE_TITLE"],
        "issue_statuses": ISSUE_STATUSES,
    }


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


def reset_rate_limit_ok(ip_address):
    now = time.time()
    window_start = now - app.config["PASSWORD_RESET_RATE_WINDOW_SECONDS"]
    attempts = password_reset_attempts[ip_address]

    while attempts and attempts[0] < window_start:
        attempts.popleft()

    if len(attempts) >= app.config["PASSWORD_RESET_RATE_MAX_ATTEMPTS"]:
        return False

    attempts.append(now)
    return True


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_password_reset_token(account_id, request_ip):
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + app.config["PASSWORD_RESET_EXPIRE_MINUTES"] * 60
    digest = token_digest(token)

    with site_db() as db:
        db.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE account_id = ? AND used_at IS NULL",
            (int(time.time()), account_id),
        )
        db.execute(
            """
            INSERT INTO password_reset_tokens(account_id, token_hash, expires_at, request_ip)
            VALUES(?, ?, ?, ?)
            """,
            (account_id, digest, expires_at, request_ip),
        )
        db.commit()

    return token


def get_valid_reset_token(token):
    digest = token_digest(token)
    with site_db() as db:
        return db.execute(
            """
            SELECT *
            FROM password_reset_tokens
            WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?
            """,
            (digest, int(time.time())),
        ).fetchone()


def consume_reset_token(token):
    digest = token_digest(token)
    with site_db() as db:
        db.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (int(time.time()), digest),
        )
        db.commit()


def send_password_reset_email(recipient, username, reset_url):
    message = EmailMessage()
    message["Subject"] = f"{app.config['SITE_TITLE']} 密码重置"
    message["From"] = app.config["SMTP_FROM"]
    message["To"] = recipient
    message.set_content(
        f"""你好，{username}：

我们收到了你的密码重置请求。

请在 {app.config['PASSWORD_RESET_EXPIRE_MINUTES']} 分钟内打开下面的链接：
{reset_url}

如果不是你本人操作，请忽略这封邮件。
"""
    )

    if app.config["SMTP_USE_SSL"]:
        smtp = smtplib.SMTP_SSL(
            app.config["SMTP_HOST"],
            app.config["SMTP_PORT"],
            timeout=app.config["SMTP_TIMEOUT_SECONDS"],
        )
    else:
        smtp = smtplib.SMTP(
            app.config["SMTP_HOST"],
            app.config["SMTP_PORT"],
            timeout=app.config["SMTP_TIMEOUT_SECONDS"],
        )

    try:
        if app.config["SMTP_USE_TLS"] and not app.config["SMTP_USE_SSL"]:
            smtp.starttls()
        if app.config["SMTP_USER"]:
            smtp.login(app.config["SMTP_USER"], app.config["SMTP_PASS"])
        smtp.send_message(message)
    finally:
        smtp.quit()


def refresh_captcha():
    left = random.randint(2, 9)
    right = random.randint(2, 9)
    session["captcha_answer"] = str(left + right)
    session["captcha_question"] = f"{left} + {right} = ?"
    return session["captcha_question"]


def captcha_question():
    return session.get("captcha_question") or refresh_captcha()


def captcha_ok(value):
    return (value or "").strip() == session.get("captcha_answer")


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

    if not email:
        return None, "请输入邮箱，邮箱将用于密码找回。"

    if any(char.isspace() for char in email) or not EMAIL_RE.fullmatch(email):
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


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


@app.get("/")
def index():
    if session.get("account_id"):
        return redirect(url_for("dashboard"))
    return render_template(
        "index.html",
        site_title=app.config["SITE_TITLE"],
        captcha_question=captcha_question(),
    )


@app.post("/login")
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("请输入账号名和密码。", "error")
        return redirect(url_for("index"))

    try:
        account = get_account(username)
    except pymysql.MySQLError:
        app.logger.exception("Login database error")
        flash("登录服务暂时不可用。", "error")
        return redirect(url_for("index"))

    if not account or not check_account_password(account, password):
        flash("账号或密码错误。", "error")
        return redirect(url_for("index"))

    session.clear()
    session["account_id"] = account["id"]
    session["username"] = account["username"]
    flash("登录成功。", "success")
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    session.clear()
    flash("已退出登录。", "success")
    return redirect(url_for("index"))


@app.get("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


@app.post("/forgot-password")
def request_password_reset():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    generic_message = "如果账号和邮箱匹配，重置邮件将在几分钟内发送。"

    if not username or not email:
        flash("账号名和邮箱都必须填写。", "error")
        return redirect(url_for("forgot_password"))

    if not EMAIL_RE.fullmatch(email) or any(char.isspace() for char in email):
        flash("邮箱格式不正确。", "error")
        return redirect(url_for("forgot_password"))

    if not reset_rate_limit_ok(client_ip()):
        flash("请求太频繁，请稍后再试。", "error")
        return redirect(url_for("forgot_password"))

    try:
        account = find_account_for_reset(username, email)
        if account and app.config["SMTP_HOST"] and app.config["SMTP_FROM"]:
            token = create_password_reset_token(account["id"], client_ip())
            reset_url = (
                f"{app.config['PUBLIC_BASE_URL']}"
                f"{url_for('reset_password', token=token)}"
            )
            send_password_reset_email(account["email"], account["username"], reset_url)
        elif account:
            app.logger.error("Password reset requested but SMTP is not configured")
    except Exception:
        app.logger.exception("Password reset email failed")

    flash(generic_message, "success")
    return redirect(url_for("forgot_password"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_row = get_valid_reset_token(token)
    if not token_row:
        flash("重置链接无效或已经过期。", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not 6 <= len(new_password) <= 32 or any(char.isspace() for char in new_password):
            flash("新密码必须为 6 到 32 位，并且不能包含空格。", "error")
            return redirect(url_for("reset_password", token=token))

        if new_password != confirm_password:
            flash("两次输入的新密码不一致。", "error")
            return redirect(url_for("reset_password", token=token))

        account = get_account_by_id(token_row["account_id"])
        if not account:
            flash("账号不存在。", "error")
            return redirect(url_for("forgot_password"))

        update_account_password(account["id"], account["username"], new_password)
        consume_reset_token(token)
        session.clear()
        flash("密码已重置，请使用新密码登录。", "success")
        return redirect(url_for("index"))

    return render_template("reset_password.html", token=token)


@app.post("/register")
def register():
    ip_address = client_ip()
    if not rate_limit_ok(ip_address):
        return handle_form_response(False, "提交太频繁，请稍后再试。", 429)

    if not captcha_ok(request.form.get("captcha_answer")):
        refresh_captcha()
        return handle_form_response(False, "验证码不正确，请重新输入。", 400)

    payload, validation_error = validate_registration(request.form)
    if validation_error:
        refresh_captcha()
        return handle_form_response(False, validation_error, 400)

    command = (
        f"account create {payload['username']} "
        f"{payload['password']} {payload['email']}"
    )

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
        refresh_captcha()
        return handle_form_response(False, public_message, 400)
    except Exception:
        app.logger.exception(
            "Unexpected registration error for username=%s ip=%s",
            payload["username"],
            ip_address,
        )
        refresh_captcha()
        return handle_form_response(False, "注册失败，请联系管理员。", 500)

    app.logger.info("Registration succeeded for username=%s ip=%s", payload["username"], ip_address)
    refresh_captcha()
    return handle_form_response(True, "注册成功！现在可以登录。", 200)


def handle_form_response(ok, message, status_code):
    if request.accept_mimetypes.best == "application/json" or request.headers.get("X-Requested-With"):
        return jsonify({"ok": ok, "message": message, "realmlist": app.config["REALMLIST"]}), status_code

    flash(message, "success" if ok else "error")
    return redirect(url_for("index"))


@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    try:
        character_count = count_user_characters(user["id"])
    except pymysql.MySQLError:
        character_count = None
    return render_template(
        "dashboard.html",
        user=user,
        character_count=character_count,
        server_status=server_status_snapshot(),
        realmlist=app.config["REALMLIST"],
    )


@app.get("/account/security")
@login_required
def account_security():
    return render_template("account_security.html", user=current_user())


@app.post("/account/security")
@login_required
def change_password():
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    account = get_account_by_id(session["account_id"], include_secret=True)

    if not account or not check_account_password(account, current_password):
        flash("当前密码不正确。", "error")
        return redirect(url_for("account_security"))

    if not 6 <= len(new_password) <= 32 or any(char.isspace() for char in new_password):
        flash("新密码必须为 6 到 32 位，并且不能包含空格。", "error")
        return redirect(url_for("account_security"))

    if new_password != confirm_password:
        flash("两次输入的新密码不一致。", "error")
        return redirect(url_for("account_security"))

    update_account_password(account["id"], account["username"], new_password)
    flash("密码已修改，请使用新密码登录。", "success")
    return redirect(url_for("dashboard"))


@app.post("/account/email")
@login_required
def change_email():
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    account = get_account_by_id(session["account_id"], include_secret=True)

    if not account or not check_account_password(account, password):
        flash("当前密码不正确。", "error")
        return redirect(url_for("account_security"))

    if not email or any(char.isspace() for char in email) or not EMAIL_RE.fullmatch(email):
        flash("请输入有效邮箱。", "error")
        return redirect(url_for("account_security"))

    update_account_email(account["id"], email)
    flash("邮箱已更新，可以用于密码找回。", "success")
    return redirect(url_for("account_security"))


@app.get("/downloads")
@login_required
def downloads():
    user = current_user()
    with site_db() as db:
        links = db.execute("SELECT * FROM download_links ORDER BY id DESC").fetchall()
    return render_template("downloads.html", user=user, links=links)


@app.post("/downloads")
@login_required
@gm_required
def save_download():
    title = (request.form.get("title") or "").strip()
    url = (request.form.get("url") or "").strip()
    description = (request.form.get("description") or "").strip()
    link_id = request.form.get("link_id")
    action = request.form.get("action")

    with site_db() as db:
        if action == "delete" and link_id:
            db.execute("DELETE FROM download_links WHERE id = ?", (link_id,))
            flash("下载链接已删除。", "success")
        elif title and url:
            if link_id:
                db.execute(
                    """
                    UPDATE download_links
                    SET title = ?, url = ?, description = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (title, url, description, link_id),
                )
                flash("下载链接已更新。", "success")
            else:
                db.execute(
                    "INSERT INTO download_links(title, url, description) VALUES(?, ?, ?)",
                    (title, url, description),
                )
                flash("下载链接已添加。", "success")
        else:
            flash("标题和链接不能为空。", "error")
        db.commit()

    return redirect(url_for("downloads"))


@app.get("/online")
@login_required
def online_players():
    try:
        with characters_db() as db:
            with db.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT guid, account, name, level, race, class, map, zone
                    FROM characters
                    WHERE online = 1
                    ORDER BY name
                    """
                )
                players = cursor.fetchall()
    except pymysql.MySQLError:
        app.logger.exception("Online players query failed")
        players = None

    return render_template("online.html", players=players)


@app.get("/issues")
@login_required
def issues():
    user = current_user()
    status_filter = request.args.get("status") or ""
    params = []

    if int(user["gmlevel"] or 0) >= app.config["GM_DOWNLOAD_LEVEL"]:
        query = "SELECT * FROM issues"
        if status_filter in ISSUE_STATUSES:
            query += " WHERE status = ?"
            params.append(status_filter)
        query += " ORDER BY id DESC LIMIT 100"
    else:
        query = "SELECT * FROM issues WHERE account_id = ?"
        params.append(user["id"])
        if status_filter in ISSUE_STATUSES:
            query += " AND status = ?"
            params.append(status_filter)
        query += " ORDER BY id DESC LIMIT 50"

    with site_db() as db:
        items = db.execute(query, params).fetchall()
    return render_template(
        "issues.html",
        user=user,
        issues=items,
        status_filter=status_filter,
    )


@app.post("/issues")
@login_required
def submit_issue():
    user = current_user()
    content = (request.form.get("content") or "").strip()
    image = request.files.get("image")
    image_path = None

    if not content:
        flash("请输入问题内容。", "error")
        return redirect(url_for("issues"))

    if image and image.filename:
        if not allowed_image(image.filename):
            flash("图片格式仅支持 png、jpg、jpeg、gif、webp。", "error")
            return redirect(url_for("issues"))

        original = secure_filename(image.filename)
        extension = original.rsplit(".", 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{extension}"
        target = UPLOAD_DIR / filename
        image.save(target)
        image_path = f"uploads/issues/{filename}"

    with site_db() as db:
        db.execute(
            "INSERT INTO issues(account_id, username, content, image_path) VALUES(?, ?, ?, ?)",
            (user["id"], user["username"], content, image_path),
        )
        db.commit()

    flash("问题已提交。", "success")
    return redirect(url_for("issues"))


@app.post("/issues/<int:issue_id>/moderate")
@login_required
@gm_required
def moderate_issue(issue_id):
    status = request.form.get("status") or "open"
    reply = (request.form.get("gm_reply") or "").strip()
    user = current_user()

    if status not in ISSUE_STATUSES:
        flash("问题状态不正确。", "error")
        return redirect(url_for("issues"))

    with site_db() as db:
        db.execute(
            """
            UPDATE issues
            SET status = ?,
                gm_reply = ?,
                replied_by = ?,
                replied_at = CASE WHEN ? = '' THEN replied_at ELSE CURRENT_TIMESTAMP END
            WHERE id = ?
            """,
            (status, reply or None, user["username"] if reply else None, reply, issue_id),
        )
        db.commit()

    flash("问题处理信息已更新。", "success")
    return redirect(url_for("issues"))


setup_logging()
init_site_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=app.config["DEBUG"])
