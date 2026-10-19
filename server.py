#!/usr/bin/env python3
"""职安盾 VeriWork 本地服务。

仅使用 Python 标准库，既可提供静态前端，也可在配置环境变量后接入
OpenAI-compatible 大模型接口。硬规则和法源引用由程序控制，模型只负责
在已有证据范围内优化解释，不拥有修改风险等级和新增法源的权限。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import subprocess
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta
from email.message import EmailMessage
from html import escape as html_escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

BASE_DIR = Path(__file__).resolve().parent


def load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file()

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
MAX_BODY = 12 * 1024 * 1024
MAX_AUTH_BODY = 64 * 1024
_db_path = os.environ.get("VERIWORK_DB_PATH", "").strip()
DB_PATH = Path(_db_path).expanduser().resolve() if _db_path else BASE_DIR / "data" / "veriwork.db"
_evidence_dir = os.environ.get("VERIWORK_EVIDENCE_DIR", "").strip()
EVIDENCE_DIR = Path(_evidence_dir).expanduser().resolve() if _evidence_dir else DB_PATH.parent / "evidence"
MAX_EVIDENCE_BYTES = max(1024, int(os.environ.get("MAX_EVIDENCE_BYTES", str(8 * 1024 * 1024))))
PBKDF2_ITERATIONS = 200_000
SESSION_DAYS = 7
SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME", "veriwork_session").strip() or "veriwork_session"
SESSION_COOKIE_PATH = os.environ.get("SESSION_COOKIE_PATH", "/").strip() or "/"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "").strip().rstrip("/")
LOGIN_FAILURE_LIMIT = max(1, int(os.environ.get("LOGIN_FAILURE_LIMIT", "5")))
LOGIN_WINDOW_SECONDS = max(60, int(os.environ.get("LOGIN_WINDOW_SECONDS", "600")))
REGISTER_LIMIT = max(1, int(os.environ.get("REGISTER_LIMIT", "5")))
REGISTER_WINDOW_SECONDS = max(60, int(os.environ.get("REGISTER_WINDOW_SECONDS", "3600")))
REPORT_DISCLAIMER = "本报告用于就业风险提示、普法教育和材料整理，不替代律师、仲裁机构或人社部门作出最终法律判断。"
STARTED_AT = time.time()
APP_SECRET = os.environ.get("APP_SECRET", "").strip() or hashlib.sha256(f"veriwork-local:{DB_PATH}".encode("utf-8")).hexdigest()
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip()
ADMIN_2FA_ENABLED = os.environ.get("ADMIN_2FA_ENABLED", "").lower() in {"1", "true", "yes"}
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "true").lower() in {"1", "true", "yes"}
SMTP_USE_STARTTLS = os.environ.get("SMTP_USE_STARTTLS", "false").lower() in {"1", "true", "yes"}
EMAIL_DELIVERY_MODE = os.environ.get("EMAIL_DELIVERY_MODE", "smtp").strip().lower()
EMAIL_CODE_TTL_SECONDS = max(120, int(os.environ.get("EMAIL_CODE_TTL_SECONDS", "600")))
EMAIL_CODE_RESEND_SECONDS = max(30, int(os.environ.get("EMAIL_CODE_RESEND_SECONDS", "60")))
EMAIL_CODE_MAX_ATTEMPTS = max(3, int(os.environ.get("EMAIL_CODE_MAX_ATTEMPTS", "5")))
_rate_lock = threading.Lock()
_login_failures: dict[str, list[float]] = {}
_register_attempts: dict[str, list[float]] = {}


def auth_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return salt, digest


def init_auth_db() -> None:
    with auth_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                status TEXT NOT NULL DEFAULT 'active',
                email TEXT,
                email_verified_at TEXT,
                last_login_at TEXT,
                updated_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                user_agent TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                case_type TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                document_language TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                risk_ids TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                result_json TEXT,
                updated_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS evidence_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                case_id INTEGER,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT,
                client_ip TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS email_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS custody_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                evidence_id INTEGER,
                action TEXT NOT NULL,
                file_sha256 TEXT,
                record_hash TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_email_challenges_user ON email_challenges(user_id, purpose, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_cases_user_created ON cases(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_evidence_user_created ON evidence_files(user_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
            """
        )
        ensure_column(connection, "users", "status", "TEXT NOT NULL DEFAULT 'active'")
        ensure_column(connection, "users", "email", "TEXT")
        ensure_column(connection, "users", "email_verified_at", "TEXT")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(email)) WHERE email IS NOT NULL AND email <> ''")
        ensure_column(connection, "users", "last_login_at", "TEXT")
        ensure_column(connection, "users", "updated_at", "TEXT")
        ensure_column(connection, "sessions", "user_agent", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "sessions", "client_ip", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "cases", "title", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "cases", "status", "TEXT NOT NULL DEFAULT 'active'")
        ensure_column(connection, "cases", "result_json", "TEXT")
        ensure_column(connection, "cases", "updated_at", "TEXT")
        ensure_column(connection, "evidence_files", "previous_hash", "TEXT")
        ensure_column(connection, "evidence_files", "record_hash", "TEXT")
        def sync_configured_account(username_key: str, password_key: str, default_username: str, role: str, required: bool) -> None:
            username = os.environ.get(username_key, default_username).strip() or default_username
            password = os.environ.get(password_key, "").strip()
            existing = connection.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if not password:
                if required and not existing:
                    raise RuntimeError(f"首次初始化必须配置 {password_key}，禁止使用默认密码")
                return
            if len(password) < 10:
                raise RuntimeError(f"{password_key} 至少需要 10 位")
            salt, digest = hash_password(password)
            if existing:
                connection.execute(
                    "UPDATE users SET salt = ?, password_hash = ?, role = ? WHERE username = ?",
                    (salt, digest, role, username),
                )
            else:
                connection.execute(
                    "INSERT INTO users(username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, salt, digest, role, datetime.now().isoformat(timespec="seconds")),
                )

        sync_configured_account("DEMO_USERNAME", "DEMO_PASSWORD", "demo", "student", required=False)
        sync_configured_account("ADMIN_USERNAME", "ADMIN_PASSWORD", "admin", "admin", required=True)
        if ADMIN_EMAIL:
            admin_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
            now = datetime.now().isoformat(timespec="seconds")
            connection.execute(
                "UPDATE users SET email = ?, email_verified_at = ?, updated_at = ? WHERE username = ?",
                (ADMIN_EMAIL, now, now, admin_username),
            )
        connection.commit()


init_auth_db()


def register_user(username: str, password: str, role: str = "student", email: str = "") -> dict:
    username = username.strip()
    if not username:
        raise ValueError("用户名不能为空")
    if len(password) < 8:
        raise ValueError("密码至少8位")
    email = normalize_email(email) if str(email or "").strip() else None
    salt, digest = hash_password(password)
    try:
        with auth_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, salt, password_hash, role, email, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, salt, digest, role, email, datetime.now().isoformat(timespec="seconds")),
            )
            connection.commit()
            return {
                "id": cursor.lastrowid,
                "username": username,
                "role": role,
                "status": "active",
                "email": email,
                "emailVerified": False,
            }
    except sqlite3.IntegrityError as exc:
        raise ValueError("用户名或邮箱已存在") from exc


def authenticate_user(username: str, password: str) -> dict | None:
    with auth_db() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if not row:
        return None
    _, digest = hash_password(password, row["salt"])
    if not secrets.compare_digest(digest, row["password_hash"]):
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "status": row["status"],
        "email": row["email"] if "email" in row.keys() else None,
        "emailVerified": bool(row["email_verified_at"]) if "email_verified_at" in row.keys() else False,
    }


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int, user_agent: str = "", client_ip: str = "") -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now()
    expires = now + timedelta(days=SESSION_DAYS)
    with auth_db() as connection:
        connection.execute(
            "INSERT INTO sessions(token, user_id, created_at, expires_at, user_agent, client_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (
                hash_session_token(token),
                user_id,
                now.isoformat(timespec="seconds"),
                expires.isoformat(timespec="seconds"),
                user_agent[:300],
                client_ip[:64],
            ),
        )
        connection.commit()
    return token


def resolve_session(token: str | None) -> dict | None:
    if not token:
        return None
    token_digest = hash_session_token(token)
    with auth_db() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.username, users.role, users.status, users.email,
                   users.email_verified_at, sessions.expires_at
            FROM sessions JOIN users ON sessions.user_id = users.id
            WHERE sessions.token = ?
            """,
            (token_digest,),
        ).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now() or row["status"] != "active":
            connection.execute("DELETE FROM sessions WHERE token = ?", (token_digest,))
            connection.commit()
            return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "status": row["status"],
        "email": row["email"],
        "emailVerified": bool(row["email_verified_at"]),
    }


def strip_result_for_storage(result: dict) -> dict:
    payload = json.loads(json.dumps(result, ensure_ascii=False))
    payload.pop("inputText", None)
    for risk in payload.get("risks", []):
        for key in ("clause", "matchText", "reason", "action", "modelReason", "modelAction"):
            if risk.get(key):
                risk[key] = redact_pii(str(risk[key]))
    if isinstance(payload.get("sourceDocument"), dict):
        source_document = payload["sourceDocument"]
        if source_document.get("filename"):
            source_document["filename"] = redact_pii(str(source_document["filename"]))
    if payload.get("complaintDraft"):
        payload["complaintDraft"] = redact_pii(str(payload["complaintDraft"]))
    if isinstance(payload.get("questions"), list):
        payload["questions"] = [redact_pii(str(item)) for item in payload["questions"]]
    return payload


def save_case_record(user: dict, result: dict, case_type: str, jurisdiction: str, language: str) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    stored = strip_result_for_storage(result)
    title = f"{case_type} · {result.get('riskLevel', '风险')}研判"
    with auth_db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO cases(user_id, title, case_type, jurisdiction, document_language, risk_score,
                              risk_level, risk_ids, status, result_json, updated_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                user["id"],
                title[:120],
                case_type,
                jurisdiction,
                language,
                int(result.get("riskScore", 0)),
                str(result.get("riskLevel", "")),
                ",".join(risk["id"] for risk in result.get("risks", [])),
                json.dumps(stored, ensure_ascii=False),
                now,
                now,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def health_payload() -> dict:
    database_ok = False
    try:
        with auth_db() as connection:
            database_ok = int(connection.execute("SELECT 1").fetchone()[0]) == 1
    except Exception:  # noqa: BLE001
        database_ok = False
    return {
        "ok": database_ok,
        "name": "职安盾 VeriWork",
        "version": "2.0.0",
        "uptimeSeconds": int(time.time() - STARTED_AT),
        "databaseOk": database_ok,
        "evidenceStorageOk": EVIDENCE_DIR.is_dir() and os.access(EVIDENCE_DIR, os.W_OK),
        "llmConfigured": bool(os.environ.get("LLM_API_URL") and os.environ.get("LLM_API_KEY") and os.environ.get("LLM_MODEL")),
        "emailConfigured": smtp_configured(),
        "admin2faEnabled": ADMIN_2FA_ENABLED and bool(ADMIN_EMAIL) and smtp_configured(),
        "model": os.environ.get("LLM_MODEL", ""),
        "rules": len(RISKS),
        "laws": len(LAWS),
    }


EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def normalize_email(value: str) -> str:
    email = str(value or "").strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise ValueError("邮箱格式不正确")
    return email


def mask_email(value: str) -> str:
    email = str(value or "")
    if "@" not in email:
        return ""
    local, domain = email.split("@", 1)
    visible = local[:2] if len(local) >= 2 else local[:1]
    return f"{visible}***@{domain}"


def smtp_configured() -> bool:
    return EMAIL_DELIVERY_MODE == "test" or bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and SMTP_FROM)


def send_email_message(to_email: str, subject: str, body: str) -> None:
    to_email = normalize_email(to_email)
    if EMAIL_DELIVERY_MODE == "test":
        print(f"[VERIWORK_EMAIL_TEST] to={to_email} subject={subject} body={body}", flush=True)
        return
    if not smtp_configured():
        raise ValueError("邮件服务尚未配置")
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as client:
            client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as client:
            client.ehlo()
            if SMTP_USE_STARTTLS:
                client.starttls(context=context)
                client.ehlo()
            client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.send_message(message)


def email_code_hash(user_id: int, purpose: str, code: str) -> str:
    return hmac.new(APP_SECRET.encode("utf-8"), f"{user_id}|{purpose}|{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def create_email_challenge(user_id: int, purpose: str) -> tuple[int, str]:
    now = datetime.now()
    with auth_db() as connection:
        recent = connection.execute(
            "SELECT created_at FROM email_challenges WHERE user_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1",
            (user_id, purpose),
        ).fetchone()
        if recent and (now - datetime.fromisoformat(recent["created_at"])).total_seconds() < EMAIL_CODE_RESEND_SECONDS:
            raise ValueError("验证码发送过于频繁，请稍后再试")
        code = f"{secrets.randbelow(1_000_000):06d}"
        cursor = connection.execute(
            "INSERT INTO email_challenges(user_id, purpose, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                purpose,
                email_code_hash(user_id, purpose, code),
                (now + timedelta(seconds=EMAIL_CODE_TTL_SECONDS)).isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid), code


def verify_email_challenge(challenge_id: int, code: str, purpose: str, user_id: int | None = None) -> int:
    code = re.sub(r"\D", "", str(code or ""))
    if len(code) != 6:
        raise ValueError("请输入6位邮箱验证码")
    with auth_db() as connection:
        row = connection.execute("SELECT * FROM email_challenges WHERE id = ? AND purpose = ?", (challenge_id, purpose)).fetchone()
        if not row or (user_id is not None and int(row["user_id"]) != int(user_id)):
            raise ValueError("验证码无效或已过期")
        if row["consumed_at"]:
            raise ValueError("验证码已使用")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            raise ValueError("验证码已过期")
        if int(row["attempts"]) >= EMAIL_CODE_MAX_ATTEMPTS:
            raise ValueError("验证码尝试次数过多，请重新获取")
        expected = email_code_hash(int(row["user_id"]), purpose, code)
        if not secrets.compare_digest(expected, str(row["code_hash"])):
            connection.execute("UPDATE email_challenges SET attempts = attempts + 1 WHERE id = ?", (challenge_id,))
            connection.commit()
            raise ValueError("验证码不正确")
        connection.execute("UPDATE email_challenges SET consumed_at = ? WHERE id = ?", (datetime.now().isoformat(timespec="seconds"), challenge_id))
        connection.commit()
        return int(row["user_id"])


def latest_email_challenge(user_id: int, purpose: str) -> dict | None:
    with auth_db() as connection:
        row = connection.execute(
            "SELECT * FROM email_challenges WHERE user_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1",
            (user_id, purpose),
        ).fetchone()
    return dict(row) if row else None


def send_auth_code(user: dict, purpose: str, email: str) -> tuple[int, str]:
    challenge_id, code = create_email_challenge(int(user["id"]), purpose)
    labels = {
        "admin_2fa": "管理员登录验证码",
        "reset_password": "密码重置验证码",
        "verify_email": "邮箱绑定验证码",
    }
    label = labels.get(purpose, "身份验证码")
    send_email_message(
        email,
        f"职安盾 VeriWork {label}",
        f"你的{label}是：{code}\n\n验证码{EMAIL_CODE_TTL_SECONDS // 60}分钟内有效。如非本人操作，请忽略本邮件。",
    )
    return challenge_id, code


EVIDENCE_CHAIN_SECRET = os.environ.get("EVIDENCE_CHAIN_SECRET", "").strip() or hashlib.sha256(f"veriwork-evidence:{DB_PATH}".encode("utf-8")).hexdigest()


def evidence_record_hash(previous_hash: str, user_id: int, file_sha256: str, size_bytes: int, filename: str, created_at: str) -> str:
    payload = "|".join([previous_hash, str(user_id), file_sha256, str(size_bytes), filename, created_at])
    return hmac.new(EVIDENCE_CHAIN_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def add_custody_event(user_id: int, evidence_id: int | None, action: str, file_sha256: str = "", record_hash: str = "", detail: str = "") -> None:
    with auth_db() as connection:
        connection.execute(
            "INSERT INTO custody_events(user_id, evidence_id, action, file_sha256, record_hash, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, evidence_id, action[:60], file_sha256, record_hash, detail[:200], datetime.now().isoformat(timespec="seconds")),
        )
        connection.commit()


def backfill_evidence_chain() -> None:
    with auth_db() as connection:
        rows = connection.execute("SELECT * FROM evidence_files ORDER BY id").fetchall()
        previous_by_user: dict[int, str] = {}
        for row in rows:
            if row["record_hash"]:
                previous_by_user[int(row["user_id"])] = row["record_hash"]
                continue
            previous = previous_by_user.get(int(row["user_id"]), "")
            record_hash = evidence_record_hash(previous, int(row["user_id"]), row["sha256"], int(row["size_bytes"]), row["filename"], row["created_at"])
            connection.execute("UPDATE evidence_files SET previous_hash = ?, record_hash = ? WHERE id = ?", (previous, record_hash, row["id"]))
            previous_by_user[int(row["user_id"])] = record_hash
        connection.commit()


def verify_evidence_chain(user_id: int) -> dict:
    with auth_db() as connection:
        rows = connection.execute("SELECT * FROM evidence_files WHERE user_id = ? ORDER BY id", (user_id,)).fetchall()
    previous = ""
    items = []
    valid = True
    for row in rows:
        path = Path(row["storage_path"])
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        expected_record = evidence_record_hash(previous, int(row["user_id"]), row["sha256"], int(row["size_bytes"]), row["filename"], row["created_at"])
        item_valid = bool(actual_sha and actual_sha == row["sha256"] and row["previous_hash"] == previous and expected_record == row["record_hash"])
        valid = valid and item_valid
        items.append({
            "id": row["id"], "filename": row["filename"], "valid": item_valid,
            "file_sha256": row["sha256"], "actual_sha256": actual_sha,
            "previous_hash": row["previous_hash"], "record_hash": row["record_hash"],
            "expected_record_hash": expected_record,
        })
        previous = row["record_hash"]
    return {"valid": valid, "items": items, "head": previous}


def scan_evidence_file(path: Path) -> None:
    scanner = os.environ.get("CLAMSCAN_BIN", "").strip()
    if not scanner:
        return
    result = subprocess.run([scanner, "--no-summary", str(path)], capture_output=True, text=True, timeout=60)
    if result.returncode == 1:
        raise ValueError("证据文件病毒扫描未通过")
    if result.returncode not in (0, 1):
        raise ValueError("证据文件病毒扫描失败")


def audit_event(actor_user_id: int | None, action: str, target_type: str = "", target_id: str = "", detail: str = "", client_ip: str = "") -> None:
    with auth_db() as connection:
        connection.execute(
            "INSERT INTO audit_logs(actor_user_id, action, target_type, target_id, detail, client_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (actor_user_id, action[:80], target_type[:40], str(target_id)[:80], detail[:300], client_ip[:64], datetime.now().isoformat(timespec="seconds")),
        )
        connection.commit()


def list_user_cases(user_id: int) -> list[dict]:
    with auth_db() as connection:
        rows = connection.execute(
            """
            SELECT id, title, case_type, jurisdiction, document_language, risk_score, risk_level,
                   risk_ids, status, created_at, updated_at
            FROM cases WHERE user_id = ? ORDER BY id DESC LIMIT 200
            """,
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_case(user_id: int, case_id: int, allow_admin: bool = False) -> dict | None:
    with auth_db() as connection:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            return None
        if int(row["user_id"]) != int(user_id) and not allow_admin:
            return None
    item = dict(row)
    if item.get("result_json"):
        try:
            item["result"] = json.loads(item["result_json"])
        except json.JSONDecodeError:
            item["result"] = None
    item.pop("result_json", None)
    return item


def list_evidence(user_id: int) -> list[dict]:
    with auth_db() as connection:
        rows = connection.execute(
            "SELECT id, case_id, filename, content_type, size_bytes, sha256, previous_hash, record_hash, created_at FROM evidence_files WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_sessions(user_id: int, current_token: str | None) -> list[dict]:
    current_digest = hash_session_token(current_token) if current_token else ""
    with auth_db() as connection:
        rows = connection.execute(
            "SELECT token, created_at, expires_at, user_agent, client_ip FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    return [
        {
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "user_agent": row["user_agent"],
            "client_ip": row["client_ip"],
            "current": secrets.compare_digest(row["token"], current_digest),
        }
        for row in rows
    ]


def remove_user_sessions(connection: sqlite3.Connection, user_id: int, keep_token: str | None = None) -> None:
    keep_digest = hash_session_token(keep_token) if keep_token else ""
    if keep_digest:
        connection.execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (user_id, keep_digest))
    else:
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def admin_stats() -> dict:
    with auth_db() as connection:
        users = connection.execute(
            "SELECT id, username, role, status, email, email_verified_at, last_login_at, created_at FROM users ORDER BY id DESC"
        ).fetchall()
        cases = connection.execute(
            """
            SELECT cases.id, cases.title, cases.case_type, cases.jurisdiction, cases.document_language,
                   cases.risk_score, cases.risk_level, cases.risk_ids, cases.status, cases.created_at,
                   users.username
            FROM cases JOIN users ON cases.user_id = users.id
            ORDER BY cases.id DESC LIMIT 100
            """
        ).fetchall()
        case_count = int(connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0])
        high_risk_count = int(connection.execute("SELECT COUNT(*) FROM cases WHERE risk_score >= 70").fetchone()[0])
        evidence_count = int(connection.execute("SELECT COUNT(*) FROM evidence_files").fetchone()[0])
        audit_logs = connection.execute(
            """
            SELECT audit_logs.id, audit_logs.action, audit_logs.target_type, audit_logs.target_id,
                   audit_logs.detail, audit_logs.client_ip, audit_logs.created_at, users.username AS actor
            FROM audit_logs LEFT JOIN users ON audit_logs.actor_user_id = users.id
            ORDER BY audit_logs.id DESC LIMIT 100
            """
        ).fetchall()
    risk_counter = {}
    for case in cases:
        for risk_id in filter(None, case["risk_ids"].split(",")):
            risk_counter[risk_id] = risk_counter.get(risk_id, 0) + 1
    return {
        "userCount": len(users),
        "activeUserCount": sum(1 for user in users if user["status"] == "active"),
        "disabledUserCount": sum(1 for user in users if user["status"] != "active"),
        "caseCount": case_count,
        "highRiskCount": high_risk_count,
        "evidenceCount": evidence_count,
        "users": [dict(row) for row in users],
        "cases": [dict(row) for row in cases],
        "auditLogs": [dict(row) for row in audit_logs],
        "topRisks": sorted(risk_counter.items(), key=lambda item: item[1], reverse=True)[:10],
        "model": os.environ.get("LLM_MODEL", ""),
        "rules": len(RISKS),
        "laws": len(LAWS),
    }


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with auth_db() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (hash_session_token(token),))
        connection.commit()


LAWS = [
    {
        "id": "lcl_10_82",
        "title": "书面劳动合同与二倍工资",
        "source": "《中华人民共和国劳动合同法》第十条、第八十二条",
        "summary": "建立劳动关系应订立书面劳动合同；超过一个月未订立存在二倍工资责任风险。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_19",
        "title": "试用期期限与次数",
        "source": "《中华人民共和国劳动合同法》第十九条",
        "summary": "试用期期限与合同期限对应，同一用人单位与同一劳动者只能约定一次试用期。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_20",
        "title": "试用期工资底线",
        "source": "《中华人民共和国劳动合同法》第二十条",
        "summary": "试用期工资不得低于本单位相同岗位最低档工资或者合同约定工资的80%，且不得低于当地最低工资标准。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_9",
        "title": "禁止收取财物和扣押证件",
        "source": "《中华人民共和国劳动合同法》第九条",
        "summary": "用人单位不得扣押证件、要求担保或者以其他名义向劳动者收取财物。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_26",
        "title": "无效或部分无效条款",
        "source": "《中华人民共和国劳动合同法》第二十六条",
        "summary": "免除用人单位法定责任、排除劳动者权利的条款可能无效或部分无效。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_23_24",
        "title": "竞业限制人员、期限与补偿",
        "source": "《中华人民共和国劳动合同法》第二十三条、第二十四条",
        "summary": "竞业限制期限不得超过二年，并应关注适用人员范围和补偿安排。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "labor_41_44",
        "title": "加班安排与加班费",
        "source": "《中华人民共和国劳动法》第四十一条、第四十四条",
        "summary": "延长工作时间应符合法定程序和时长限制，并依法支付加班工资。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "labor_50_wage",
        "title": "工资支付与不得克扣拖欠",
        "source": "《中华人民共和国劳动法》第五十条",
        "summary": "工资应以货币形式按月支付，不得克扣或者无故拖欠。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_35",
        "title": "合同变更应协商一致",
        "source": "《中华人民共和国劳动合同法》第三十五条",
        "summary": "变更劳动合同约定内容应协商一致并采用书面形式。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_37",
        "title": "劳动者提前通知解除合同",
        "source": "《中华人民共和国劳动合同法》第三十七条",
        "summary": "劳动者提前三十日书面通知可以解除劳动合同，试用期提前三日通知。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_38_46_47",
        "title": "解除情形与经济补偿",
        "source": "《中华人民共和国劳动合同法》第三十八条、第四十六条、第四十七条",
        "summary": "欠薪、未依法缴社保等情形下劳动者可以解除合同并可能获得经济补偿。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "lcl_85",
        "title": "拖欠工资等行为的法律后果",
        "source": "《中华人民共和国劳动合同法》第八十五条",
        "summary": "未及时足额支付报酬、低于最低工资、未依法支付加班费等存在限期支付和加付赔偿金风险。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "social_58_60",
        "title": "社会保险登记与依法缴纳",
        "source": "《中华人民共和国社会保险法》第五十八条、第六十条",
        "summary": "用人单位应依法办理社保登记并按时足额缴费，不能通过约定放弃法定义务。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "employment_27",
        "title": "平等就业与反歧视",
        "source": "《中华人民共和国就业促进法》第二十七条",
        "summary": "用人单位招用人员应依法保障劳动者平等就业权利。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "wage_payment_9_15",
        "title": "工资支付与离职结算",
        "source": "《工资支付暂行规定》第九条、第十五条",
        "summary": "劳动关系解除或终止时应一次付清工资；不得克扣或无故拖欠劳动者工资。",
        "url": "https://www.gov.cn/",
    },
    {
        "id": "civil_code_contract",
        "title": "格式条款与合同公平",
        "source": "《中华人民共和国民法典》第四百九十六条、第四百九十七条",
        "summary": "格式条款应提示说明；不合理免除责任、加重对方责任或限制主要权利的条款可能无效。",
        "url": "https://flk.npc.gov.cn/",
    },
    {
        "id": "labor_relationship_notice",
        "title": "事实劳动关系判断要素",
        "source": "《关于确立劳动关系有关事项的通知》（劳社部发〔2005〕12号）",
        "summary": "判断劳动关系应综合主体资格、劳动管理、报酬支付和业务组成等事实，不能只看协议名称。",
        "url": "https://www.gov.cn/",
    },
    {
        "id": "internship_policy",
        "title": "高校实习管理与实习协议要求",
        "source": "教育部关于加强和规范普通本科高校实习管理工作的意见（教高函〔2019〕12号）",
        "summary": "高校实习应完善实习协议、安全教育、过程管理和权益保障；具体适用需结合学校制度和属地要求核验。",
        "url": "https://www.moe.gov.cn/",
    },
]


REVIEW_RULES = [
    {
        "id": "relationship_ambiguity",
        "regex": r"实习|兼职|劳务|非全日制|灵活用工|项目合作|合作人员|合作协议",
        "title": "劳动关系性质需核实",
        "detail": "实习、兼职、劳务或非全日制关系适用规则不同，需要结合实际管理方式、报酬和用工事实判断。",
    },
    {
        "id": "missing_terms",
        "regex": r"工资面议|薪资面议|社保面议|试用期待定|合同期限未定|以实际为准|另行约定|尚未确定|尚未明确|未确定|未明确",
        "title": "关键条款缺失或表述不确定",
        "detail": "工资、试用期、社保或合同期限未明确，不能仅凭当前材料输出确定结论。",
    },
    {
        "id": "oral_context",
        "regex": r"口头承诺|微信里说|HR口头表示|暂未写入合同",
        "title": "口头约定需要补充证据",
        "detail": "未写入书面材料的口头承诺需要聊天、录音、邮件或其他证据佐证。",
    },
]


JURISDICTIONS = {
    "全国规则": {
        "id": "全国规则",
        "title": "全国基础规则包",
        "status": "基础模式",
        "note": "当前使用全国性法律法规规则，不自动套用未经验证的地方数字标准。",
    },
    "北京": {
        "id": "北京",
        "title": "北京地区政策适配包",
        "status": "原型占位",
        "note": "正式参赛前接入北京市人社部门最新政策，并保留生效日期。",
    },
    "上海": {
        "id": "上海",
        "title": "上海地区政策适配包",
        "status": "原型占位",
        "note": "正式参赛前接入上海市人社部门最新政策，并保留生效日期。",
    },
    "广东": {
        "id": "广东",
        "title": "广东地区政策适配包",
        "status": "原型占位",
        "note": "广东不同城市最低工资存在差异，正式部署应按用工所在地建立城市级政策包。",
    },
}


RISKS = [
    {
        "id": "no_social_insurance",
        "title": "约定不缴或放弃社会保险",
        "category": "社会保障",
        "severity": "high",
        "weight": 22,
        "confidence": 0.97,
        "regex": r"(?:不|不予|不再|无需|拒绝)[^。；\n]{0,8}(?:缴纳|购买|办理)[^。；\n]{0,8}(?:社保|社会保险)|自愿放弃[^。；\n]{0,10}(?:社保|社会保险)|社保补贴代替社保",
        "reason": "依法参加社会保险属于法定义务，通常不能通过“自愿放弃”或现金补贴有效排除。",
        "action": "要求书面确认社保缴纳主体、起始月份和基数，并要求删除放弃社保条款。",
        "lawIds": ["social_58_60", "lcl_26", "lcl_38_46_47"],
    },
    {
        "id": "employment_deposit",
        "title": "押金、保证金或扣押证件",
        "category": "入职收费",
        "severity": "high",
        "weight": 20,
        "confidence": 0.96,
        "regex": r"押金|保证金|设备押金|服装费|扣留身份证|扣押身份证|提交证件原件|身份证原件由公司保管",
        "exceptionRegex": r"(?:不|不会|不得|禁止)[^。；\n]{0,12}(?:收取|要求)[^。；\n]{0,12}(?:押金|保证金|服装费)|不扣押[^。；\n]{0,10}(?:证件|身份证)",
        "reason": "用人单位不得收取押金、保证金等财物，也不得扣押居民身份证和其他证件。",
        "action": "拒绝支付入职押金，保留招聘信息和付款记录，必要时向人社部门投诉。",
        "lawIds": ["lcl_9", "lcl_26"],
    },
    {
        "id": "training_loan",
        "title": "培训贷或变相岗前收费",
        "category": "招聘诈骗",
        "severity": "high",
        "weight": 24,
        "confidence": 0.95,
        "regex": r"培训贷|分期贷款|贷款培训|岗前培训费|先交[^。；\n]{0,10}培训费|工作未满[^。；\n]{0,12}偿还培训贷款",
        "exceptionRegex": r"(?:不|不会|不得|禁止)[^。；\n]{0,12}(?:要求|设置|收取)?[^。；\n]{0,12}(?:培训贷|培训费|岗前收费)",
        "reason": "以入职为条件要求贷款或先缴高额培训费用，存在招聘诈骗和变相收费风险。",
        "action": "停止付款和贷款，核验机构资质，保留聊天、合同、转账与宣传页面证据。",
        "lawIds": ["lcl_9", "lcl_26"],
    },
    {
        "id": "probation_salary",
        "title": "试用期工资低于法定底线",
        "category": "试用期",
        "severity": "high",
        "weight": 18,
        "confidence": 0.88,
        "regex": r"试用期[^。；\n]{0,18}(?:工资|薪资|薪酬)[^。；\n]{0,15}(?:50%|60%|70%|不支付|零工资|无薪)",
        "exceptionRegex": r"不低于[^。；\n]{0,8}80%|达到[^。；\n]{0,8}80%|符合[^。；\n]{0,8}80%",
        "reason": "试用期工资不得低于法定底线的80%规则，并不得低于当地最低工资标准。",
        "action": "要求写明试用期月工资，并对照合同约定工资和当地最低工资核验。",
        "lawIds": ["lcl_20", "lcl_85"],
    },
    {
        "id": "probation_duration",
        "title": "试用期期限需要重点核验",
        "category": "试用期",
        "severity": "medium",
        "weight": 11,
        "confidence": 0.82,
        "regex": r"(?:试用期[^。；\n]{0,12}(?:六个月|6个月|一年|十二个月|延长试用期)|(?:转正后|入职后)[^。；\n]{0,12}再次试用)",
        "exceptionRegex": r"试用期[^。；\n]{0,8}不超过(?:六个月|6个月)|(?:合同期限三年以上|三年以上固定期限|无固定期限)[^。；\n]{0,30}试用期[^。；\n]{0,10}(?:六个月|6个月)",
        "reason": "六个月试用期仅在特定合同期限下才可能合法，同一单位只能约定一次试用期。",
        "action": "核对劳动合同期限、试用期次数和转正条件，拒绝不合理重复试用。",
        "lawIds": ["lcl_19"],
    },
    {
        "id": "noncompete_risk",
        "title": "竞业限制期限或补偿异常",
        "category": "离职限制",
        "severity": "high",
        "weight": 19,
        "confidence": 0.91,
        "regex": r"竞业限制[^。；\n]{0,35}(?:三年|3年|不支付(?:经济)?补偿|无需支付|无经济补偿)|离职后[^。；\n]{0,12}(?:三年|3年)[^。；\n]{0,15}不得",
        "reason": "竞业限制期限不得超过二年，适用人员范围和补偿安排均有法定限制。",
        "action": "核对岗位是否适用，要求明确补偿标准、支付方式和限制范围。",
        "lawIds": ["lcl_23_24"],
    },
    {
        "id": "overtime_unpaid",
        "title": "排除或变相规避加班费",
        "category": "工时薪酬",
        "severity": "high",
        "weight": 18,
        "confidence": 0.92,
        "regex": r"996|自愿加班|无偿加班|不支付加班费|加班费[^。；\n]{0,10}(?:包含|已包含)[^。；\n]{0,8}工资|自愿放弃加班费",
        "reason": "加班安排和加班费支付属于法定义务，以“自愿”为名排除责任存在违法风险。",
        "action": "保存考勤、工作群、任务记录和工资单，要求明确工时制度和加班费计算方式。",
        "lawIds": ["labor_41_44", "labor_50_wage", "lcl_85"],
    },
    {
        "id": "resignation_penalty",
        "title": "辞职违约金或不合理离职限制",
        "category": "离职限制",
        "severity": "high",
        "weight": 18,
        "confidence": 0.89,
        "regex": r"(?:辞职|离职|未满[^。；\n]{0,6}年)[^。；\n]{0,18}违约金|离职需[^。；\n]{0,12}批准",
        "reason": "除服务期和竞业限制等法定情形外，一般不得随意约定由劳动者承担违约金。",
        "action": "核验违约金对应的法定情形和金额依据，保留提出离职和送达证据。",
        "lawIds": ["lcl_37", "lcl_26"],
    },
    {
        "id": "unilateral_change",
        "title": "单方调岗、调薪或变更工作地点",
        "category": "合同变更",
        "severity": "medium",
        "weight": 12,
        "confidence": 0.86,
        "regex": r"(?:公司|用人单位)[^。；\n]{0,12}(?:随时|根据经营需要|无需同意)[^。；\n]{0,14}(?:调岗|调薪|调整(?:岗位|薪酬|薪资|工作地点))|无条件服从[^。；\n]{0,8}调岗",
        "reason": "合同变更原则上应协商一致并采用书面形式，完全排除协商权存在风险。",
        "action": "要求明确岗位、薪酬、工作地点和变更程序，保留原合同及调岗通知。",
        "lawIds": ["lcl_35", "lcl_26"],
    },
    {
        "id": "wage_delay",
        "title": "工资延迟、押金式发放或离职结算异常",
        "category": "工资支付",
        "severity": "high",
        "weight": 18,
        "confidence": 0.90,
        "regex": r"押[^。；\n]{0,4}个月工资|次月[^。；\n]{0,4}(?:30|28|月底)[^。；\n]{0,8}发放|年底[^。；\n]{0,6}(?:统一|一次性)[^。；\n]{0,4}发放|离职后[^。；\n]{0,12}结算(?:剩余)?工资",
        "reason": "工资应依法按月足额支付，无故拖欠或克扣工资存在法律责任。",
        "action": "确认每月工资发放日期，保留工资条、银行流水和催款记录。",
        "lawIds": ["labor_50_wage", "lcl_85"],
    },
    {
        "id": "no_written_contract",
        "title": "不签订或拖延签订书面劳动合同",
        "category": "合同形式",
        "severity": "high",
        "weight": 17,
        "confidence": 0.91,
        "regex": r"口头约定|暂不签订[^。；\n]{0,10}劳动合同|转正后[^。；\n]{0,8}(?:再|才)[^。；\n]{0,6}签订|试用期不签合同",
        "reason": "建立劳动关系后应依法订立书面劳动合同，超过一个月未订立存在二倍工资等风险。",
        "action": "保留入职通知、考勤、工资发放和工作沟通记录，主动要求补签书面合同。",
        "lawIds": ["lcl_10_82"],
    },
    {
        "id": "social_base",
        "title": "社保基数或缴纳方式异常",
        "category": "社会保障",
        "severity": "medium",
        "weight": 11,
        "confidence": 0.78,
        "regex": r"社保[^。；\n]{0,15}(?:最低基数|按最低标准)|(?:按)?最低基数[^。；\n]{0,10}(?:办理|缴纳)[^。；\n]{0,6}社保|最低标准[^。；\n]{0,10}(?:办理|缴纳)[^。；\n]{0,6}社保|工资[^。；\n]{0,12}另发[^。；\n]{0,12}社保",
        "reason": "社保缴费基数通常应与工资收入相关联，统一按最低基数可能产生争议。",
        "action": "核对工资构成、合同金额、社保缴费记录和缴费基数。",
        "lawIds": ["social_58_60"],
    },
    {
        "id": "discrimination",
        "title": "婚育、性别等就业歧视风险",
        "category": "平等就业",
        "severity": "high",
        "weight": 18,
        "confidence": 0.94,
        "regex": r"(?:不得|禁止|承诺)[^。；\n]{0,8}(?:怀孕|生育|结婚|婚育)|仅限男性|男性优先|女性[^。；\n]{0,8}(?:未婚|未育)",
        "reason": "与岗位无关的性别、婚育限制可能构成就业歧视。",
        "action": "保存招聘页面和沟通记录，可向人社部门、工会或公共法律服务平台反映。",
        "lawIds": ["employment_27"],
    },
    {
        "id": "internship_wage_forfeit",
        "title": "离职即扣发实习补贴",
        "category": "工资支付",
        "severity": "high",
        "weight": 30,
        "confidence": 0.98,
        "regex": r"(?:离职|自动离职)[^。；\n]{0,35}(?:工资|补贴)[^。；\n]{0,15}(?:不予|不|停发|扣除|核发)|(?:入职后|实习)[^。；\n]{0,25}(?:10|十|15|十五)[^。；\n]{0,12}个?工作日[^。；\n]{0,25}(?:离职|自动离职)",
        "reason": "以离职为条件不支付已经提供劳动的实习补贴或工资，属于惩罚性扣发，需重点核实其法律性质。",
        "action": "要求删除离职限制；保留考勤、工作记录和补贴发放记录，明确离职时按实际出勤结算。",
        "lawIds": ["wage_payment_9_15", "labor_50_wage", "civil_code_contract"],
        "documentTypes": ["实习协议"],
    },
    {
        "id": "third_party_payor",
        "title": "签约单位、实际用工单位和发薪主体不一致",
        "category": "用工关系",
        "severity": "high",
        "weight": 18,
        "confidence": 0.91,
        "regex": r"(?:委托|由)[^。；\n]{0,70}(?:分公司|第三方|人力资源|人才)[^。；\n]{0,45}(?:发放|支付|代发|薪酬|工资)",
        "reason": "签约、实际用工和发薪主体分离会使用人责任和证据指向不清，也可能涉及派遣、外包或事实用工。",
        "action": "书面确认实际用工单位、发薪主体、管理主体和事故责任主体，并保留排班、考勤和发薪记录。",
        "lawIds": ["labor_relationship_notice", "internship_policy", "lcl_26"],
        "documentTypes": ["实习协议", "劳务协议"],
    },
    {
        "id": "overtime_without_compensation",
        "title": "安排加班但未约定补偿",
        "category": "工时薪酬",
        "severity": "medium",
        "weight": 14,
        "confidence": 0.86,
        "regex": r"(?:安排|要求|需要)[^。；\n]{0,24}(?:延长工作时间|休息日|节假日)[^。；\n]{0,24}加班",
        "exceptionRegex": r"加班费|加班工资|调休|补休|加班补偿",
        "reason": "协议允许安排加班但没有明确加班报酬、调休或审批程序，实际执行容易产生争议。",
        "action": "要求补充加班审批、加班费或调休规则，并保存考勤、排班和任务分配记录。",
        "lawIds": ["labor_41_44", "labor_50_wage"],
        "documentTypes": ["实习协议", "劳动合同"],
    },
    {
        "id": "performance_unilateral",
        "title": "绩效津贴可单方变化",
        "category": "工资支付",
        "severity": "medium",
        "weight": 12,
        "confidence": 0.84,
        "regex": r"绩效[^。；\n]{0,30}(?:随|根据)[^。；\n]{0,28}(?:岗位|表现)[^。；\n]{0,24}(?:调整|变化)|绩效[^。；\n]{0,35}(?:理解|确认|接受)",
        "reason": "绩效津贴调整缺少明确标准、计算方式和异议程序，存在变相降低报酬的空间。",
        "action": "要求写明绩效基数、考核周期、计算方式和调整程序，并保留工资条。",
        "lawIds": ["civil_code_contract", "lcl_35"],
        "documentTypes": ["实习协议", "劳动合同"],
    },
    {
        "id": "broad_deduction",
        "title": "工资扣款范围不明确",
        "category": "工资支付",
        "severity": "medium",
        "weight": 13,
        "confidence": 0.87,
        "regex": r"扣除[^。；\n]{0,15}(?:有关|其他|相应|相关|适当)[^。；\n]{0,12}(?:款项|费用)|代缴[^。；\n]{0,25}扣除",
        "reason": "“有关款项”“其他费用”等表述范围不清，可能造成未经明确依据的工资扣减。",
        "action": "要求逐项列明可扣除项目、法律依据、计算方式和通知程序。",
        "lawIds": ["wage_payment_9_15", "labor_50_wage"],
        "documentTypes": ["实习协议", "劳动合同"],
    },
    {
        "id": "confidentiality_overbroad",
        "title": "保密义务范围过宽或期限过长",
        "category": "保密与竞业",
        "severity": "medium",
        "weight": 14,
        "confidence": 0.86,
        "regex": r"保密[^。；\n]{0,18}(?:最高限度|所有|不明确|视为商业机密)|保密(?:期限|义务)[^。；\n]{0,25}(?:终止|解除|结束)[^。；\n]{0,18}(?:后|继续有效)|视为商业机密",
        "reason": "将不明确信息推定为商业秘密、无限期保密或让员工承担全部损失，可能导致义务边界不清。",
        "action": "要求限定商业秘密范围、保密期限、例外情形和责任上限，并保留信息和权限记录。",
        "lawIds": ["civil_code_contract", "lcl_23_24"],
        "documentTypes": ["实习协议", "劳动合同"],
    },
    {
        "id": "unilateral_termination",
        "title": "即时解除和赔偿责任缺少边界",
        "category": "解除与赔偿",
        "severity": "medium",
        "weight": 15,
        "confidence": 0.85,
        "regex": r"(?:不能胜任|违反[^。；\n]{0,25}(?:规章|制度))[^。；\n]{0,28}(?:随时|立即)[^。；\n]{0,15}解除|(?:随时|立即)解除[^。；\n]{0,25}(?:不支付|无赔偿|全部赔偿)",
        "reason": "即时解除、严重违纪和全部赔偿责任应当有明确事实、证据和程序，不宜由一方单方认定。",
        "action": "要求补充解除程序、申辩机会、损失范围和举证责任；保留考核、通知和沟通记录。",
        "lawIds": ["lcl_38_46_47", "lcl_26", "civil_code_contract"],
        "documentTypes": ["实习协议", "劳动合同"],
    },
    {
        "id": "internship_insurance_missing",
        "title": "缺少实习责任或意外伤害保险安排",
        "category": "实习保障",
        "severity": "medium",
        "weight": 13,
        "confidence": 0.78,
        "factOnly": True,
        "regex": r"(?:劳动保护|安全卫生|防护用品|实习期间)",
        "exceptionRegex": r"意外|工伤|保险|实习责任|商业保险",
        "reason": "实习协议提到劳动保护但没有看到实习责任保险或意外伤害保障安排，发生事故时责任和救治路径不清。",
        "action": "要求补充保险类型、投保主体、保额、理赔流程和事故联系人。",
        "lawIds": ["internship_policy"],
        "documentTypes": ["实习协议"],
    },
    {
        "id": "internship_relationship_mismatch",
        "title": "名为实习但存在劳动用工特征",
        "category": "用工关系",
        "severity": "medium",
        "weight": 20,
        "confidence": 0.76,
        "regex": r"实习协议[\s\S]{0,1200}(?:标准工时|实际出勤|绩效|考勤|部门|按月|派驻)",
        "reason": "固定期限、标准工时、考勤绩效、按月补贴和第三方派驻等事实可能构成事实劳动关系或派遣用工特征，需要结合真实管理方式核实。",
        "action": "补查学校实习安排、实际管理主体、工作内容、报酬支付和社保情况；在确认关系性质前不要只按“实习”处理。",
        "lawIds": ["labor_relationship_notice", "internship_policy", "lcl_10_82"],
        "documentTypes": ["实习协议"],
    },
]


SEMANTIC_PATTERNS = {
    "no_social_insurance": r"(?=.*(?:社保|社会保险))(?=.*(?:员工自行|自行购买|公司不承担|不办理|不缴|再补缴|自行承担)).*",
    "employment_deposit": r"(?=.*(?:押金|保证金|工装费|服装费|毕业证原件|证件原件|身份证原件))(?=.*(?:入职|录用|先交|需交|须交|上交|收取|保管|缴纳)).*",
    "training_loan": r"(?=.*(?:贷款|培训费|培训收费|技能提升))(?=.*(?:入职|岗前|岗位|办理|分期|工资中扣除|先交|为获得)).*",
    "probation_salary": r"(?:试用期[^。；\n]{0,22}(?:[1-7][0-9]%|一半|低于[^。；\n]{0,6}80%)|前(?:一|二|三|1|2|3)个月[^。；\n]{0,18}(?:一半|只发|仅发|不给)).*",
    "probation_duration": r"(?:(?:试用期|实习期)[^。；\n]{0,16}(?:[7-9]个月|1[0-2]个月|八个月|九个月|十个月|十一个月|十二个月|一年)|(?:劳动合同|合同期限|期限)[^。；\n]{0,14}(?:一年|两年|二年|1年|2年)[^。；\n]{0,18}试用期[^。；\n]{0,8}(?:[3-9]个月|1[0-2]个月)).*",
    "noncompete_risk": r"(?=.*(?:竞业禁止|竞业限制|不得同业|不得从事同类))(?=.*(?:三年|3年|24个月|无补偿|未约定[^。；\n]{0,8}补偿|不支付[^。；\n]{0,8}补偿)).*",
    "overtime_unpaid": r"(?=.*(?:加班|额外工时|延长工作时间))(?=.*(?:不计算|不结算|不支付|已覆盖|不再结算|视为自愿|不得主张)).*",
    "resignation_penalty": r"(?=.*(?:离职|辞职|服务期))(?=.*(?:赔偿|违约金|须经[^。；\n]{0,8}同意|未完成|扣发)).*",
    "unilateral_change": r"(?=.*(?:调岗|调薪|调整[^。；\n]{0,8}(?:岗位|薪资|薪酬)|工作地点[^。；\n]{0,8}变更))(?=.*(?:公司有权|无需同意|不得异议|根据[^。；\n]{0,8}业务|依[^。；\n]{0,8}业务|向业务变化)).*",
    "wage_delay": r"(?=.*(?:工资|报酬))(?=.*(?:推迟|下月底|三个月后|再发放|延后|延期)).*",
    "no_written_contract": r"(?=.*(?:书面合同|劳动合同|书面文件))(?=.*(?:代替|再签|后再签|满[^。；\n]{0,8}再签|未签|暂不签)).*",
    "social_base": r"(?=.*(?:社保|社会保险))(?=.*(?:最低档|最低基数|按基本工资|不含绩效|不按实际工资)).*",
    "discrimination": r"(?:未婚女性|已婚未育|不生育|生育承诺|承诺[^。；\n]{0,8}(?:不怀孕|不生育)|仅限男性|男性优先).*",
}


def parse_page_range(spec: str, total: int) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec in {"all", "全部", "*"}:
        return list(range(total))
    selected = []
    for part in spec.replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(part)
        start = max(1, start)
        end = min(total, end)
        if start <= end:
            selected.extend(range(start - 1, end))
    return sorted(dict.fromkeys(selected))


def extract_document(filename: str, data: bytes, language: str = "zh", page_range: str = "") -> dict:
    suffix = Path(filename).suffix.lower()
    text = ""
    page_texts: list[dict] = []
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise ValueError("服务器未安装 pypdf，无法解析PDF") from exc
        reader = PdfReader(io.BytesIO(data))
        selected = parse_page_range(page_range, len(reader.pages))
        for index in selected:
            page_text = reader.pages[index].extract_text() or ""
            page_texts.append({"page": index + 1, "text": page_text})
        text = "\n".join(item["text"] for item in page_texts)
    elif suffix == ".docx":
        try:
            import docx
        except ImportError as exc:
            raise ValueError("服务器未安装 python-docx，无法解析DOCX") from exc
        document = docx.Document(io.BytesIO(data))
        lines = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
        for table in document.tables:
            for row in table.rows:
                cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if cells:
                    lines.append(" | ".join(cells))
        text = "\n".join(lines)
    elif suffix in {".txt", ".md", ".json", ".csv"}:
        text = data.decode("utf-8", errors="replace")
    else:
        raise ValueError(f"暂不支持的文件类型：{suffix or '未知'}")
    text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if not page_texts:
        page_texts = [{"page": 1, "text": text}]
    else:
        page_texts = [
            {"page": item["page"], "text": "\n".join(line.strip() for line in item["text"].splitlines() if line.strip())}
            for item in page_texts
        ]
    if len(text) < 20:
        raise ValueError("文件中未提取到足够的文本内容")
    return {
        "filename": filename,
        "format": suffix.lstrip("."),
        "language": language,
        "pageRange": page_range,
        "chars": len(text),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "pageCount": len(page_texts),
        "pages": page_texts,
        "text": text,
    }


def law_map() -> dict[str, dict]:
    return {item["id"]: item for item in LAWS}


def tokenize_chinese(text: str) -> set[str]:
    normalized = re.sub(r"[^\u4e00-\u9fa5a-zA-Z0-9]", "", text)
    tokens: set[str] = set()
    for index, char in enumerate(normalized):
        tokens.add(char)
        if index + 1 < len(normalized):
            tokens.add(normalized[index:index + 2])
    return tokens


def retrieve_laws(clause: str, seed_ids: list[str], laws_by_id: dict[str, dict], limit: int = 4) -> list[dict]:
    query_tokens = tokenize_chinese(clause)
    seed_set = set(seed_ids)
    ranked = []
    for law in laws_by_id.values():
        haystack = " ".join([law["title"], law["source"], law["summary"]])
        haystack_tokens = tokenize_chinese(haystack)
        overlap = sum((2 if len(token) > 1 else 1) for token in query_tokens if token in haystack_tokens)
        ranked.append({
            "law": law,
            "score": overlap + (100 if law["id"] in seed_set else 0),
            "seed": law["id"] in seed_set,
        })
    ranked.sort(key=lambda item: (item["score"], item["seed"]), reverse=True)

    selected = []
    seen = set()
    for item in ranked:
        law = item["law"]
        if law["id"] in seen:
            continue
        if not item["seed"] and item["score"] <= 0 and len(selected) >= len(seed_ids):
            continue
        seen.add(law["id"])
        selected.append({**law, "retrievalScore": item["score"], "seed": item["seed"]})
        if len(selected) >= limit:
            break
    return selected


def semantic_detection(
    clauses: list[str],
    already_detected: set[str],
    laws_by_id: dict[str, dict],
    document_type: str = "",
    source_pages: list[dict] | None = None,
) -> list[dict]:
    risk_by_id = {risk["id"]: risk for risk in RISKS}
    candidates = []
    for risk_id, semantic_regex in SEMANTIC_PATTERNS.items():
        if risk_id in already_detected:
            continue
        base = risk_by_id[risk_id]
        if base.get("documentTypes") and document_type not in base["documentTypes"]:
            continue
        pattern = re.compile(semantic_regex, re.IGNORECASE)
        for clause in clauses:
            match = pattern.search(clause)
            if not match:
                continue
            if base.get("exceptionRegex") and re.search(base["exceptionRegex"], clause, flags=re.IGNORECASE):
                continue
            item = dict(base)
            item["clause"] = clause
            item["matchText"] = match.group(0)
            item["lawItems"] = retrieve_laws(clause, base["lawIds"], laws_by_id, 4)
            item["detectionMode"] = "semantic"
            item["location"] = locate_clause(clause, source_pages)
            candidates.append(item)
            break
    return candidates


def split_clauses(text: str) -> list[str]:
    normalized = re.sub(r"\s*\n\s*", "", text)
    clauses: list[str] = []
    for part in re.split(r"[。；;]+", normalized):
        for segment in re.split(r"(?=第[一二三四五六七八九十百0-9]+条)", part):
            segment = segment.strip()
            if len(segment) > 1:
                clauses.append(segment)
    return clauses


def detect_document_type(text: str, selected_type: str = "") -> str:
    head = re.sub(r"\s+", "", text[:500])
    if "实习协议" in head:
        return "实习协议"
    if "劳动合同" in head:
        return "劳动合同"
    internship_terms = ("实习协议", "实习补贴", "实习期", "实习内容", "实习期间", "学校学生", "派驻", "实习岗位")
    labor_terms = ("劳动合同", "用人单位", "劳动者", "社会保险", "工资支付", "试用期")
    internship_score = sum(1 for term in internship_terms if term in text)
    labor_score = sum(1 for term in labor_terms if term in text)
    if internship_score >= 2 and internship_score >= labor_score:
        return "实习协议"
    if labor_score >= 2:
        return "劳动合同"
    return selected_type or "其他材料"


def extract_document_facts(text: str, document_type: str, selected_jurisdiction: str = "") -> dict:
    def match(pattern: str, flags: int = re.IGNORECASE) -> str:
        item = re.search(pattern, text, flags)
        return item.group(1).strip() if item else ""

    def clean(value: str) -> str:
        return re.sub(r"\s+", "", value or "")

    party_a = clean(match(r"(?:甲方|用人单位)\s*[:：]\s*([^\n（(]{2,60})"))
    if not party_a:
        party_a = clean(match(r"([^\n（(]{2,60}?)\s*[（(]\s*以下简称[^）)]*甲方[^）)]*[）)]"))
    school = clean(match(r"([\u4e00-\u9fa5]{2,30}(?:学院|大学))[\s\S]{0,40}?学\s*生"))
    if not school:
        school = clean(match(r"(?:学校|院校)\s*[:：]\s*([^\n，,；;]{2,40})"))
    actual_employer = clean(match(r"派驻至\s*([\s\S]{3,80}?)[，,。；]?\s*在"))
    if not actual_employer:
        actual_employer = clean(match(r"(?:实际用工单位|用工单位)\s*[:：]\s*([^\n，,；;]{2,60})"))
    position = clean(match(r"在\s*([^\s，,。；;]{1,20})\s*(?:部门|岗位)"))
    location_text = clean(match(r"(?:工作地点|实习地点|用工地点)\s*[:：]\s*([^\n，,；;]{2,40})"))
    start_match = re.search(r"自\s*(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日\s*至", text)
    end_match = re.search(r"至\s*(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日", text)
    start_date = f"{start_match.group(1)}年{start_match.group(2)}月{start_match.group(3)}日" if start_match else ""
    end_date = f"{end_match.group(1)}年{end_match.group(2)}月{end_match.group(3)}日" if end_match else ""
    daily_pay_text = match(r"(\d+(?:\.\d+)?)\s*元\s*[/／]\s*天")
    monthly_pay_text = match(r"(\d+(?:\.\d+)?)\s*元\s*[/／]\s*月")
    work_hours = "标准工时制" if "标准工时" in text else ("综合计算工时制" if "综合计算工时" in text else ("不定时工作制" if "不定时工作" in text else ""))
    insurance_terms = [term for term in ("意外伤害保险", "意外险", "实习责任保险", "工伤保险", "商业保险") if term in text]
    school_signature = bool(re.search(r"学校[^。；\n]{0,20}(?:盖章|签字)|学校（盖章）|丙方[^。；\n]{0,20}(?:盖章|签字)", text))
    has_dispute_clause = bool(re.search(r"争议|仲裁|人民法院|诉讼|管辖", text))
    has_job_attachment = bool(re.search(r"岗位说明|实习任务书|实习任务|附件[一二三四五六七八九十0-9]?|附件清单", text))
    third_party = bool(actual_employer and party_a and actual_employer not in party_a)
    payer_window = match(r"委托([\s\S]{0,220}?)(?:发放|支付)")
    payer_candidates = re.findall(r"[\u4e00-\u9fa5]{4,40}(?:有限公司|有限责任公司|分公司|集团)", payer_window)
    payer = payer_candidates[-1] if payer_candidates else ""
    payer = re.sub(r"^(?:其)?(?:依法)?(?:设立的?)?", "", payer)
    relationship_features = [term for term in ("标准工时", "实际出勤", "绩效", "考勤", "部门", "按月", "派驻") if term in text]
    city_names = ["深圳", "广州", "北京", "上海", "重庆", "成都", "杭州", "南京", "武汉", "西安", "苏州", "天津", "长沙", "郑州", "合肥", "厦门", "福州", "济南", "青岛", "大连", "沈阳", "哈尔滨", "昆明", "南昌", "贵阳", "南宁", "海口", "兰州", "太原", "石家庄", "乌鲁木齐", "呼和浩特", "银川", "西宁", "拉萨"]
    work_location = location_text or actual_employer
    work_city = next((city for city in city_names if city in work_location), "")
    if not work_city and actual_employer:
        work_city = next((city for city in city_names if city in actual_employer), "")
    jurisdiction_map = {"深圳": "广东", "广州": "广东", "北京": "北京", "上海": "上海", "重庆": "重庆", "成都": "四川", "杭州": "浙江", "南京": "江苏", "武汉": "湖北", "西安": "陕西", "苏州": "江苏", "天津": "天津", "长沙": "湖南", "郑州": "河南", "合肥": "安徽", "厦门": "福建", "福州": "福建"}
    jurisdiction_hint = jurisdiction_map.get(work_city, "")
    hourly_equivalent = round(float(daily_pay_text) / 8, 2) if daily_pay_text else None
    term_days = None
    if start_match and end_match:
        try:
            start_value = datetime(int(start_match.group(1)), int(start_match.group(2)), int(start_match.group(3)))
            end_value = datetime(int(end_match.group(1)), int(end_match.group(2)), int(end_match.group(3)))
            term_days = max(0, (end_value - start_value).days)
        except ValueError:
            term_days = None
    facts = {
        "documentType": document_type,
        "selectedCaseType": "",
        "partyA": party_a,
        "school": school,
        "actualEmployer": actual_employer,
        "position": position,
        "workLocation": work_location,
        "workCity": work_city,
        "startDate": start_date,
        "endDate": end_date,
        "termDays": term_days,
        "dailyPay": daily_pay_text,
        "monthlyPay": monthly_pay_text,
        "hourlyEquivalentAt8h": hourly_equivalent,
        "workHours": work_hours,
        "payer": payer if payer and payer != party_a else "",
        "thirdPartyArrangement": third_party,
        "hasSchoolSignature": school_signature,
        "hasAccidentInsurance": bool(insurance_terms),
        "insuranceTerms": insurance_terms,
        "hasDisputeClause": has_dispute_clause,
        "hasJobAttachment": has_job_attachment,
        "relationshipFeatures": relationship_features,
        "suggestedJurisdiction": jurisdiction_hint,
        "factsToVerify": [],
    }
    if selected_jurisdiction == "全国规则" and jurisdiction_hint:
        facts["factsToVerify"].append(f"已识别到工作地点可能在{jurisdiction_hint}（{work_city}），请切换或核验属地规则。")
    if third_party:
        facts["factsToVerify"].append("签约单位、实际用工单位和发薪主体可能不一致，需确认管理、报酬和事故责任主体。")
    if document_type == "实习协议" and school and not school_signature:
        facts["factsToVerify"].append("协议提到学校，但未识别到学校签署或盖章页。")
    if document_type == "实习协议" and not has_dispute_clause:
        facts["factsToVerify"].append("未识别到争议解决或管辖条款。")
    if document_type == "实习协议" and not has_job_attachment:
        facts["factsToVerify"].append("未识别到岗位说明书、实习任务书或具体工作内容附件。")
    if document_type == "实习协议" and not insurance_terms:
        facts["factsToVerify"].append("未识别到实习责任保险或意外伤害保险安排。")
    if daily_pay_text:
        facts["factsToVerify"].append(f"日补贴{daily_pay_text}元，按8小时折算约{hourly_equivalent}元/小时，需核对工作地最低工资和实际工时。")
    return facts


def locate_clause(clause: str, source_pages: list[dict] | None) -> dict:
    def article_labels(value: str) -> list[str]:
        labels = re.findall(r"(?m)^\s*(第[\s一二三四五六七八九十百0-9]+条)", value)
        if not labels:
            labels = re.findall(r"第[\s一二三四五六七八九十百0-9]+条", value)
        return [re.sub(r"\s+", "", label) for label in labels]

    needle = re.sub(r"\s+", "", clause[:90]).strip()
    leading = re.match(r"\s*(第[\s一二三四五六七八九十百0-9]+条)", clause)
    pages = source_pages or []
    for page_index, page in enumerate(pages):
        page_text = str(page.get("text", ""))
        compact_chars = [(char, index) for index, char in enumerate(page_text) if not char.isspace()]
        compact_page = "".join(char for char, _ in compact_chars)
        compact_pos = compact_page.find(needle[:40]) if needle else -1
        if compact_pos < 0:
            continue
        page_no = int(page.get("page", page_index + 1))
        if leading:
            return {"page": page_no, "clause": re.sub(r"\s+", "", leading.group(1))}
        original_index = compact_chars[compact_pos][1]
        prefix = page_text[:original_index]
        clause_matches = article_labels(prefix)
        if clause_matches:
            return {"page": page_no, "clause": clause_matches[-1]}
        for previous in reversed(pages[:page_index]):
            previous_matches = article_labels(str(previous.get("text", "")))
            if previous_matches:
                return {"page": page_no, "clause": previous_matches[-1]}
        return {"page": page_no, "clause": "未编号条款"}
    clause_matches = article_labels(clause[:160])
    return {"page": 1, "clause": clause_matches[-1] if clause_matches else "未编号条款"}


def deterministic_analysis(text: str, case_type: str, jurisdiction: str, language: str = "zh", source_pages: list[dict] | None = None, source_document: dict | None = None) -> dict:
    started_at = time.perf_counter()
    document_type = detect_document_type(text, case_type)
    facts = extract_document_facts(text, document_type, jurisdiction)
    facts["selectedCaseType"] = case_type
    jurisdiction_profile = JURISDICTIONS.get(jurisdiction, JURISDICTIONS["全国规则"])
    clauses = split_clauses(text)
    laws_by_id = law_map()
    detected: list[dict] = []
    rule_hits = 0

    for risk in RISKS:
        if risk.get("documentTypes") and document_type not in risk["documentTypes"]:
            continue
        if risk.get("factOnly"):
            continue
        pattern = re.compile(risk["regex"], re.IGNORECASE)
        for clause in clauses:
            match = pattern.search(clause)
            if not match:
                continue
            if risk.get("exceptionRegex") and re.search(risk["exceptionRegex"], clause, flags=re.IGNORECASE):
                continue
            item = dict(risk)
            item["clause"] = clause
            item["matchText"] = match.group(0)
            item["lawItems"] = retrieve_laws(clause, risk["lawIds"], laws_by_id, 4)
            item["detectionMode"] = "deterministic"
            item["location"] = locate_clause(clause, source_pages)
            detected.append(item)
            rule_hits += 1
            break

    def add_fact_risk(risk_id: str, match_text: str, anchor: str = "") -> None:
        if any(item["id"] == risk_id for item in detected):
            return
        base = next((risk for risk in RISKS if risk["id"] == risk_id), None)
        if not base:
            return
        item = dict(base)
        item["clause"] = match_text
        item["matchText"] = match_text
        item["lawItems"] = retrieve_laws(match_text, base["lawIds"], laws_by_id, 4)
        item["detectionMode"] = "fact"
        location = locate_clause(anchor or match_text, source_pages)
        if location.get("clause") == "未编号条款":
            location["clause"] = "结构化事实"
        item["location"] = location
        detected.append(item)

    if facts.get("thirdPartyArrangement"):
        add_fact_risk("third_party_payor", "签约单位、实际用工单位或发薪主体不一致", "派驻至")
    if document_type == "实习协议" and facts.get("relationshipFeatures"):
        add_fact_risk("internship_relationship_mismatch", "标准工时、考勤、绩效或派驻等劳动用工特征", "标准工时")
    if "延长工作时间" in text and "加班费" not in text and "加班工资" not in text:
        add_fact_risk("overtime_without_compensation", "文本存在加班安排但未识别到加班费或调休", "延长工作时间")
    if "绩效" in text and not any(item["id"] == "performance_unilateral" for item in detected):
        if "岗位" in text and "调整" in text:
            add_fact_risk("performance_unilateral", "绩效津贴可随岗位或表现变化", "绩效")
    if "保密" in text and ("终止" in text or "后均有效" in text) and not any(item["id"] == "confidentiality_overbroad" for item in detected):
        add_fact_risk("confidentiality_overbroad", "保密义务延续至协议终止后且范围不明确", "保密")
    if document_type == "实习协议" and not facts.get("hasAccidentInsurance"):
        add_fact_risk("internship_insurance_missing", "未识别到实习责任保险或意外伤害保险", "")

    semantic = semantic_detection(
        clauses,
        {item["id"] for item in detected},
        laws_by_id,
        document_type=document_type,
        source_pages=source_pages,
    )
    detected.extend(semantic)
    semantic_hits = len(semantic)
    fact_hits = sum(1 for item in detected if item.get("detectionMode") == "fact")

    review_items = []
    for rule in REVIEW_RULES:
        if re.search(rule["regex"], text, flags=re.IGNORECASE):
            review_items.append({"id": rule["id"], "title": rule["title"], "detail": rule["detail"], "source": "文本"})
    if jurisdiction != "全国规则":
        review_items.append({
            "id": "dynamic_local_policy",
            "title": "地区标准需要核验",
            "detail": f"当前选择“{jurisdiction}”政策模式，最低工资、社保缴费等动态标准必须使用当地最新有效版本。",
            "source": "规则",
        })
    for index, detail in enumerate(facts.get("factsToVerify", [])):
        review_items.append({
            "id": f"fact_verify_{index + 1}",
            "title": "材料事实需要核实",
            "detail": detail,
            "source": "事实抽取",
        })
    if document_type == "实习协议" and facts.get("relationshipFeatures"):
        review_items.append({
            "id": "internship_relationship",
            "title": "需核实是否仅构成实习关系",
            "detail": "材料同时出现固定期限、标准工时、实际出勤、绩效或派驻等特征，需结合实际管理、报酬和学校安排判断是否可能构成劳动关系或派遣用工。",
            "source": "规则",
        })
    if document_type == "实习协议" and facts.get("school") and not facts.get("hasSchoolSignature"):
        review_items.append({
            "id": "school_signature_missing",
            "title": "学校签署或三方安排需核实",
            "detail": "协议提到学校，但未识别到学校盖章或签字页；请补充学校实习安排、三方协议或指导教师信息。",
            "source": "事实抽取",
        })
    if document_type == "实习协议" and not facts.get("hasDisputeClause"):
        review_items.append({
            "id": "dispute_clause_missing",
            "title": "争议解决条款缺失",
            "detail": "未识别到争议解决、仲裁或法院管辖安排，发生争议时责任和路径可能不明确。",
            "source": "事实抽取",
        })
    if document_type == "实习协议" and not facts.get("hasJobAttachment"):
        review_items.append({
            "id": "job_attachment_missing",
            "title": "岗位任务附件缺失",
            "detail": "协议未识别到岗位说明书、实习任务书或具体工作内容附件，岗位边界和考核标准不明确。",
            "source": "事实抽取",
        })
    # Remove duplicate review titles while keeping the first explanation.
    deduped_reviews = []
    seen_review_ids = set()
    for item in review_items:
        if item["id"] in seen_review_ids:
            continue
        seen_review_ids.add(item["id"])
        deduped_reviews.append(item)
    review_items = deduped_reviews

    high_count = sum(1 for item in detected if item["severity"] == "high")
    medium_count = sum(1 for item in detected if item["severity"] == "medium")
    has_review = bool(review_items) or any(item["detectionMode"] == "llm_candidate" for item in detected)
    if detected:
        risk_score = min(98, 22 + sum(item["weight"] for item in detected))
        if any(item["id"] == "internship_wage_forfeit" for item in detected):
            risk_score = max(risk_score, 78)
        risk_level = "高风险" if risk_score >= 70 else "中风险" if risk_score >= 40 else "低风险"
    elif has_review:
        risk_score = 35
        risk_level = "待核实"
    else:
        risk_score = 6
        risk_level = "低风险"
    unique_law_ids = list(dict.fromkeys(law_id for item in detected for law_id in item["lawIds"]))
    citations = [laws_by_id[law_id] for law_id in unique_law_ids if law_id in laws_by_id]
    citation_coverage = round(sum(1 for item in detected if item["lawItems"]) / len(detected) * 100) if detected else 100
    questions = [item["action"] for item in detected[:8]] or ["请提供正式合同文本、岗位说明和工资记录，并确认实际用工主体。"]
    questions.extend(f"核实：{item['detail']}" for item in review_items[:8])
    questions = list(dict.fromkeys(questions))[:14]
    evidence_lines = [f"- {item['title']}：{item['action']}" for item in detected[:10]]
    complaint_lines = [
        "实习/劳动权益事项材料整理草稿",
        "",
        "一、诉求事项",
        "请求核对并依法处理下列材料风险：" + "、".join(item["title"] for item in detected) + "。"
        if detected else "当前未识别到需要生成材料的明显风险。",
        "",
        "二、可提交证据",
        *(evidence_lines or ["- 保存协议、岗位说明、考勤、工资或补贴记录、沟通记录和学校实习安排。"]),
        "",
        "三、办理提示",
        "建议先与实际用工单位和签约单位书面沟通；协商不成时，可向用工所在地人社部门、劳动保障监察机构、公共法律服务平台或学校就业实习管理部门咨询。",
        "",
        "本系统用于风险提示、普法教育和材料整理，不替代专业法律意见。",
    ]
    return {
        "caseType": document_type,
        "selectedCaseType": case_type,
        "documentType": document_type,
        "documentTypeConfidence": min(0.99, 0.55 + 0.08 * len([term for term in ("实习协议", "实习补贴", "实习期", "派驻", "学校学生") if term in text])),
        "documentLanguage": language,
        "inputText": text,
        "jurisdiction": jurisdiction,
        "facts": facts,
        "sourceDocument": source_document or {},
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "jurisdictionProfile": jurisdiction_profile,
        "clauses": clauses,
        "risks": detected,
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "riskHeadline": (
            f"发现 {len(detected)} 项风险，其中 {high_count} 项高风险"
            if detected
            else ("材料信息不足，暂不能给出确定结论" if has_review else "未发现明显高风险条款")
        ),
        "riskDescription": (
            f"已识别为{document_type}。以下结论来自确定性规则、法源匹配和模型候选，涉及实际用工关系、地方标准和事实的部分必须人工复核。"
        ),
        "reviewItems": review_items,
        "requiresHumanReview": has_review or document_type == "实习协议",
        "citations": citations,
        "citationCoverage": citation_coverage,
        "analysisStats": {
            "ruleHits": rule_hits,
            "semanticHits": semantic_hits,
            "factHits": fact_hits,
            "modelCandidates": 0,
            "totalRisks": len(detected),
        },
        "processingMs": max(1, round((time.perf_counter() - started_at) * 1000)),
        "trace": [
            {"title": "文档类型判断", "detail": f"识别为{document_type}；用户选择为{case_type}。"},
            {"title": "条款切分与事实抽取", "detail": f"识别 {len(clauses)} 个语义片段，并抽取主体、地点、期限、报酬和签署信息。"},
            {"title": "本地法源检索", "detail": f"风险规则关联 {len(citations)} 条核心法源，并结合条款关键词执行本地检索排序。"},
            {"title": "规则引擎研判", "detail": f"确定性规则命中 {rule_hits} 项，事实规则补充 {fact_hits} 项，语义规则补充 {semantic_hits} 项，共发现 {high_count} 项高风险、{medium_count} 项中风险。"},
            {"title": "交叉验证与拒答策略", "detail": f"发现 {len(review_items)} 项需要人工核实的事实；无可靠法源或关键信息不足时，系统停止输出确定结论。"},
        ],
        "questions": questions,
        "complaintDraft": "\n".join(complaint_lines),
        "engine": "deterministic-rules",
    }

def extract_json_object(content: str) -> dict:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("模型未返回 JSON 对象")
    return json.loads(content[start:end + 1])


def recompute_after_enhancement(result: dict) -> None:
    detected = result["risks"]
    high_count = sum(1 for item in detected if item["severity"] == "high")
    medium_count = sum(1 for item in detected if item["severity"] == "medium")
    review_items = result.get("reviewItems", [])
    if detected:
        risk_score = min(96, 22 + sum(item["weight"] for item in detected))
        if any(item["id"] == "internship_wage_forfeit" for item in detected):
            risk_score = max(risk_score, 78)
        risk_level = "高风险" if risk_score >= 70 else "中风险" if risk_score >= 40 else "低风险"
        risk_headline = f"发现 {len(detected)} 项风险，其中 {high_count} 项高风险"
        risk_description = "以下结论来自规则、语义与模型候选，并经本地法源绑定；仍需人工复核具体事实。"
    elif review_items:
        risk_score = 35
        risk_level = "待核实"
        risk_headline = "材料信息不足，暂不能给出确定结论"
        risk_description = "当前材料缺少决定性事实，系统停止输出确定结论。"
    else:
        risk_score = 6
        risk_level = "低风险"
        risk_headline = "未发现明显高风险条款"
        risk_description = "当前链路未发现明显风险，但不代表合同不存在争议。"

    law_ids = list(dict.fromkeys(law_id for item in detected for law_id in item["lawIds"]))
    laws_by_id = law_map()
    citations = [laws_by_id[law_id] for law_id in law_ids if law_id in laws_by_id]
    citation_coverage = round(sum(1 for item in detected if item["lawItems"]) / len(detected) * 100) if detected else 100
    questions = [item.get("modelAction") or item["action"] for item in detected[:6]]
    questions.extend(f"核实：{item['detail']}" for item in review_items[:8])
    questions = list(dict.fromkeys(questions))[:14]
    if not questions:
        questions = ["请提供正式劳动合同文本并确认薪资、工时、社保和离职条款。"]
    evidence_lines = [f"- {item['title']}：{item.get('modelAction') or item['action']}" for item in detected[:8]]

    result.update({
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "riskHeadline": risk_headline,
        "riskDescription": risk_description,
        "citations": citations,
        "citationCoverage": citation_coverage,
        "questions": questions,
        "requiresHumanReview": bool(review_items),
        "complaintDraft": "\n".join([
            "劳动权益事项材料整理草稿",
            "",
            "一、诉求事项",
            "请求核对并依法处理下列合同风险：" + "、".join(item["title"] for item in detected) + "。"
            if detected else "当前材料不足以形成确定诉求，请先补充书面合同和用工事实。",
            "",
            "二、可提交证据",
            *(evidence_lines or ["- 保存 Offer、合同、岗位说明、考勤和工资记录。"]),
            "",
            "三、办理提示",
            "建议先与用人单位书面沟通；协商不成时，可向用工所在地劳动保障监察机构、人社部门或公共法律服务平台咨询。",
            "",
            "本系统用于竞赛展示、普法教育和材料整理，不替代专业法律意见。",
        ]),
    })


_PII_RULES = [
    (re.compile(r"1[3-9]\d{9}"), "[手机号]"),
    (re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), "[身份证号]"),
    (re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"), "[邮箱]"),
    (re.compile(r"(?<!\d)\d{16,19}(?!\d)"), "[银行卡号]"),
]
_PII_PLACEHOLDERS = {placeholder: pattern.pattern for pattern, placeholder in _PII_RULES}


def redact_pii(text: str) -> str:
    redacted = str(text or "")
    for pattern, placeholder in _PII_RULES:
        redacted = pattern.sub(placeholder, redacted)
    return redacted


def ground_model_clause(candidate: str, source_text: str) -> str | None:
    """Use the model's redacted clause to recover the exact source fragment."""
    candidate = str(candidate or "").strip()
    if not candidate:
        return None
    if candidate in source_text:
        return candidate
    parts = re.split(r"(\[手机号\]|\[身份证号\]|\[邮箱\]|\[银行卡号\])", candidate)
    regex = "".join(
        f"(?:{_PII_PLACEHOLDERS[part]})" if part in _PII_PLACEHOLDERS else re.escape(part)
        for part in parts
    )
    matched = re.search(regex, source_text)
    return matched.group(0) if matched else None


def enhance_with_llm(result: dict) -> dict:
    api_url = os.environ.get("LLM_API_URL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    if not api_url or not api_key or not model:
        result["engine"] = "rules+semantic+retrieval"
        return result

    allowed_ids = [risk["id"] for risk in RISKS]
    compact_risks = []
    for item in result["risks"]:
        compact_risks.append({
            "id": item["id"],
            "clause": redact_pii(item["clause"]),
            "lawItems": [{"source": law["source"], "summary": law["summary"]} for law in item["lawItems"]],
        })

    system_prompt = (
        "你是就业合同候选风险识别器。只能从允许的风险ID中选择，不得创造新ID。"
        "只有原文明确支持时才提出风险；信息不足时不要猜测。"
        "文档可能为中文、英文或日文，但解释和行动建议统一用中文。返回严格 JSON："
        '{"items":[{"id":"风险ID","clause":"原文片段","reason":"不超过120字",'
        '"action":"不超过120字","confidence":0.0}]}。'
    )
    user_payload = {
        "allowedRiskIds": allowed_ids,
        "currentRisks": compact_risks,
        "documentLanguage": result.get("documentLanguage", "zh"),
        "documentText": redact_pii(result.get("inputText", "")[:15000]),
    }
    body = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    }
    request = urllib.request.Request(
        api_url,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        enhanced = extract_json_object(content)
        risk_by_id = {risk["id"]: risk for risk in RISKS}
        laws_by_id = law_map()
        existing = {risk["id"]: risk for risk in result["risks"]}
        input_text = result.get("inputText", "")

        for update in enhanced.get("items", []):
            risk_id = update.get("id")
            clause = ground_model_clause(str(update.get("clause", "")), input_text)
            if risk_id not in risk_by_id or not clause:
                continue
            try:
                model_confidence = float(update.get("confidence", 0))
            except (TypeError, ValueError):
                model_confidence = 0
            if model_confidence < 0.55:
                continue

            if risk_id in existing:
                risk = existing[risk_id]
            else:
                base = risk_by_id[risk_id]
                risk = dict(base)
                risk["clause"] = clause
                risk["matchText"] = clause
                risk["lawItems"] = retrieve_laws(clause, base["lawIds"], laws_by_id, 4)
                risk["detectionMode"] = "llm_candidate"
                risk["confidence"] = min(float(base["confidence"]), model_confidence)
                result["risks"].append(risk)
                existing[risk_id] = risk

            if update.get("reason"):
                risk["modelReason"] = redact_pii(str(update["reason"]))[:240]
            if update.get("action"):
                risk["modelAction"] = redact_pii(str(update["action"]))[:240]

        result["engine"] = "rules+semantic+retrieval+llm"
        result["trace"].append({
            "title": "大模型候选风险召回",
            "detail": f"模型 {model} 可在允许的风险ID内提出有原文依据的候选；无原文命中、低置信度或非法ID将被丢弃。",
        })
        recompute_after_enhancement(result)
    except (KeyError, ValueError, json.JSONDecodeError, urllib.error.URLError, TimeoutError) as exc:
        result["engine"] = "rules+semantic+retrieval+llm-fallback"
        result["trace"].append({
            "title": "模型调用降级",
            "detail": f"模型服务不可用或返回格式异常，系统已保留规则与语义结果。原因：{type(exc).__name__}。",
        })
    return result


def _prune_attempts(bucket: dict[str, list[float]], key: str, window: int) -> list[float]:
    now = time.time()
    attempts = [stamp for stamp in bucket.get(key, []) if now - stamp < window]
    if attempts:
        bucket[key] = attempts
    else:
        bucket.pop(key, None)
    return attempts


def register_rate_limited(client_ip: str) -> bool:
    with _rate_lock:
        attempts = _prune_attempts(_register_attempts, client_ip, REGISTER_WINDOW_SECONDS)
        if len(attempts) >= REGISTER_LIMIT:
            return True
        bucket = _register_attempts.setdefault(client_ip, [])
        bucket.append(time.time())
        return False


def login_rate_limited(client_ip: str, username: str) -> bool:
    key = f"{client_ip}|{username.strip().lower()}"
    with _rate_lock:
        return len(_prune_attempts(_login_failures, key, LOGIN_WINDOW_SECONDS)) >= LOGIN_FAILURE_LIMIT


def record_login_failure(client_ip: str, username: str) -> None:
    key = f"{client_ip}|{username.strip().lower()}"
    with _rate_lock:
        _login_failures.setdefault(key, []).append(time.time())


def clear_login_failures(client_ip: str, username: str) -> None:
    key = f"{client_ip}|{username.strip().lower()}"
    with _rate_lock:
        _login_failures.pop(key, None)


def get_user_record(user_id: int) -> dict | None:
    with auth_db() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def verify_user_password(user_id: int, password: str) -> bool:
    row = get_user_record(user_id)
    if not row:
        return False
    _, digest = hash_password(password, row["salt"])
    return secrets.compare_digest(digest, row["password_hash"])


def set_user_password(user_id: int, password: str) -> None:
    if len(password) < 10:
        raise ValueError("密码至少10位")
    salt, digest = hash_password(password)
    with auth_db() as connection:
        connection.execute(
            "UPDATE users SET salt = ?, password_hash = ?, updated_at = ? WHERE id = ?",
            (salt, digest, datetime.now().isoformat(timespec="seconds"), user_id),
        )
        remove_user_sessions(connection, user_id)
        connection.commit()


def active_admin_count(connection: sqlite3.Connection | None = None) -> int:
    if connection is not None:
        return int(connection.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'").fetchone()[0])
    with auth_db() as local:
        return int(local.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'").fetchone()[0])


def evidence_rows_for_user(user_id: int) -> list[dict]:
    with auth_db() as connection:
        rows = connection.execute(
            "SELECT * FROM evidence_files WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def remove_files(paths: list[str]) -> None:
    for raw_path in paths:
        try:
            Path(raw_path).resolve().unlink(missing_ok=True)
        except OSError:
            continue


def delete_case_data(user_id: int, case_id: int) -> bool:
    with auth_db() as connection:
        row = connection.execute("SELECT id FROM cases WHERE id = ? AND user_id = ?", (case_id, user_id)).fetchone()
        if not row:
            return False
        paths = [item["storage_path"] for item in connection.execute(
            "SELECT storage_path FROM evidence_files WHERE case_id = ? AND user_id = ?",
            (case_id, user_id),
        ).fetchall()]
        connection.execute("DELETE FROM evidence_files WHERE case_id = ? AND user_id = ?", (case_id, user_id))
        connection.execute("DELETE FROM cases WHERE id = ? AND user_id = ?", (case_id, user_id))
        connection.commit()
    remove_files(paths)
    return True


def delete_user_data(user_id: int) -> list[str]:
    with auth_db() as connection:
        paths = [item["storage_path"] for item in connection.execute(
            "SELECT storage_path FROM evidence_files WHERE user_id = ?",
            (user_id,),
        ).fetchall()]
        connection.execute("DELETE FROM evidence_files WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM cases WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()
    return paths


def build_user_export(user_id: int) -> dict:
    user = get_user_record(user_id)
    if not user:
        raise ValueError("用户不存在")
    safe_user = {key: user.get(key) for key in ("id", "username", "role", "status", "email", "email_verified_at", "created_at", "last_login_at")}
    cases = []
    for item in list_user_cases(user_id):
        detail = get_case(user_id, int(item["id"]))
        if detail:
            cases.append(detail)
    with auth_db() as connection:
        audit_rows = connection.execute(
            "SELECT action, target_type, target_id, detail, created_at FROM audit_logs WHERE actor_user_id = ? ORDER BY id DESC LIMIT 500",
            (user_id,),
        ).fetchall()
    return {
        "exportVersion": "1.0",
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "user": safe_user,
        "cases": cases,
        "evidence": list_evidence(user_id),
        "sessions": list_sessions(user_id, None),
        "auditLogs": [dict(row) for row in audit_rows],
        "notice": "研判原文不长期保存；案例中的敏感字段已脱敏。证据原件请通过证据包下载。",
    }


def build_evidence_package(user_id: int) -> bytes:
    buffer = io.BytesIO()
    evidence = evidence_rows_for_user(user_id)
    user = get_user_record(user_id)
    manifest = build_user_export(user_id)
    manifest["evidence"] = [
        {key: value for key, value in row.items() if key != "storage_path"}
        for row in evidence
    ]
    manifest["evidenceChain"] = verify_evidence_chain(user_id)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        for row in evidence:
            source = Path(row["storage_path"])
            if not source.is_file():
                continue
            safe_name = re.sub(r"[^\w.\-\u4e00-\u9fa5]+", "_", row["filename"])[:120] or "evidence"
            archive.write(source, f"files/{row['id']:04d}-{safe_name}")
    return buffer.getvalue()


def validate_evidence_content(extension: str, data: bytes) -> None:
    signatures = {
        ".pdf": (b"%PDF-",),
        ".png": (b"\x89PNG\r\n\x1a\n",),
        ".jpg": (b"\xff\xd8\xff",),
        ".jpeg": (b"\xff\xd8\xff",),
        ".webp": (b"RIFF",),
        ".docx": (b"PK\x03\x04",),
        ".doc": (b"\xd0\xcf\x11\xe0",),
    }
    expected = signatures.get(extension)
    if expected and not any(data.startswith(item) for item in expected):
        raise ValueError("文件内容与扩展名不匹配")
    if extension in {".txt", ".eml", ".msg"} and b"\x00" in data[:4096]:
        raise ValueError("文本类证据包含二进制内容")


def build_report_pdf(user: dict, case: dict, evidence: list[dict]) -> bytes | None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    font_name = "STSong-Light"
    pdfmetrics.registerFont(UnicodeCIDFont(font_name))
    result = case.get("result") or {}
    facts = result.get("facts") or {}
    source_doc = result.get("sourceDocument") or {}
    stats = result.get("analysisStats") or {}
    reviews = result.get("reviewItems") or []
    risks = result.get("risks") or []
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"职安盾研判报告 VW-{int(case['id']):06d}",
        author="职安盾 VeriWork",
    )
    base = getSampleStyleSheet()
    title_style = ParagraphStyle("CJKTitle", parent=base["Title"], fontName=font_name, fontSize=18, leading=26, alignment=TA_CENTER, textColor=colors.HexColor("#0d5c63"))
    heading_style = ParagraphStyle("CJKHeading", parent=base["Heading2"], fontName=font_name, fontSize=13, leading=20, textColor=colors.HexColor("#0d5c63"), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle("CJKBody", parent=base["BodyText"], fontName=font_name, fontSize=9.5, leading=15, alignment=TA_LEFT)
    small_style = ParagraphStyle("CJKSmall", parent=body_style, fontSize=7.5, leading=11, textColor=colors.HexColor("#475569"), wordWrap="CJK")
    story = [
        Paragraph("职安盾 VeriWork 就业材料研判报告", title_style),
        Paragraph(f"报告编号：VW-{int(case['id']):06d}　生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}", body_style),
        Spacer(1, 8),
        Paragraph(f"用户：{html_escape(str(user.get('username', '')))}　识别材料：{html_escape(str(result.get('documentType') or case.get('case_type', '')))}　用户选择：{html_escape(str(case.get('case_type', '')))}", body_style),
        Paragraph(f"适用地区：{html_escape(str(case.get('jurisdiction', '')))}　建议地区：{html_escape(str(facts.get('suggestedJurisdiction') or '待核实'))}", body_style),
        Paragraph(f"风险等级：{html_escape(str(case.get('risk_level', '')))}　风险分：{int(case.get('risk_score') or 0)}　文档语言：{html_escape(str(case.get('document_language', '')))}", body_style),
        Paragraph("一、基本事实", heading_style),
    ]
    fact_data = [[Paragraph("项目", small_style), Paragraph("抽取结果", small_style)]]
    term_text = f"{facts.get('startDate') or '待核实'} 至 {facts.get('endDate') or '待核实'}"
    if facts.get("termDays") is not None:
        term_text += f"（约 {facts.get('termDays')} 天）"
    pay_text = "待核实"
    if facts.get("dailyPay"):
        pay_text = f"{facts.get('dailyPay')} 元/天；按8小时约 {facts.get('hourlyEquivalentAt8h')} 元/小时"
    elif facts.get("monthlyPay"):
        pay_text = f"{facts.get('monthlyPay')} 元/月"
    for label, value in [
        ("甲方/签约单位", facts.get("partyA")),
        ("学校", facts.get("school")),
        ("实际用工单位", facts.get("actualEmployer")),
        ("岗位/部门", facts.get("position")),
        ("工作地点", facts.get("workLocation") or facts.get("workCity")),
        ("期限", term_text),
        ("补贴/工资", pay_text),
        ("工时", facts.get("workHours") or "待核实"),
        ("发薪主体", facts.get("payer") or "待核实"),
        ("保险安排", "已识别：" + "、".join(facts.get("insuranceTerms") or []) if facts.get("hasAccidentInsurance") else "未识别到"),
        ("争议条款", "已识别" if facts.get("hasDisputeClause") else "未识别到"),
        ("岗位附件", "已识别" if facts.get("hasJobAttachment") else "未识别到"),
        ("学校签署", "已识别" if facts.get("hasSchoolSignature") else "未识别到"),
        ("原始文件", source_doc.get("filename") or "未记录"),
        ("文件哈希", source_doc.get("sha256") or "未记录"),
        ("文件信息", f"{source_doc.get('format') or '未知'} · {source_doc.get('pageCount') or '?'} 页 · {source_doc.get('chars') or '?'} 字" if source_doc else "未记录"),
    ]:
        fact_data.append([Paragraph(html_escape(str(label)), small_style), Paragraph(html_escape(str(value or "待核实")), small_style)])
    fact_table = Table(fact_data, colWidths=[38 * mm, 140 * mm], repeatRows=1)
    fact_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef4fb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([fact_table, Paragraph("二、风险结论", heading_style)])
    if not risks:
        story.append(Paragraph("本次研判未发现明确高风险条款，仍需核对合同主体、工资、工时、社保、保险和离职条款。", body_style))
    for index, item in enumerate(risks, 1):
        story.append(Paragraph(f"{index}. {html_escape(str(item.get('title', '风险项')))}（{html_escape(str(item.get('severity', '')))}）", body_style))
        location = item.get("location") or {}
        location_text = f"第{location.get('page') or 1}页 / {location.get('clause') or '未编号条款'}"
        mode_text = {"deterministic": "确定性规则", "fact": "结构化事实", "semantic": "语义规则", "llm_candidate": "大模型候选"}.get(str(item.get("detectionMode")), "规则")
        story.append(Paragraph(f"位置：{html_escape(location_text)}　来源：{html_escape(mode_text)}　置信度：{round(float(item.get('confidence') or 0) * 100)}%", small_style))
        clause_label = "事实依据" if item.get("detectionMode") == "fact" else "原文片段"
        story.append(Paragraph(f"{clause_label}：{html_escape(str(item.get('clause', '')))}", body_style))
        story.append(Paragraph(f"风险说明：{html_escape(str(item.get('modelReason') or item.get('reason') or ''))}", body_style))
        story.append(Paragraph(f"行动建议：{html_escape(str(item.get('modelAction') or item.get('action') or ''))}", body_style))
        story.append(Paragraph("法源依据：" + html_escape("；".join(str(law.get("source", "")) for law in item.get("lawItems", []))), body_style))
        story.append(Spacer(1, 5))
    story.append(Paragraph("三、待核实事项", heading_style))
    if reviews:
        for index, item in enumerate(reviews, 1):
            story.append(Paragraph(f"{index}. {html_escape(str(item.get('title', '待核实')))}（{html_escape(str(item.get('source', '规则')))}）", body_style))
            story.append(Paragraph(html_escape(str(item.get("detail", ""))), small_style))
    else:
        story.append(Paragraph("本次未生成额外待核实事项，仍建议由专业人员抽查实际管理、报酬和用工主体事实。", body_style))
    story.append(Paragraph("四、可信研判轨迹", heading_style))
    for item in result.get("trace") or []:
        story.append(Paragraph(f"• {html_escape(str(item.get('title', '')))}：{html_escape(str(item.get('detail', '')))}", body_style))
    story.append(Paragraph(
        f"研判来源统计：确定性规则 {int(stats.get('ruleHits') or 0)} 项；结构化事实 {int(stats.get('factHits') or 0)} 项；语义规则 {int(stats.get('semanticHits') or 0)} 项；大模型候选 {int(stats.get('modelCandidates') or 0)} 项；合计 {int(stats.get('totalRisks') or len(risks))} 项。",
        small_style,
    ))
    story.append(Paragraph("五、证据文件清单", heading_style))
    table_data = [[
        Paragraph("文件", small_style), Paragraph("字节", small_style),
        Paragraph("SHA-256", small_style), Paragraph("上传时间", small_style),
    ]]
    for item in evidence:
        table_data.append([
            Paragraph(html_escape(str(item["filename"])), small_style),
            Paragraph(str(int(item["size_bytes"])), small_style),
            Paragraph(html_escape(str(item["sha256"])), small_style),
            Paragraph(html_escape(str(item["created_at"])), small_style),
        ])
    if len(table_data) == 1:
        table_data.append([Paragraph("尚未上传证据文件", small_style), "", "", ""])
    table = Table(table_data, colWidths=[42 * mm, 17 * mm, 78 * mm, 36 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef4fb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([table, Paragraph("六、后续行动", heading_style)])
    questions = result.get("questions") or []
    if not questions:
        questions = ["请补充正式协议、岗位说明、考勤和报酬记录，并确认签约主体、实际用工主体和发薪主体。"]
    for item in questions:
        story.append(Paragraph(f"• {html_escape(str(item))}", body_style))
    story.extend([
        Spacer(1, 8),
        Paragraph(html_escape(REPORT_DISCLAIMER), small_style),
    ])
    doc.build(story)
    return buffer.getvalue()


def build_report_html(user: dict, case: dict, evidence: list[dict]) -> str:
    result = case.get("result") or {}
    facts = result.get("facts") or {}
    source_doc = result.get("sourceDocument") or {}
    stats = result.get("analysisStats") or {}
    risks = result.get("risks") or []
    reviews = result.get("reviewItems") or []
    trace = result.get("trace") or []
    questions = result.get("questions") or []

    def esc(value) -> str:
        return html_escape(str(value or ""))

    term_text = f"{facts.get('startDate') or '待核实'} 至 {facts.get('endDate') or '待核实'}"
    if facts.get("termDays") is not None:
        term_text += f"（约 {facts.get('termDays')} 天）"
    pay_text = "待核实"
    if facts.get("dailyPay"):
        pay_text = f"{facts.get('dailyPay')} 元/天；按8小时约 {facts.get('hourlyEquivalentAt8h')} 元/小时"
    elif facts.get("monthlyPay"):
        pay_text = f"{facts.get('monthlyPay')} 元/月"
    fact_rows = [
        ("甲方 / 签约单位", facts.get("partyA")),
        ("学校", facts.get("school")),
        ("实际用工单位", facts.get("actualEmployer")),
        ("岗位 / 部门", facts.get("position")),
        ("工作地点", facts.get("workLocation") or facts.get("workCity")),
        ("期限", term_text),
        ("补贴 / 工资", pay_text),
        ("工时", facts.get("workHours")),
        ("发薪主体", facts.get("payer")),
        ("保险安排", "已识别：" + "、".join(facts.get("insuranceTerms") or []) if facts.get("hasAccidentInsurance") else "未识别到"),
        ("争议条款", "已识别" if facts.get("hasDisputeClause") else "未识别到"),
        ("岗位附件", "已识别" if facts.get("hasJobAttachment") else "未识别到"),
        ("学校签署", "已识别" if facts.get("hasSchoolSignature") else "未识别到"),
        ("原始文件", source_doc.get("filename")),
        ("文件哈希", source_doc.get("sha256")),
        ("文件信息", f"{source_doc.get('format') or '未知'} · {source_doc.get('pageCount') or '?'} 页 · {source_doc.get('chars') or '?'} 字" if source_doc else ""),
    ]
    fact_html = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value or '待核实')}</td></tr>"
        for label, value in fact_rows
    )
    mode_names = {"deterministic": "确定性规则", "fact": "结构化事实", "semantic": "语义规则", "llm_candidate": "大模型候选"}
    risk_cards = "".join(
        f"""<article class="risk {esc(item.get('severity', 'low'))}">
        <div class="risk-head"><h3>{esc(item.get('title', '风险项'))}</h3><span>{esc(mode_names.get(str(item.get('detectionMode')), '规则'))}</span></div>
        <p class="risk-meta">位置：第{(item.get('location') or {}).get('page') or 1}页 / {esc((item.get('location') or {}).get('clause') or '未编号条款')}　分类：{esc(item.get('category'))}　置信度：{round(float(item.get('confidence') or 0) * 100)}%</p>
        <p><b>{'事实依据' if item.get('detectionMode') == 'fact' else '原文片段'}</b>{esc(item.get('clause'))}</p>
        <p><b>风险说明</b>{esc(item.get('modelReason') or item.get('reason'))}</p>
        <p><b>行动建议</b>{esc(item.get('modelAction') or item.get('action'))}</p>
        <p class="laws"><b>法源依据</b>{esc('；'.join(str(law.get('source', '')) for law in item.get('lawItems', [])))}</p>
        </article>"""
        for item in risks
    ) or "<p class=\"empty\">本次研判未发现明确高风险条款，仍需核对合同主体、工资、工时、社保、保险和离职条款。</p>"
    review_html = "".join(
        f"<li><strong>{esc(item.get('title', '待核实'))}</strong><span>{esc(item.get('source', '规则'))}</span><p>{esc(item.get('detail'))}</p></li>"
        for item in reviews
    ) or "<li><strong>未生成额外待核实事项</strong><p>仍建议由专业人员抽查实际管理、报酬和用工主体事实。</p></li>"
    trace_html = "".join(
        f"<li><b>{esc(item.get('title', ''))}</b><p>{esc(item.get('detail', ''))}</p></li>"
        for item in trace
    ) or "<li>该历史案例未保存完整轨迹。</li>"
    evidence_rows = "".join(
        f"<tr><td>{esc(item['filename'])}</td><td>{int(item['size_bytes'])}</td><td class=\"hash\">{esc(item['sha256'])}</td><td>{esc(item['created_at'])}</td></tr>"
        for item in evidence
    ) or "<tr><td colspan=\"4\">尚未上传证据文件</td></tr>"
    action_html = "".join(f"<li>{esc(item)}</li>" for item in questions) or "<li>请补充正式协议、岗位说明、考勤和报酬记录，并确认签约主体、实际用工主体和发薪主体。</li>"
    disclaimer = esc(REPORT_DISCLAIMER)
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>职安盾研判报告 VW-{int(case['id']):06d}</title>
<style>
@page{{size:A4;margin:16mm}}
*{{box-sizing:border-box}}
body{{margin:0;background:#eef1f4;color:#172033;font-family:"Noto Sans CJK SC","Microsoft YaHei",sans-serif;line-height:1.7}}
main{{max-width:980px;margin:28px auto;padding:46px 54px;background:#fff;box-shadow:0 12px 40px #16203318}}
header{{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #0d5c63}}
.brand{{font-size:12px;letter-spacing:.16em;color:#0d5c63;font-weight:700}}
h1{{margin:8px 0 6px;font-size:28px;line-height:1.3;font-family:Georgia,"Songti SC",serif;font-weight:600}}
.sub{{font-size:12px;color:#667085}}
.report-no{{min-width:190px;text-align:right;font-size:12px;color:#475569;line-height:1.9}}
.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;margin:24px 0 6px;background:#dbe2e9;border:1px solid #dbe2e9}}
.meta div{{padding:11px 14px;background:#f8fafb}}
.meta span{{display:block;color:#7a8696;font-size:10px;letter-spacing:.08em}}
.meta strong{{display:block;margin-top:3px;font-size:13px;font-weight:600}}
.score{{font-size:26px;line-height:1.2;color:#a3342b}}
h2{{margin:34px 0 12px;padding-left:11px;border-left:4px solid #0d5c63;font-size:18px;font-family:Georgia,"Songti SC",serif;font-weight:600}}
h3{{margin:0;font-size:15px}}
.stats{{display:flex;flex-wrap:wrap;gap:7px;margin:12px 0 4px}}
.stats span{{padding:4px 9px;border:1px solid #d8e0e8;border-radius:2px;background:#f8fafb;color:#435267;font-size:10px}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th,td{{padding:8px 9px;border:1px solid #dbe2e9;vertical-align:top;text-align:left}}
thead th{{background:#eef4f5;color:#274b4f;font-weight:600}}
tbody th{{width:132px;background:#f8fafb;color:#526173;font-weight:500}}
.hash{{font-family:Consolas,monospace;font-size:10px;word-break:break-all}}
.risk{{margin:12px 0;padding:15px 17px;border:1px solid #dbe2e9;border-left:4px solid #2e90fa;break-inside:avoid}}
.risk.high{{border-left-color:#b42318}}
.risk.medium{{border-left-color:#d97706}}
.risk.low{{border-left-color:#15803d}}
.risk-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}
.risk-head span{{flex:0 0 auto;padding:2px 7px;background:#eef4f5;color:#315b60;font-size:9px}}
.risk p{{margin:7px 0 0;font-size:12px;line-height:1.75}}
.risk p b{{display:inline-block;min-width:68px;margin-right:8px;color:#526173;font-weight:600}}
.risk-meta{{color:#667085;font-size:10.5px!important}}
.risk .laws{{padding-top:7px;border-top:1px dashed #dbe2e9;color:#435267}}
.reviews{{margin:0;padding:0;list-style:none;counter-reset:review}}
.reviews li{{position:relative;margin:9px 0;padding:12px 14px 12px 42px;border:1px solid #e3e8ee;background:#fbfcfd;break-inside:avoid}}
.reviews li::before{{counter-increment:review;content:counter(review);position:absolute;left:14px;top:13px;width:19px;height:19px;border-radius:50%;background:#0d5c63;color:#fff;font-size:10px;text-align:center;line-height:19px}}
.reviews li span{{margin-left:8px;padding:1px 6px;background:#eef4f5;color:#526173;font-size:9px}}
.reviews li p{{margin:5px 0 0;color:#526173;font-size:11.5px}}
.trace{{margin:0;padding:0;list-style:none;border-left:1px solid #cfd8e2}}
.trace li{{position:relative;margin:0 0 13px;padding-left:20px}}
.trace li::before{{content:"";position:absolute;left:-4px;top:6px;width:7px;height:7px;border-radius:50%;background:#0d5c63}}
.trace b{{font-size:12px}}
.trace p{{margin:2px 0 0;color:#5b6878;font-size:11px}}
.actions{{margin:0;padding-left:20px;font-size:12px}}
.actions li{{margin:6px 0}}
.empty{{color:#667085;font-size:12px}}
.disclaimer{{margin-top:30px;padding:13px 15px;border:1px solid #ead9a9;background:#fffaf0;color:#6b5b35;font-size:11px}}
.toolbar{{position:fixed;right:24px;top:20px}}
button{{padding:10px 16px;border:0;background:#0d5c63;color:#fff;cursor:pointer;font-size:12px}}
@media(max-width:760px){{main{{margin:0;padding:22px 14px;box-shadow:none}}.meta{{grid-template-columns:1fr 1fr}}header{{display:block}}.report-no{{margin-top:12px;text-align:left}}table{{table-layout:fixed;width:100%}}th,td{{padding:6px;word-break:break-word;overflow-wrap:anywhere}}tbody th{{width:92px}}.risk-head{{display:block}}.risk-head span{{display:inline-block;margin-top:6px}}.risk p b{{display:block;min-width:0;margin-right:0}}.stats span{{font-size:9px}}}}
@media print{{body{{background:#fff}}main{{margin:0;padding:0;box-shadow:none;max-width:none}}.toolbar{{display:none}}.risk,.reviews li{{break-inside:avoid}}}}
</style></head><body>
<div class="toolbar"><button onclick="window.print()">打印 / 另存为 PDF</button></div>
<main>
<header><div><div class="brand">VERIWORK · 职安盾</div><h1>就业材料研判报告</h1><div class="sub">规则校验 · 法源检索 · 事实抽取 · 人工复核</div></div><div class="report-no">报告编号：VW-{int(case['id']):06d}<br>生成时间：{esc(datetime.now().strftime('%Y-%m-%d %H:%M'))}</div></header>
<section class="meta">
<div><span>用户</span><strong>{esc(user.get('username'))}</strong></div>
<div><span>识别材料</span><strong>{esc(result.get('documentType') or case.get('case_type'))}</strong></div>
<div><span>用户选择</span><strong>{esc(case.get('case_type'))}</strong></div>
<div><span>适用地区</span><strong>{esc(case.get('jurisdiction'))}</strong></div>
<div><span>建议地区</span><strong>{esc(facts.get('suggestedJurisdiction') or '待核实')}</strong></div>
<div><span>风险等级</span><strong>{esc(case.get('risk_level'))}</strong></div>
<div><span>风险分</span><strong class="score">{int(case.get('risk_score') or 0)}</strong></div>
<div><span>文档语言</span><strong>{esc(case.get('document_language'))}</strong></div>
<div><span>研判引擎</span><strong>{esc(result.get('engine') or 'rules+retrieval')}</strong></div>
</section>
<div class="stats"><span>确定性规则 {int(stats.get('ruleHits') or 0)}</span><span>结构化事实 {int(stats.get('factHits') or 0)}</span><span>语义规则 {int(stats.get('semanticHits') or 0)}</span><span>大模型候选 {int(stats.get('modelCandidates') or 0)}</span><span>合计 {int(stats.get('totalRisks') or len(risks))}</span></div>
<h2>一、基本事实</h2><table><tbody>{fact_html}</tbody></table>
<h2>二、风险结论</h2>{risk_cards}
<h2>三、待核实事项</h2><ol class="reviews">{review_html}</ol>
<h2>四、可信研判轨迹</h2><ul class="trace">{trace_html}</ul>
<h2>五、证据文件清单</h2><table><thead><tr><th>文件</th><th>字节</th><th>SHA-256</th><th>上传时间</th></tr></thead><tbody>{evidence_rows}</tbody></table>
<h2>六、后续行动</h2><ol class="actions">{action_html}</ol>
<div class="disclaimer">{disclaimer}</div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "VeriWork"
    sys_version = ""

    def common_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin and CORS_ORIGIN and secrets.compare_digest(origin, CORS_ORIGIN):
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def send_json(self, payload: dict, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.common_headers()
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin and not (CORS_ORIGIN and secrets.compare_digest(origin, CORS_ORIGIN)):
            self.send_json({"error": "origin_not_allowed"}, 403)
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.common_headers()
        if origin:
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def client_ip(self) -> str:
        real_ip = self.headers.get("X-Real-IP", "").strip()
        if real_ip:
            return real_ip[:64]
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            # Nginx appends the peer address. Taking the last value avoids a spoofed first hop.
            return forwarded.rsplit(",", 1)[-1].strip()[:64]
        return self.client_address[0]

    def session_token(self) -> str | None:
        raw_cookie = self.headers.get("Cookie", "")
        if raw_cookie:
            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
                morsel = cookie.get(SESSION_COOKIE_NAME)
                if morsel and morsel.value:
                    return morsel.value
            except Exception:  # noqa: BLE001 - 非法 Cookie 直接忽略
                pass
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return None

    def session_cookie(self, token: str | None, clear: bool = False) -> str:
        parts = [f"{SESSION_COOKIE_NAME}={token or ''}", f"Path={SESSION_COOKIE_PATH}", "HttpOnly", "SameSite=Lax"]
        if clear:
            parts.extend(["Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
        else:
            parts.append(f"Max-Age={SESSION_DAYS * 86400}")
        if SESSION_COOKIE_SECURE or self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip() == "https":
            parts.append("Secure")
        return "; ".join(parts)

    def current_user(self) -> dict | None:
        return resolve_session(self.session_token())

    def require_user(self) -> dict | None:
        user = self.current_user()
        if not user:
            self.send_json({"error": "请先登录后再使用研判和文件解析功能"}, 401)
            return None
        return user

    def read_json_body(self, max_body: int = MAX_BODY) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0 or content_length > max_body:
            raise ValueError("请求体为空或过大")
        body = json.loads(self.rfile.read(content_length).decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("请求体必须是JSON对象")
        return body

    def require_admin(self) -> dict | None:
        user = self.current_user()
        if not user or user.get("role") != "admin" or user.get("status") != "active":
            self.send_json({"error": "需要管理员权限"}, 403)
            return None
        return user

    def send_bytes(
        self,
        data: bytes,
        content_type: str,
        status: int = 200,
        filename: str = "",
        inline: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            disposition = "inline" if inline else "attachment"
            self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(filename)}")
        self.common_headers()
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def handle_auth(self, path: str) -> None:
        try:
            client_ip = self.client_ip()
            if path == "/api/auth/logout":
                user = self.current_user()
                revoke_session(self.session_token())
                if user:
                    audit_event(user["id"], "logout", "user", user["id"], "用户退出登录", client_ip)
                self.send_json({"ok": True}, extra_headers={"Set-Cookie": self.session_cookie(None, clear=True)})
                return

            body = self.read_json_body(MAX_AUTH_BODY)
            if path == "/api/auth/register":
                if register_rate_limited(client_ip):
                    self.send_json({"error": "注册过于频繁，请稍后再试"}, 429)
                    return
                user = register_user(
                    str(body.get("username", "")),
                    str(body.get("password", "")),
                    email=str(body.get("email", "")),
                )
                token = create_session(user["id"], self.headers.get("User-Agent", ""), client_ip)
                audit_event(user["id"], "register", "user", user["id"], "用户注册", client_ip)
                self.send_json({"user": user}, extra_headers={"Set-Cookie": self.session_cookie(token)})
                return
            if path == "/api/auth/login":
                username = str(body.get("username", "")).strip()
                if login_rate_limited(client_ip, username):
                    self.send_json({"error": "登录失败次数过多，请10分钟后再试"}, 429)
                    return
                user = authenticate_user(username, str(body.get("password", "")))
                if not user:
                    record_login_failure(client_ip, username)
                    self.send_json({"error": "用户名或密码错误"}, 401)
                    return
                if user.get("status") != "active":
                    self.send_json({"error": "账号已停用，请联系管理员"}, 403)
                    return
                if user.get("role") == "admin" and ADMIN_2FA_ENABLED and user.get("emailVerified") and smtp_configured():
                    try:
                        challenge_id, _ = send_auth_code(user, "admin_2fa", str(user.get("email", "")))
                    except Exception:
                        self.send_json({"error": "管理员验证码发送失败，请检查邮件服务"}, 503)
                        return
                    audit_event(user["id"], "admin_2fa_requested", "user", user["id"], "管理员登录验证码已发送", client_ip)
                    self.send_json({
                        "requires2fa": True,
                        "challengeId": challenge_id,
                        "emailHint": mask_email(str(user.get("email", ""))),
                    })
                    return
                clear_login_failures(client_ip, username)
                now = datetime.now().isoformat(timespec="seconds")
                with auth_db() as connection:
                    connection.execute("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", (now, now, user["id"]))
                    connection.commit()
                token = create_session(user["id"], self.headers.get("User-Agent", ""), client_ip)
                audit_event(user["id"], "login", "user", user["id"], "用户登录", client_ip)
                self.send_json({"user": user}, extra_headers={"Set-Cookie": self.session_cookie(token)})
                return
            if path == "/api/auth/verify-2fa":
                challenge_id = int(body.get("challengeId"))
                code = str(body.get("code", ""))
                user_id = verify_email_challenge(challenge_id, code, "admin_2fa")
                user = get_user_record(user_id)
                if not user or user.get("status") != "active":
                    self.send_json({"error": "账号不可用"}, 403)
                    return
                clear_login_failures(client_ip, user["username"])
                now = datetime.now().isoformat(timespec="seconds")
                with auth_db() as connection:
                    connection.execute("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", (now, now, user_id))
                    connection.commit()
                token = create_session(user_id, self.headers.get("User-Agent", ""), client_ip)
                audit_event(user_id, "admin_2fa_verified", "user", user_id, "管理员二次验证通过", client_ip)
                self.send_json({"user": user}, extra_headers={"Set-Cookie": self.session_cookie(token)})
                return
            if path == "/api/auth/request-password-reset":
                identifier = str(body.get("identifier", "")).strip()
                delivery = False
                with auth_db() as connection:
                    row = connection.execute(
                        "SELECT * FROM users WHERE (username = ? OR lower(email) = lower(?)) AND status = 'active' LIMIT 1",
                        (identifier, identifier),
                    ).fetchone()
                if row and row["email"] and row["email_verified_at"] and smtp_configured():
                    try:
                        send_auth_code(dict(row), "reset_password", str(row["email"]))
                        delivery = True
                    except Exception:
                        delivery = False
                self.send_json({"ok": True, "deliveryAvailable": delivery, "message": "如果账号存在且已绑定邮箱，验证码将发送到该邮箱。"})
                return
            if path == "/api/auth/reset-password":
                identifier = str(body.get("identifier", "")).strip()
                code = str(body.get("code", ""))
                new_password = str(body.get("newPassword", ""))
                with auth_db() as connection:
                    row = connection.execute(
                        "SELECT * FROM users WHERE (username = ? OR lower(email) = lower(?)) AND status = 'active' LIMIT 1",
                        (identifier, identifier),
                    ).fetchone()
                if not row or not row["email_verified_at"]:
                    raise ValueError("账号不存在或未绑定已验证邮箱")
                challenge = latest_email_challenge(int(row["id"]), "reset_password")
                if not challenge:
                    raise ValueError("请先获取密码重置验证码")
                verify_email_challenge(int(challenge["id"]), code, "reset_password", int(row["id"]))
                set_user_password(int(row["id"]), new_password)
                audit_event(int(row["id"]), "reset_password", "user", int(row["id"]), "通过邮箱验证码重置密码", client_ip)
                self.send_json({"ok": True})
                return
            if path == "/api/auth/set-email":
                user = self.require_user()
                if not user:
                    return
                email = normalize_email(str(body.get("email", "")))
                with auth_db() as connection:
                    duplicate = connection.execute(
                        "SELECT id FROM users WHERE lower(email) = lower(?) AND id != ? LIMIT 1",
                        (email, user["id"]),
                    ).fetchone()
                    if duplicate:
                        raise ValueError("该邮箱已被其他账号使用")
                    connection.execute("UPDATE users SET email = ?, email_verified_at = NULL, updated_at = ? WHERE id = ?", (email, datetime.now().isoformat(timespec="seconds"), user["id"]))
                    connection.commit()
                try:
                    challenge_id, _ = send_auth_code(user, "verify_email", email)
                except Exception:
                    with auth_db() as connection:
                        connection.execute("UPDATE users SET email = NULL, email_verified_at = NULL WHERE id = ?", (user["id"],))
                        connection.commit()
                    self.send_json({"error": "验证码发送失败，请检查邮件服务"}, 503)
                    return
                audit_event(user["id"], "email_binding_requested", "user", user["id"], mask_email(email), client_ip)
                self.send_json({"ok": True, "challengeId": challenge_id, "emailHint": mask_email(email)})
                return
            if path == "/api/auth/verify-email":
                user = self.require_user()
                if not user:
                    return
                challenge_id = int(body.get("challengeId"))
                verify_email_challenge(challenge_id, str(body.get("code", "")), "verify_email", int(user["id"]))
                now = datetime.now().isoformat(timespec="seconds")
                with auth_db() as connection:
                    connection.execute("UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?", (now, now, user["id"]))
                    connection.commit()
                audit_event(user["id"], "email_verified", "user", user["id"], "邮箱验证完成", client_ip)
                self.send_json({"ok": True})
                return
            if path == "/api/auth/change-password":
                user = self.require_user()
                if not user:
                    return
                current_password = str(body.get("currentPassword", ""))
                new_password = str(body.get("newPassword", ""))
                if not verify_user_password(user["id"], current_password):
                    self.send_json({"error": "当前密码不正确"}, 400)
                    return
                set_user_password(user["id"], new_password)
                token = create_session(user["id"], self.headers.get("User-Agent", ""), client_ip)
                audit_event(user["id"], "change_password", "user", user["id"], "修改密码并退出其他设备", client_ip)
                self.send_json({"ok": True}, extra_headers={"Set-Cookie": self.session_cookie(token)})
                return
            if path == "/api/auth/revoke-sessions":
                user = self.require_user()
                if not user:
                    return
                token = self.session_token()
                with auth_db() as connection:
                    remove_user_sessions(connection, user["id"], keep_token=token)
                    connection.commit()
                audit_event(user["id"], "revoke_sessions", "user", user["id"], "退出其他登录设备", client_ip)
                self.send_json({"ok": True})
                return
            if path == "/api/auth/export":
                user = self.require_user()
                if not user:
                    return
                if not verify_user_password(user["id"], str(body.get("password", ""))):
                    self.send_json({"error": "密码不正确，无法导出个人数据"}, 400)
                    return
                audit_event(user["id"], "export_data", "user", user["id"], "导出个人数据", client_ip)
                self.send_json(build_user_export(user["id"]))
                return
            if path == "/api/auth/delete":
                user = self.require_user()
                if not user:
                    return
                if str(body.get("confirm", "")) != user["username"]:
                    self.send_json({"error": "请输入当前用户名以确认删除"}, 400)
                    return
                if not verify_user_password(user["id"], str(body.get("password", ""))):
                    self.send_json({"error": "密码不正确，无法删除账号"}, 400)
                    return
                audit_event(user["id"], "delete_account", "user", user["id"], "用户删除账号及全部数据", client_ip)
                paths = delete_user_data(user["id"])
                remove_files(paths)
                self.send_json(
                    {"ok": True},
                    extra_headers={"Set-Cookie": self.session_cookie(None, clear=True)},
                )
                return
            self.send_json({"error": "not_found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": f"认证失败：{type(exc).__name__}"}, 500)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/me":
            user = self.current_user()
            self.send_json({"authenticated": bool(user), "user": user})
            return
        if parsed.path == "/api/health":
            self.send_json(health_payload())
            return
        if parsed.path == "/api/laws":
            self.send_json({"laws": LAWS})
            return
        if not parsed.path.startswith("/api/"):
            self.serve_static(parsed.path)
            return

        user = self.require_user()
        if not user:
            return

        if parsed.path == "/api/auth/sessions":
            self.send_json({"sessions": list_sessions(user["id"], self.session_token())})
            return
        if parsed.path == "/api/admin/stats":
            if user.get("role") != "admin":
                self.send_json({"error": "需要管理员权限"}, 403)
                return
            self.send_json(admin_stats())
            return
        if parsed.path == "/api/cases":
            self.send_json({"cases": list_user_cases(user["id"])})
            return
        case_match = re.fullmatch(r"/api/cases/(\d+)", parsed.path)
        if case_match:
            case = get_case(user["id"], int(case_match.group(1)), allow_admin=user.get("role") == "admin")
            if not case:
                self.send_json({"error": "案例不存在"}, 404)
                return
            self.send_json({"case": case})
            return
        pdf_match = re.fullmatch(r"/api/cases/(\d+)/report\.pdf", parsed.path)
        if pdf_match:
            case = get_case(user["id"], int(pdf_match.group(1)), allow_admin=user.get("role") == "admin")
            if not case:
                self.send_json({"error": "案例不存在"}, 404)
                return
            evidence = [item for item in list_evidence(int(case["user_id"])) if item.get("case_id") == case["id"]]
            target_user = get_user_record(int(case["user_id"])) or user
            pdf = build_report_pdf(target_user, case, evidence)
            if not pdf:
                self.send_json({"error": "PDF组件未安装，请使用打印版另存为PDF"}, 501)
                return
            audit_event(user["id"], "download_report_pdf", "case", case["id"], "下载PDF研判报告", self.client_ip())
            self.send_bytes(pdf, "application/pdf", filename=f"职安盾-研判报告-VW-{int(case['id']):06d}.pdf")
            return
        report_match = re.fullmatch(r"/api/cases/(\d+)/report", parsed.path)
        if report_match:
            case = get_case(user["id"], int(report_match.group(1)), allow_admin=user.get("role") == "admin")
            if not case:
                self.send_json({"error": "案例不存在"}, 404)
                return
            evidence = [item for item in list_evidence(int(case["user_id"])) if item.get("case_id") == case["id"]]
            target_user = get_user_record(int(case["user_id"])) or user
            html = build_report_html(target_user, case, evidence)
            self.send_bytes(
                html.encode("utf-8"),
                "text/html; charset=utf-8",
                filename=f"职安盾-研判报告-VW-{int(case['id']):06d}.html",
                inline=True,
                extra_headers={
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'",
                },
            )
            return
        if parsed.path == "/api/evidence":
            self.send_json({"evidence": list_evidence(user["id"])})
            return
        if parsed.path == "/api/evidence/verify":
            result = verify_evidence_chain(user["id"])
            audit_event(user["id"], "verify_evidence_chain", "user", user["id"], f"valid={result['valid']}", self.client_ip())
            self.send_json(result)
            return
        if parsed.path == "/api/evidence/package":
            package = build_evidence_package(user["id"])
            audit_event(user["id"], "export_evidence_package", "user", user["id"], "下载证据包", self.client_ip())
            self.send_bytes(
                package,
                "application/zip",
                filename=f"职安盾-证据包-{datetime.now().strftime('%Y%m%d')}.zip",
            )
            return
        evidence_match = re.fullmatch(r"/api/evidence/(\d+)/download", parsed.path)
        if evidence_match:
            evidence_id = int(evidence_match.group(1))
            row = next((item for item in evidence_rows_for_user(user["id"]) if int(item["id"]) == evidence_id), None)
            if not row:
                self.send_json({"error": "证据文件不存在"}, 404)
                return
            source = Path(row["storage_path"])
            if not source.is_file():
                self.send_json({"error": "证据原件已丢失，请重新上传"}, 404)
                return
            content = source.read_bytes()
            actual_sha = hashlib.sha256(content).hexdigest()
            expected_record = evidence_record_hash(
                row["previous_hash"] or "",
                int(row["user_id"]),
                row["sha256"],
                int(row["size_bytes"]),
                row["filename"],
                row["created_at"],
            )
            if actual_sha != row["sha256"] or expected_record != row["record_hash"]:
                self.send_json({"error": "证据完整性校验失败，文件可能被篡改"}, 409)
                return
            add_custody_event(user["id"], evidence_id, "downloaded", actual_sha, row["record_hash"], row["filename"])
            audit_event(user["id"], "download_evidence", "evidence", evidence_id, row["filename"], self.client_ip())
            self.send_bytes(content, row["content_type"], filename=row["filename"], extra_headers={"X-Evidence-SHA256": actual_sha})
            return
        self.send_json({"error": "not_found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/auth/"):
            self.handle_auth(parsed.path)
            return
        if parsed.path == "/api/extract":
            self.handle_extract()
            return

        if parsed.path.startswith("/api/admin/"):
            admin = self.require_admin()
            if not admin:
                return
            try:
                body = self.read_json_body(MAX_AUTH_BODY)
                if parsed.path == "/api/admin/set-role":
                    target = int(body.get("user_id"))
                    role = str(body.get("role", "student"))
                    if role not in {"student", "admin"}:
                        raise ValueError("角色只能是 student 或 admin")
                    with auth_db() as connection:
                        row = connection.execute("SELECT * FROM users WHERE id = ?", (target,)).fetchone()
                        if not row:
                            raise ValueError("用户不存在")
                        if target == admin["id"] and role != "admin":
                            raise ValueError("不能取消自己的管理员角色")
                        if row["role"] == "admin" and role != "admin" and active_admin_count(connection) <= 1:
                            raise ValueError("必须保留至少一名可用管理员")
                        now = datetime.now().isoformat(timespec="seconds")
                        connection.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", (role, now, target))
                        connection.commit()
                    audit_event(admin["id"], "admin_set_role", "user", target, f"角色调整为 {role}", self.client_ip())
                    self.send_json({"ok": True})
                    return
                if parsed.path == "/api/admin/set-status":
                    target = int(body.get("user_id"))
                    status = str(body.get("status", "active"))
                    if status not in {"active", "disabled"}:
                        raise ValueError("账号状态只能是 active 或 disabled")
                    if target == admin["id"] and status == "disabled":
                        raise ValueError("不能停用自己的管理员账号")
                    with auth_db() as connection:
                        row = connection.execute("SELECT * FROM users WHERE id = ?", (target,)).fetchone()
                        if not row:
                            raise ValueError("用户不存在")
                        if row["role"] == "admin" and row["status"] == "active" and status == "disabled" and active_admin_count(connection) <= 1:
                            raise ValueError("必须保留至少一名可用管理员")
                        now = datetime.now().isoformat(timespec="seconds")
                        connection.execute("UPDATE users SET status = ?, updated_at = ? WHERE id = ?", (status, now, target))
                        if status == "disabled":
                            remove_user_sessions(connection, target)
                        connection.commit()
                    audit_event(admin["id"], "admin_set_status", "user", target, f"账号状态调整为 {status}", self.client_ip())
                    self.send_json({"ok": True})
                    return
                if parsed.path == "/api/admin/reset-password":
                    target = int(body.get("user_id"))
                    if not get_user_record(target):
                        raise ValueError("用户不存在")
                    temporary_password = secrets.token_urlsafe(12)
                    set_user_password(target, temporary_password)
                    audit_event(admin["id"], "admin_reset_password", "user", target, "管理员重置密码并注销该用户全部会话", self.client_ip())
                    self.send_json({"ok": True, "temporaryPassword": temporary_password})
                    return
                if parsed.path == "/api/admin/delete-user":
                    target = int(body.get("user_id"))
                    if target == admin["id"]:
                        raise ValueError("不能删除自己的管理员账号")
                    with auth_db() as connection:
                        row = connection.execute("SELECT * FROM users WHERE id = ?", (target,)).fetchone()
                        if not row:
                            raise ValueError("用户不存在")
                        if row["role"] == "admin" and row["status"] == "active" and active_admin_count(connection) <= 1:
                            raise ValueError("必须保留至少一名可用管理员")
                    audit_event(admin["id"], "admin_delete_user", "user", target, f"删除用户 {row['username']}", self.client_ip())
                    paths = delete_user_data(target)
                    remove_files(paths)
                    self.send_json({"ok": True})
                    return
                self.send_json({"error": "not_found"}, 404)
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                self.send_json({"error": f"管理员操作失败：{type(exc).__name__}"}, 500)
            return

        user = self.require_user()
        if not user:
            return

        try:
            if parsed.path == "/api/cases/status":
                body = self.read_json_body(MAX_AUTH_BODY)
                case_id = int(body.get("case_id"))
                status = str(body.get("status", "active"))
                if status not in {"active", "following", "resolved", "archived"}:
                    raise ValueError("案例状态无效")
                with auth_db() as connection:
                    cursor = connection.execute(
                        "UPDATE cases SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                        (status, datetime.now().isoformat(timespec="seconds"), case_id, user["id"]),
                    )
                    connection.commit()
                if cursor.rowcount != 1:
                    self.send_json({"error": "案例不存在"}, 404)
                    return
                audit_event(user["id"], "update_case_status", "case", case_id, status, self.client_ip())
                self.send_json({"ok": True})
                return
            if parsed.path == "/api/cases/delete":
                body = self.read_json_body(MAX_AUTH_BODY)
                case_id = int(body.get("case_id"))
                if not delete_case_data(user["id"], case_id):
                    self.send_json({"error": "案例不存在"}, 404)
                    return
                audit_event(user["id"], "delete_case", "case", case_id, "删除案例及关联证据", self.client_ip())
                self.send_json({"ok": True})
                return
            if parsed.path == "/api/evidence/upload":
                body = self.read_json_body(MAX_BODY)
                filename = Path(str(body.get("filename", ""))).name
                if not filename or len(filename) > 180:
                    raise ValueError("文件名无效")
                extension = Path(filename).suffix.lower()
                allowed = {".pdf", ".doc", ".docx", ".png", ".jpg", ".jpeg", ".webp", ".txt", ".eml", ".msg"}
                if extension not in allowed:
                    raise ValueError("仅支持PDF、Word、图片、TXT和邮件文件")
                encoded = str(body.get("content_base64", ""))
                if not encoded:
                    raise ValueError("缺少文件内容")
                data = base64.b64decode(encoded, validate=True)
                if not data or len(data) > MAX_EVIDENCE_BYTES:
                    raise ValueError(f"证据文件需小于{MAX_EVIDENCE_BYTES // 1024 // 1024}MB")
                validate_evidence_content(extension, data)
                case_id = body.get("caseId")
                if case_id:
                    case_id = int(case_id)
                    if not get_case(user["id"], case_id):
                        raise ValueError("关联案例不存在")
                else:
                    case_id = None
                digest = hashlib.sha256(data).hexdigest()
                storage_name = f"u{user['id']}-{secrets.token_hex(16)}{extension}"
                storage_path = EVIDENCE_DIR / storage_name
                storage_path.write_bytes(data)
                try:
                    scan_evidence_file(storage_path)
                    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                    created_at = datetime.now().isoformat(timespec="seconds")
                    with auth_db() as connection:
                        previous_row = connection.execute(
                            "SELECT record_hash FROM evidence_files WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                            (user["id"],),
                        ).fetchone()
                        previous_hash = previous_row["record_hash"] if previous_row and previous_row["record_hash"] else ""
                        record_hash = evidence_record_hash(previous_hash, int(user["id"]), digest, len(data), filename, created_at)
                        cursor = connection.execute(
                            """
                            INSERT INTO evidence_files(user_id, case_id, filename, content_type, size_bytes, sha256,
                                                       storage_path, previous_hash, record_hash, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (user["id"], case_id, filename, content_type, len(data), digest, str(storage_path), previous_hash, record_hash, created_at),
                        )
                        connection.commit()
                        evidence_id = int(cursor.lastrowid)
                except Exception:
                    storage_path.unlink(missing_ok=True)
                    raise
                add_custody_event(user["id"], evidence_id, "uploaded", digest, record_hash, filename)
                audit_event(user["id"], "upload_evidence", "evidence", evidence_id, filename, self.client_ip())
                self.send_json({"ok": True, "evidence": {
                    "id": evidence_id, "case_id": case_id, "filename": filename,
                    "content_type": content_type, "size_bytes": len(data),
                    "sha256": digest, "previous_hash": previous_hash, "record_hash": record_hash, "created_at": created_at,
                }})
                return
            if parsed.path == "/api/evidence/delete":
                body = self.read_json_body(MAX_AUTH_BODY)
                evidence_id = int(body.get("evidence_id"))
                with auth_db() as connection:
                    row = connection.execute("SELECT * FROM evidence_files WHERE id = ? AND user_id = ?", (evidence_id, user["id"])).fetchone()
                    if not row:
                        self.send_json({"error": "证据文件不存在"}, 404)
                        return
                    connection.execute("DELETE FROM evidence_files WHERE id = ? AND user_id = ?", (evidence_id, user["id"]))
                    connection.commit()
                add_custody_event(user["id"], evidence_id, "deleted", row["sha256"], row["record_hash"], row["filename"])
                remove_files([row["storage_path"]])
                audit_event(user["id"], "delete_evidence", "evidence", evidence_id, row["filename"], self.client_ip())
                self.send_json({"ok": True})
                return
            if parsed.path != "/api/analyze":
                self.send_json({"error": "not_found"}, 404)
                return

            body = self.read_json_body(MAX_BODY)
            text = str(body.get("text", "")).strip()
            if len(text) < 20:
                raise ValueError("文本过短")
            case_type = str(body.get("caseType", "劳动合同"))
            jurisdiction = str(body.get("jurisdiction", "全国规则"))
            language = str(body.get("language", "zh"))
            source_pages = body.get("sourcePages") if isinstance(body.get("sourcePages"), list) else []
            source_pages = [
                {"page": int(item.get("page", 1)), "text": str(item.get("text", ""))}
                for item in source_pages
                if isinstance(item, dict)
            ]
            raw_source_document = body.get("sourceDocument") if isinstance(body.get("sourceDocument"), dict) else {}
            source_document = {
                key: raw_source_document.get(key)
                for key in ("filename", "format", "chars", "sizeBytes", "sha256", "pageCount")
                if raw_source_document.get(key) not in (None, "")
            }
            result = deterministic_analysis(
                text=text,
                case_type=case_type,
                jurisdiction=jurisdiction,
                language=language,
                source_pages=source_pages,
                source_document=source_document,
            )
            result = enhance_with_llm(result)
            for risk in result.get("risks", []):
                if not risk.get("location"):
                    risk["location"] = locate_clause(str(risk.get("clause", "")), source_pages)
            stats = result.setdefault("analysisStats", {})
            stats["modelCandidates"] = sum(1 for risk in result.get("risks", []) if risk.get("detectionMode") == "llm_candidate")
            stats["totalRisks"] = len(result.get("risks", []))
            case_id = save_case_record(user, result, result["documentType"], jurisdiction, language)
            result["caseId"] = case_id
            audit_event(
                user["id"],
                "analyze_contract",
                "case",
                case_id,
                f"{result['documentType']} / {jurisdiction} / rules={result.get('analysisStats', {}).get('ruleHits', 0)}",
                self.client_ip(),
            )
            self.send_json(result)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001 - 本地服务需要返回可读错误
            self.send_json({"error": f"内部错误：{type(exc).__name__}"}, 500)

    def handle_extract(self) -> None:
        if not self.require_user():
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_BODY:
                raise ValueError("文件为空或超过12MB")
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            filename = str(body.get("filename", "document"))
            language = str(body.get("language", "zh"))
            page_range = str(body.get("pageRange", ""))
            encoded = str(body.get("content_base64", ""))
            if not encoded:
                raise ValueError("缺少文件内容")
            data = base64.b64decode(encoded, validate=True)
            self.send_json(extract_document(filename, data, language=language, page_range=page_range))
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": f"提取失败：{type(exc).__name__}"}, 500)

    def serve_static(self, request_path: str) -> None:
        relative = unquote(request_path).lstrip("/") or "index.html"
        public_files = {"index.html", "styles.css", "app.js", "data.js"}
        public_asset_suffixes = {".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".gif"}
        suffix = Path(relative).suffix.lower()
        allowed = relative in public_files or (relative.startswith("assets/") and suffix in public_asset_suffixes)
        if not allowed:
            self.send_error(404)
            return
        target = (BASE_DIR / relative).resolve()
        if BASE_DIR not in target.parents or not target.is_file():
            self.send_error(404)
            return

        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if suffix in {".html"} or relative == "index.html":
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
                "form-action 'self'; frame-ancestors 'self'",
            )
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))
        sys.stdout.flush()


def main() -> None:
    backfill_evidence_chain()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    llm_state = "已配置" if os.environ.get("LLM_API_URL") and os.environ.get("LLM_API_KEY") and os.environ.get("LLM_MODEL") else "未配置，使用本地规则链路"
    print("职安盾 VeriWork 已启动")
    print(f"地址: http://{HOST}:{PORT}")
    print(f"大模型: {llm_state}")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
