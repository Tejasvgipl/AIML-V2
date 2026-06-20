"""
CyberSentinel — Auth Microservice
===================================
JWT-based authentication, user management, and login audit.

Roles:
  admin  — full access + user management + audit log
  user   — full dashboard access, cannot manage users

Seed on first startup: Tejas / tejas@123  (admin)
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import clickhouse_connect
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET         = os.getenv("JWT_SECRET", "cs-jwt-secret-CHANGE-IN-PROD-2026")
JWT_ALG            = "HS256"
JWT_EXPIRE_HOURS   = int(os.getenv("JWT_EXPIRE_HOURS", "8"))

CH_HOST  = os.getenv("CLICKHOUSE_HOST", "clickhouse")
CH_PORT  = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CH_DB    = os.getenv("CLICKHOUSE_DB", "cybersentinel")
CH_USER  = os.getenv("CLICKHOUSE_USER", "default")
CH_PASS  = os.getenv("CLICKHOUSE_PASS", "tejas@123")

SEED_USER = os.getenv("SEED_ADMIN_USER", "Tejas")
SEED_PASS = os.getenv("SEED_ADMIN_PASS", "tejas@123")

# ── Crypto ────────────────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

app = FastAPI(title="CyberSentinel Auth", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── ClickHouse connection ─────────────────────────────────────────────────────
_ch: Optional[clickhouse_connect.driver.Client] = None

def ch():
    global _ch
    if _ch is None:
        _ch = clickhouse_connect.get_client(
            host=CH_HOST, port=CH_PORT, database=CH_DB,
            username=CH_USER, password=CH_PASS,
        )
    return _ch


# ── Schema bootstrap (idempotent) ─────────────────────────────────────────────
def _ensure_schema():
    c = ch()
    c.command("""
        CREATE TABLE IF NOT EXISTS cybersentinel.cs_users
        (
            id            String        DEFAULT toString(generateUUIDv4()),
            username      String,
            password_hash String,
            role          String        DEFAULT 'user',
            created_at    DateTime64(3) DEFAULT now64(3),
            created_by    String        DEFAULT '',
            is_active     UInt8         DEFAULT 1
        )
        ENGINE = ReplacingMergeTree(created_at)
        ORDER BY username
    """)
    c.command("""
        CREATE TABLE IF NOT EXISTS cybersentinel.cs_auth_audit
        (
            id         String        DEFAULT toString(generateUUIDv4()),
            username   String,
            action     String,
            client_ip  String        DEFAULT '',
            session_id String        DEFAULT '',
            ts         DateTime64(3) DEFAULT now64(3),
            extra      String        DEFAULT ''
        )
        ENGINE = MergeTree()
        ORDER BY (username, ts)
        TTL toDateTime(ts) + INTERVAL 90 DAY
    """)


def _seed_admin():
    """Create the default admin if no users exist yet."""
    rows = ch().query(
        "SELECT username FROM cybersentinel.cs_users FINAL WHERE is_active = 1 LIMIT 1"
    ).result_rows
    if not rows:
        ch().insert(
            "cybersentinel.cs_users",
            [[str(uuid.uuid4()), SEED_USER, pwd_ctx.hash(SEED_PASS),
              "admin", datetime.now(timezone.utc), "system", 1]],
            column_names=["id", "username", "password_hash", "role",
                          "created_at", "created_by", "is_active"],
        )
        print(f"[auth] Seeded admin: {SEED_USER}")


@app.on_event("startup")
def on_startup():
    _ensure_schema()
    _seed_admin()


# ── JWT helpers ───────────────────────────────────────────────────────────────
def _make_token(username: str, role: str, session_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": username, "role": role, "sid": session_id, "exp": exp},
        JWT_SECRET, algorithm=JWT_ALG,
    )


def _decode(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


# ── FastAPI dependencies ──────────────────────────────────────────────────────
def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        p = _decode(creds.credentials)
        return {"username": p["sub"], "role": p.get("role", "user"), "sid": p.get("sid", "")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ── DB helpers ────────────────────────────────────────────────────────────────
def _get_user(username: str) -> Optional[dict]:
    rows = ch().query(
        "SELECT username, password_hash, role, is_active, created_at, created_by "
        "FROM cybersentinel.cs_users FINAL "
        "WHERE username = {u:String} LIMIT 1",
        parameters={"u": username},
    ).result_rows
    if not rows:
        return None
    r = rows[0]
    return {
        "username": r[0], "password_hash": r[1], "role": r[2],
        "is_active": bool(r[3]), "created_at": str(r[4]), "created_by": r[5],
    }


def _log(username: str, action: str, client_ip: str = "",
         session_id: str = "", extra: str = ""):
    ch().insert(
        "cybersentinel.cs_auth_audit",
        [[str(uuid.uuid4()), username, action, client_ip,
          session_id, datetime.now(timezone.utc), extra]],
        column_names=["id", "username", "action", "client_ip",
                      "session_id", "ts", "extra"],
    )


# ── Request models ────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str


class CreateUserReq(BaseModel):
    username: str
    password: str
    role: str = "user"


class ChangePassReq(BaseModel):
    old_password: str
    new_password: str


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/auth/health")
def health():
    return {"status": "ok", "service": "auth"}


@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
    client_ip = request.client.host if request.client else ""
    user = _get_user(req.username)
    if not user or not user["is_active"] or not pwd_ctx.verify(req.password, user["password_hash"]):
        _log(req.username, "login_failed", client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    sid = str(uuid.uuid4())
    token = _make_token(user["username"], user["role"], sid)
    _log(user["username"], "login", client_ip, sid)
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     user["username"],
        "role":         user["role"],
        "session_id":   sid,
        "expires_in":   JWT_EXPIRE_HOURS * 3600,
    }


@app.post("/api/auth/logout")
def logout(request: Request, user: dict = Depends(current_user)):
    client_ip = request.client.host if request.client else ""
    _log(user["username"], "logout", client_ip, user.get("sid", ""))
    return {"status": "ok"}


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    u = _get_user(user["username"])
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username":   u["username"],
        "role":       u["role"],
        "created_at": u["created_at"],
    }


# ── User management (admin only) ──────────────────────────────────────────────

@app.get("/api/auth/users")
def list_users(admin: dict = Depends(admin_only)):
    rows = ch().query(
        "SELECT username, role, is_active, created_at, created_by "
        "FROM cybersentinel.cs_users FINAL "
        "ORDER BY created_at ASC"
    ).result_rows
    return [
        {"username": r[0], "role": r[1], "is_active": bool(r[2]),
         "created_at": str(r[3]), "created_by": r[4]}
        for r in rows
    ]


@app.post("/api/auth/users", status_code=201)
def create_user(req: CreateUserReq, admin: dict = Depends(admin_only)):
    if _get_user(req.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    if req.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    ch().insert(
        "cybersentinel.cs_users",
        [[str(uuid.uuid4()), req.username, pwd_ctx.hash(req.password),
          req.role, datetime.now(timezone.utc), admin["username"], 1]],
        column_names=["id", "username", "password_hash", "role",
                      "created_at", "created_by", "is_active"],
    )
    _log(admin["username"], "create_user", extra=f"created:{req.username}:{req.role}")
    return {"status": "created", "username": req.username, "role": req.role}


@app.delete("/api/auth/users/{username}")
def deactivate_user(username: str, admin: dict = Depends(admin_only)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    user = _get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # ReplacingMergeTree keeps the latest row per username — insert with is_active=0
    ch().insert(
        "cybersentinel.cs_users",
        [[str(uuid.uuid4()), username, user["password_hash"],
          user["role"], datetime.now(timezone.utc), admin["username"], 0]],
        column_names=["id", "username", "password_hash", "role",
                      "created_at", "created_by", "is_active"],
    )
    _log(admin["username"], "deactivate_user", extra=f"deactivated:{username}")
    return {"status": "deactivated", "username": username}


@app.post("/api/auth/users/{username}/reactivate")
def reactivate_user(username: str, admin: dict = Depends(admin_only)):
    user = _get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ch().insert(
        "cybersentinel.cs_users",
        [[str(uuid.uuid4()), username, user["password_hash"],
          user["role"], datetime.now(timezone.utc), admin["username"], 1]],
        column_names=["id", "username", "password_hash", "role",
                      "created_at", "created_by", "is_active"],
    )
    _log(admin["username"], "reactivate_user", extra=f"reactivated:{username}")
    return {"status": "reactivated", "username": username}


# ── Audit log (admin only) ────────────────────────────────────────────────────

@app.get("/api/auth/audit")
def audit_log(
    admin: dict = Depends(admin_only),
    limit: int = 300,
    username: str = "",
    action: str = "",
):
    where_parts = []
    params: dict = {"lim": limit}
    if username:
        where_parts.append("username = {u:String}")
        params["u"] = username
    if action:
        where_parts.append("action = {a:String}")
        params["a"] = action
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    rows = ch().query(
        f"SELECT username, action, client_ip, session_id, ts, extra "
        f"FROM cybersentinel.cs_auth_audit {where} "
        f"ORDER BY ts DESC LIMIT {{lim:UInt32}}",
        parameters=params,
    ).result_rows
    return [
        {"username": r[0], "action": r[1], "client_ip": r[2],
         "session_id": r[3], "ts": str(r[4]), "extra": r[5]}
        for r in rows
    ]


@app.get("/api/auth/audit/summary")
def audit_summary(admin: dict = Depends(admin_only)):
    """Per-user: last login time, login count, failed count."""
    rows = ch().query(
        """
        SELECT
            username,
            countIf(action = 'login')        AS logins,
            countIf(action = 'login_failed') AS failures,
            maxIf(ts, action = 'login')      AS last_login,
            minIf(ts, action = 'login')      AS first_login
        FROM cybersentinel.cs_auth_audit
        GROUP BY username
        ORDER BY last_login DESC
        """
    ).result_rows
    return [
        {
            "username":   r[0],
            "logins":     r[1],
            "failures":   r[2],
            "last_login": str(r[3]) if r[3] else None,
            "first_login": str(r[4]) if r[4] else None,
        }
        for r in rows
    ]
