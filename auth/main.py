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
import secrets
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import clickhouse_connect
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
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

# ── Google SSO ────────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI", "")
GOOGLE_ALLOWED_DOMAIN = os.getenv("GOOGLE_ALLOWED_DOMAIN", "")  # e.g. "company.com" — blank = any Google account
FRONTEND_URL         = os.getenv("FRONTEND_URL", "")            # e.g. "http://10.200.10.23:19888"

GOOGLE_AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL    = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# Short-lived in-memory state store for CSRF protection (state → expiry timestamp)
_sso_states: dict[str, float] = {}

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


# ── Google SSO ────────────────────────────────────────────────────────────────

@app.get("/api/auth/sso/providers")
def sso_providers():
    """Return which SSO providers are configured so the frontend can show/hide buttons."""
    return {"google": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI)}


@app.get("/api/auth/sso/login")
def sso_login():
    """Step 1 — redirect the browser to Google's OAuth2 consent screen."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        raise HTTPException(400, "Google SSO is not configured on this server")
    # Generate a random state value and store it for 10 minutes (CSRF guard)
    state = secrets.token_urlsafe(32)
    _sso_states[state] = time.time() + 600
    # Purge expired states so memory doesn't grow unbounded
    expired = [k for k, v in _sso_states.items() if v < time.time()]
    for k in expired:
        _sso_states.pop(k, None)
    params = urllib.parse.urlencode({
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
        "prompt":        "select_account",
    })
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{params}")


@app.get("/api/auth/sso/callback")
async def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Step 2 — Google redirects here with an auth code; exchange it for a JWT."""
    fe = FRONTEND_URL or str(request.base_url).rstrip("/")

    def _fail(reason: str):
        return RedirectResponse(f"{fe}?sso_error={urllib.parse.quote(reason)}#login")

    if error:
        return _fail(error)
    if not code or not state:
        return _fail("missing_code_or_state")

    # Validate CSRF state
    expires = _sso_states.pop(state, None)
    if not expires or time.time() > expires:
        return _fail("invalid_or_expired_state")

    # Exchange auth code for tokens
    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(GOOGLE_TOKEN_URL, data={
            "code":          code,
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri":  GOOGLE_REDIRECT_URI,
            "grant_type":    "authorization_code",
        })
        if not token_resp.is_success:
            return _fail("token_exchange_failed")
        tokens = token_resp.json()

        # Fetch user profile from Google
        userinfo_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        if not userinfo_resp.is_success:
            return _fail("userinfo_failed")
        userinfo = userinfo_resp.json()

    email = userinfo.get("email", "").lower().strip()
    name  = userinfo.get("name", "") or email.split("@")[0]
    if not email:
        return _fail("no_email_returned")

    # Optional: restrict to a specific Google Workspace domain
    if GOOGLE_ALLOWED_DOMAIN and not email.endswith(f"@{GOOGLE_ALLOWED_DOMAIN}"):
        return _fail(f"domain_not_allowed_{GOOGLE_ALLOWED_DOMAIN}")

    # Use email prefix as username (e.g. "tejas" from "tejas@company.com")
    username = email.split("@")[0]

    # Auto-provision the user if this is their first SSO login
    user = _get_user(username)
    if not user:
        ch().insert(
            "cybersentinel.cs_users",
            [[str(uuid.uuid4()), username, "",   # empty password_hash — SSO users can't use local login
              "user", datetime.now(timezone.utc), f"google_sso:{email}", 1]],
            column_names=["id", "username", "password_hash", "role",
                          "created_at", "created_by", "is_active"],
        )
        user = _get_user(username)

    if not user or not user.get("is_active"):
        return _fail("account_disabled")

    # Issue the standard JWT (same format as local login)
    sid = str(uuid.uuid4())
    token = _make_token(username, user["role"], sid)
    _log(username, "sso_login", client_ip=request.client.host if request.client else "",
         session_id=sid, extra=f"provider:google email:{email}")

    # Redirect back to frontend — token passed in query params, frontend stores in localStorage
    params = urllib.parse.urlencode({
        "sso_token": token,
        "role":      user["role"],
        "user":      username,
    })
    return RedirectResponse(f"{fe}?{params}#sso")


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
