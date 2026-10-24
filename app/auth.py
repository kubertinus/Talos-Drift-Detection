"""Login with the admin password and/or OpenID Connect, kept in a signed session cookie."""
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from . import audit, config

MAX_FAILURES = 5
WINDOW = 300
_failures: dict[str, deque] = defaultdict(deque)


def session_secret() -> str:
    if config.SESSION_SECRET:
        return config.SESSION_SECRET
    return hmac.new(config.MASTER_KEY.encode(), b"session-secret", hashlib.sha256).hexdigest()


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def rate_limited(request: Request) -> bool:
    q = _failures[_client(request)]
    now = time.monotonic()
    while q and now - q[0] > WINDOW:
        q.popleft()
    return len(q) >= MAX_FAILURES


def start_session(request: Request, user: str, name: str, method: str, username: str = "",
                  operator: bool = True) -> None:
    request.session.clear()  # drop anything from before the login (e.g. OIDC state)
    request.session.update({"user": user, "name": name, "username": username or name, "method": method,
                            "operator": operator, "csrf": secrets.token_urlsafe(24)})


def is_operator(request: Request) -> bool:
    """May change things. Sessions from before operator roles existed: password users, or anyone
    when no operator roles/groups are configured."""
    s = request.session
    if "operator" in s:
        return bool(s["operator"])
    return s.get("method") == "password" or not (config.OIDC_OPERATOR_ROLES or config.OIDC_OPERATOR_GROUPS)


def actor(request: Request) -> dict:
    """Who is doing something, for the activity log: stable id, username, display name, method, IP."""
    s = request.session
    return {"id": s.get("user") or "anonymous", "username": s.get("username") or s.get("name") or "",
            "name": s.get("name") or "", "method": s.get("method") or "", "ip": _client(request),
            "role": ("operator" if is_operator(request) else "viewer") if s.get("user") else ""}


def actor_label(a: dict) -> str:
    """'Jan Jansen (jjansen · oidc)'; 'admin (password)' for the shared admin password."""
    if a.get("method") == "password":
        return "admin (password)"
    name, username = a.get("name") or a.get("username") or a.get("id"), a.get("username")
    extra = " · ".join(x for x in (username if username and username != name else "", a.get("method")) if x)
    return f"{name} ({extra})" if extra else str(name)


def check_password(request: Request, password: str) -> bool:
    if not config.PASSWORD_ENABLED:
        return False
    ok = hmac.compare_digest(password.encode(), config.ADMIN_PASSWORD.encode())
    if ok:
        _failures.pop(_client(request), None)
        start_session(request, "admin", "admin", "password")
    else:
        _failures[_client(request)].append(time.monotonic())
    return ok


def is_logged_in(request: Request) -> bool:
    return bool(request.session.get("user"))


class LoginRequired(Exception):
    pass


def require_login(request: Request) -> None:
    if not is_logged_in(request):
        if request.url.path.startswith("/api/"):
            raise HTTPException(401, "Not authenticated")
        raise LoginRequired()


class OperatorRequired(HTTPException):
    def __init__(self):
        super().__init__(403, "Read-only: your account has no operator role, so it cannot change anything.")


def require_operator(request: Request) -> None:
    require_login(request)
    if not is_operator(request):
        audit.record(actor(request), "access.denied", None, method=request.method, path=request.url.path)
        raise OperatorRequired()


def check_csrf(request: Request, token: str | None) -> None:
    expected = request.session.get("csrf")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Invalid CSRF token")
