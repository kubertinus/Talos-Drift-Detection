"""Login with the admin password and/or OpenID Connect, kept in a signed session cookie."""
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from . import config

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


def start_session(request: Request, user: str, name: str, method: str) -> None:
    request.session.clear()  # drop anything from before the login (e.g. OIDC state)
    request.session.update({"user": user, "name": name, "method": method, "csrf": secrets.token_urlsafe(24)})


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


def check_csrf(request: Request, token: str | None) -> None:
    expected = request.session.get("csrf")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Invalid CSRF token")
