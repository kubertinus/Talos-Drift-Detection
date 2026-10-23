"""Runtime settings, read from env vars, *_FILE vars or Docker secrets."""
import os
from pathlib import Path


def _secret(name: str) -> str | None:
    """Resolve NAME from env, NAME_FILE, or /run/secrets/<name lowercase>."""
    if os.environ.get(name):
        return os.environ[name].strip()
    file_path = os.environ.get(f"{name}_FILE") or f"/run/secrets/{name.lower()}"
    p = Path(file_path)
    if p.is_file():
        return p.read_text().strip()
    return None


DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
TMP_DIR = Path(os.environ.get("TMP_DIR", "/tmp"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/configs"))
TALOSCTL = os.environ.get("TALOSCTL", "talosctl")

MASTER_KEY = _secret("MASTER_KEY")
ADMIN_PASSWORD = _secret("ADMIN_PASSWORD")
SESSION_SECRET = _secret("SESSION_SECRET")

# OpenID Connect (e.g. Keycloak). Enabled when issuer and client id are set.
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")  # e.g. https://sso.example.com/realms/infra
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = _secret("OIDC_CLIENT_SECRET")
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid profile email")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "")  # default: <app url>/auth/callback
OIDC_PROVIDER_NAME = os.environ.get("OIDC_PROVIDER_NAME", "Keycloak")
OIDC_ALLOWED_ROLES = [r.strip() for r in os.environ.get("OIDC_ALLOWED_ROLES", "").split(",") if r.strip()]
OIDC_ALLOWED_GROUPS = [g.strip() for g in os.environ.get("OIDC_ALLOWED_GROUPS", "").split(",") if g.strip()]
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID)
PASSWORD_ENABLED = bool(ADMIN_PASSWORD)

# HTTPS: the app serves TLS itself unless TLS_ENABLED=false (e.g. behind a TLS-terminating proxy).
TLS_ENABLED = os.environ.get("TLS_ENABLED", "true").lower() in ("1", "true", "yes")
HTTPS_PORT = int(os.environ.get("HTTPS_LISTEN_PORT", "8443"))
HTTP_PORT = int(os.environ.get("HTTP_LISTEN_PORT", "8080"))
HTTPS_PUBLIC_PORT = int(os.environ.get("HTTPS_PUBLIC_PORT", "443"))  # port in redirects to HTTPS

COOKIE_SECURE = TLS_ENABLED or os.environ.get("COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
DEFAULT_SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "900"))
SCAN_CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", "5"))
NODE_TIMEOUT = int(os.environ.get("NODE_TIMEOUT", "30"))
HISTORY_SIZE = int(os.environ.get("HISTORY_SIZE", "50"))


def validate() -> None:
    if not MASTER_KEY:
        raise SystemExit("Missing required secret: MASTER_KEY")
    if len(MASTER_KEY) < 32:
        raise SystemExit("MASTER_KEY must be at least 32 characters")
    if not (PASSWORD_ENABLED or OIDC_ENABLED):
        raise SystemExit("Configure a login method: ADMIN_PASSWORD and/or OIDC_ISSUER + OIDC_CLIENT_ID")
