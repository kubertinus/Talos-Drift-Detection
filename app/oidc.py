"""OpenID Connect login (Keycloak or any other OIDC provider).

Authorization code flow with PKCE via Authlib. Access is optionally limited
to users with one of OIDC_ALLOWED_ROLES (Keycloak realm or client roles) or
OIDC_ALLOWED_GROUPS (`groups` claim; needs a group mapper in Keycloak).
"""
import logging
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError
from fastapi import Request

from . import config

log = logging.getLogger("oidc")
oauth = OAuth()
if config.OIDC_ENABLED:
    oauth.register(
        "provider",
        client_id=config.OIDC_CLIENT_ID,
        client_secret=config.OIDC_CLIENT_SECRET,
        server_metadata_url=f"{config.OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": config.OIDC_SCOPES, "code_challenge_method": "S256"},
    )
    if not (config.OIDC_ALLOWED_ROLES or config.OIDC_ALLOWED_GROUPS):
        log.warning("OIDC enabled without OIDC_ALLOWED_ROLES/GROUPS: every user of the realm can log in")


class AccessDenied(Exception):
    pass


def redirect_uri(request: Request) -> str:
    return config.OIDC_REDIRECT_URI or str(request.url_for("oidc_callback"))


async def login_redirect(request: Request):
    return await oauth.provider.authorize_redirect(request, redirect_uri(request))


async def _access_claims(token: dict) -> dict:
    """Verified claims of the access token (Keycloak puts the roles there)."""
    jwks = JsonWebKey.import_key_set(await oauth.provider.fetch_jwk_set())
    try:
        claims = jwt.decode(token["access_token"], jwks)
        claims.validate()
    except (JoseError, ValueError):
        return {}  # opaque or unverifiable access token: fall back to ID token claims
    return dict(claims)


def roles_and_groups(id_claims: dict, access_claims: dict) -> tuple[set[str], set[str]]:
    roles, groups = set(), set()
    for claims in (id_claims, access_claims):
        roles |= set((claims.get("realm_access") or {}).get("roles") or [])
        client = (claims.get("resource_access") or {}).get(config.OIDC_CLIENT_ID) or {}
        roles |= set(client.get("roles") or [])
        roles |= set(claims.get("roles") or [])
        # Keycloak group mapper with "full path" gives "/admins"; accept both forms.
        groups |= {g.lstrip("/") for g in claims.get("groups") or []}
    return roles, groups


def is_allowed(roles: set[str], groups: set[str]) -> bool:
    if not (config.OIDC_ALLOWED_ROLES or config.OIDC_ALLOWED_GROUPS):
        return True
    allowed_groups = {g.lstrip("/") for g in config.OIDC_ALLOWED_GROUPS}
    return bool(roles & set(config.OIDC_ALLOWED_ROLES) or groups & allowed_groups)


async def handle_callback(request: Request) -> tuple[str, str, str | None]:
    """Finish the login; returns (user id, display name, id token) or raises AccessDenied / OAuthError."""
    token = await oauth.provider.authorize_access_token(request)
    id_claims = dict(token.get("userinfo") or {})
    if not id_claims.get("sub"):
        raise OAuthError(description="no ID token in response")
    if config.OIDC_ALLOWED_ROLES or config.OIDC_ALLOWED_GROUPS:
        roles, groups = roles_and_groups(id_claims, await _access_claims(token))
        if not is_allowed(roles, groups):
            name = id_claims.get("preferred_username") or id_claims["sub"]
            log.warning("OIDC login refused for %s: missing required role/group", name)
            raise AccessDenied(name)
    name = id_claims.get("preferred_username") or id_claims.get("email") or id_claims["sub"]
    display = id_claims.get("name") or name
    return f"oidc:{id_claims['sub']}", display, token.get("id_token")


async def logout_url(request: Request, id_token: str | None) -> str | None:
    """Provider logout URL that ends the SSO session and returns to the login page.

    With the ID token as hint Keycloak logs out without asking for confirmation.
    """
    try:
        metadata = await oauth.provider.load_server_metadata()
    except Exception:
        return None
    endpoint = metadata.get("end_session_endpoint")
    if not endpoint:
        return None
    back = str(request.url_for("login_page"))
    params = {"client_id": config.OIDC_CLIENT_ID, "post_logout_redirect_uri": back}
    if id_token:
        params["id_token_hint"] = id_token
    return f"{endpoint}?{urlencode(params)}"
