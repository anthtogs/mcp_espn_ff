"""Small, stateless OAuth 2.1 authorization server for ChatGPT MCP clients.

The implementation intentionally supports only ChatGPT's public CIMD clients,
authorization-code grants with PKCE/S256, and the read-only ``fantasy:read``
scope. ESPN credentials never enter OAuth tokens or browser responses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response


MCP_ENDPOINT = "/api/mcp"
OAUTH_SCOPE = "fantasy:read"
LOCAL_ISSUER = "http://127.0.0.1:8000"
CHATGPT_STABLE_CLIENT_ID = "https://chatgpt.com/oauth/client.json"
CHATGPT_STABLE_REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"
_CALLBACK_CLIENT_RE = re.compile(r"https://chatgpt\.com/oauth/([A-Za-z0-9_-]+)/client\.json")
_PKCE_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}")


class OAuthConfigurationError(RuntimeError):
    """Raised when only part of the OAuth configuration is present."""


class OAuthTokenError(ValueError):
    """Raised when a signed OAuth artifact is invalid."""


@dataclass(frozen=True)
class OAuthConfiguration:
    issuer: str
    resource: str
    signing_secret: str | None
    login_password: str | None

    @property
    def enabled(self) -> bool:
        return bool(self.signing_secret and self.login_password)


def oauth_configuration() -> OAuthConfiguration:
    issuer = os.getenv("OAUTH_ISSUER_URL", LOCAL_ISSUER).rstrip("/")
    resource = os.getenv("MCP_RESOURCE_URL", f"{issuer}{MCP_ENDPOINT}").rstrip("/")
    signing_secret = os.getenv("OAUTH_SIGNING_SECRET") or None
    login_password = os.getenv("OAUTH_LOGIN_PASSWORD") or None
    if bool(signing_secret) != bool(login_password):
        raise OAuthConfigurationError(
            "OAuth requires both OAUTH_SIGNING_SECRET and OAUTH_LOGIN_PASSWORD."
        )
    if signing_secret and len(signing_secret.encode()) < 32:
        raise OAuthConfigurationError("OAUTH_SIGNING_SECRET must contain at least 32 bytes.")
    parsed_issuer = urlparse(issuer)
    if parsed_issuer.scheme not in {"http", "https"} or not parsed_issuer.netloc:
        raise OAuthConfigurationError("OAUTH_ISSUER_URL must be an absolute HTTP(S) URL.")
    if parsed_issuer.scheme != "https" and parsed_issuer.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise OAuthConfigurationError("OAUTH_ISSUER_URL must use HTTPS outside localhost.")
    return OAuthConfiguration(issuer, resource, signing_secret, login_password)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: dict[str, Any], *, lifetime: int, token_type: str) -> str:
    config = oauth_configuration()
    if not config.enabled or not config.signing_secret:
        raise OAuthConfigurationError("OAuth is not configured.")
    now = int(time.time())
    claims = {
        **payload,
        "iss": config.issuer,
        "iat": now,
        "exp": now + lifetime,
        "jti": secrets.token_urlsafe(18),
        "token_use": token_type,
    }
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header}.{body}".encode()
    signature = _b64encode(hmac.new(config.signing_secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{body}.{signature}"


def _verify(token: str, *, token_type: str) -> dict[str, Any]:
    config = oauth_configuration()
    if not config.enabled or not config.signing_secret:
        raise OAuthTokenError("OAuth is not configured")
    try:
        header_part, body_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{body_part}".encode()
        wanted = hmac.new(config.signing_secret.encode(), signing_input, hashlib.sha256).digest()
        supplied = _b64decode(signature_part)
        header = json.loads(_b64decode(header_part))
        payload = json.loads(_b64decode(body_part))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OAuthTokenError("Malformed token") from error
    if header != {"alg": "HS256", "typ": "JWT"} or not hmac.compare_digest(supplied, wanted):
        raise OAuthTokenError("Invalid token signature")
    if not isinstance(payload, dict) or payload.get("token_use") != token_type:
        raise OAuthTokenError("Invalid token type")
    now = int(time.time())
    if not isinstance(payload.get("exp"), int) or payload["exp"] <= now:
        raise OAuthTokenError("Token expired")
    if payload.get("iss") != config.issuer:
        raise OAuthTokenError("Invalid token issuer")
    return payload


def _client_redirect_is_allowed(client_id: str, redirect_uri: str) -> bool:
    if client_id == CHATGPT_STABLE_CLIENT_ID:
        return redirect_uri == CHATGPT_STABLE_REDIRECT_URI
    match = _CALLBACK_CLIENT_RE.fullmatch(client_id)
    if not match:
        return False
    return redirect_uri == f"https://chatgpt.com/connector/oauth/{match.group(1)}"


def _redirect(url: str, **params: str | None) -> str:
    parsed = urlparse(url)
    query = [(key, item) for key, values in parse_qs(parsed.query).items() for item in values]
    query.extend((key, value) for key, value in params.items() if value is not None)
    return urlunparse(parsed._replace(query=urlencode(query)))


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _form_data(request: Request) -> dict[str, str]:
    if int(request.headers.get("content-length", "0") or "0") > 65536:
        raise ValueError("Request body is too large")
    raw = (await request.body()).decode("utf-8")
    return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}


def _authorization_request(values: dict[str, str]) -> dict[str, Any]:
    config = oauth_configuration()
    client_id = values.get("client_id", "")
    redirect_uri = values.get("redirect_uri", "")
    if not _client_redirect_is_allowed(client_id, redirect_uri):
        raise OAuthTokenError("Unknown ChatGPT client or redirect URI")
    if values.get("response_type") != "code":
        raise OAuthTokenError("response_type must be code")
    challenge = values.get("code_challenge", "")
    if values.get("code_challenge_method") != "S256" or not _PKCE_RE.fullmatch(challenge):
        raise OAuthTokenError("PKCE with a valid S256 code challenge is required")
    requested_resource = values.get("resource") or config.resource
    if requested_resource.rstrip("/") != config.resource:
        raise OAuthTokenError("Unknown resource")
    scopes = (values.get("scope") or OAUTH_SCOPE).split()
    if not scopes or any(scope != OAUTH_SCOPE for scope in scopes):
        raise OAuthTokenError("Unsupported scope")
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": values.get("state"),
        "code_challenge": challenge,
        "resource": config.resource,
        "scope": OAUTH_SCOPE,
    }


def _consent_page(request_token: str, *, error: str | None = None) -> HTMLResponse:
    message = (
        f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ESPN Fantasy Football</title>
  <style>
    :root {{ color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b1020; color: #f8fafc; }}
    main {{ width: min(420px, calc(100% - 32px)); padding: 28px; border: 1px solid #334155; border-radius: 16px; background: #111827; box-sizing: border-box; }}
    h1 {{ margin: 0 0 12px; font-size: 1.45rem; }}
    p {{ color: #cbd5e1; line-height: 1.5; }}
    label {{ display: block; margin: 22px 0 8px; font-weight: 650; }}
    input {{ width: 100%; padding: 12px; border: 1px solid #64748b; border-radius: 8px; box-sizing: border-box; font: inherit; }}
    .actions {{ display: flex; gap: 10px; margin-top: 18px; }}
    button {{ flex: 1; padding: 11px; border: 0; border-radius: 8px; font: inherit; font-weight: 700; cursor: pointer; }}
    .allow {{ background: #22c55e; color: #052e16; }}
    .deny {{ background: #334155; color: #f8fafc; }}
    .error {{ color: #fca5a5; }}
  </style>
</head>
<body>
  <main>
    <h1>Connect ESPN Fantasy Football</h1>
    <p>ChatGPT is requesting read-only access to the ESPN fantasy league data configured on this server.</p>
    {message}
    <form method="post" action="/oauth/authorize" autocomplete="off">
      <input type="hidden" name="request" value="{html.escape(request_token, quote=True)}">
      <label for="password">Server passphrase</label>
      <input id="password" name="password" type="password" required autofocus>
      <div class="actions">
        <button class="deny" name="decision" value="deny" type="submit">Deny</button>
        <button class="allow" name="decision" value="allow" type="submit">Authorize</button>
      </div>
    </form>
  </main>
</body>
</html>"""
    return HTMLResponse(
        page,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com; base-uri 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )


async def protected_resource_metadata(_: Request) -> JSONResponse:
    config = oauth_configuration()
    return JSONResponse(
        {
            "resource": config.resource,
            "authorization_servers": [config.issuer],
            "scopes_supported": [OAUTH_SCOPE],
            "resource_name": "ESPN Fantasy Football MCP",
            "resource_documentation": f"{config.issuer}/",
            "bearer_methods_supported": ["header"],
        }
    )


async def authorization_server_metadata(_: Request) -> JSONResponse:
    config = oauth_configuration()
    return JSONResponse(
        {
            "issuer": config.issuer,
            "authorization_endpoint": f"{config.issuer}/oauth/authorize",
            "token_endpoint": f"{config.issuer}/oauth/token",
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True,
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": [OAUTH_SCOPE],
        }
    )


async def authorize(request: Request) -> Response:
    config = oauth_configuration()
    if not config.enabled:
        return _oauth_error("temporarily_unavailable", "OAuth is not configured", 503)

    if request.method == "GET":
        try:
            pending = _authorization_request(dict(request.query_params))
        except OAuthTokenError as error:
            return _oauth_error("invalid_request", str(error))
        request_token = _sign(pending, lifetime=600, token_type="authorization_request")
        return _consent_page(request_token)

    try:
        form = await _form_data(request)
        request_token = form.get("request", "")
        pending = _verify(request_token, token_type="authorization_request")
    except (ValueError, OAuthTokenError) as error:
        return _oauth_error("invalid_request", str(error))

    redirect_uri = str(pending.get("redirect_uri", ""))
    state = pending.get("state")
    if not _client_redirect_is_allowed(str(pending.get("client_id", "")), redirect_uri):
        return _oauth_error("invalid_request", "Invalid redirect URI")
    if form.get("decision") != "allow":
        return RedirectResponse(
            _redirect(
                redirect_uri,
                error="access_denied",
                error_description="The resource owner denied the request",
                state=state,
                iss=config.issuer,
            ),
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )
    supplied_password = form.get("password", "")
    if not config.login_password or not hmac.compare_digest(
        supplied_password.encode(), config.login_password.encode()
    ):
        return _consent_page(request_token, error="Incorrect passphrase")

    code = _sign(
        {
            "client_id": pending["client_id"],
            "redirect_uri": redirect_uri,
            "code_challenge": pending["code_challenge"],
            "resource": pending["resource"],
            "scope": pending["scope"],
            "sub": "server-owner",
        },
        lifetime=120,
        token_type="authorization_code",
    )
    return RedirectResponse(
        _redirect(redirect_uri, code=code, state=state, iss=config.issuer),
        status_code=302,
        headers={"Cache-Control": "no-store"},
    )


def _issue_tokens(*, client_id: str, resource: str, scope: str, subject: str) -> JSONResponse:
    access_token = _sign(
        {"client_id": client_id, "aud": resource, "scope": scope, "sub": subject},
        lifetime=3600,
        token_type="access_token",
    )
    refresh_token = _sign(
        {"client_id": client_id, "aud": resource, "scope": scope, "sub": subject},
        lifetime=30 * 24 * 3600,
        token_type="refresh_token",
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": scope,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def token(request: Request) -> JSONResponse:
    config = oauth_configuration()
    if not config.enabled:
        return _oauth_error("temporarily_unavailable", "OAuth is not configured", 503)
    try:
        form = await _form_data(request)
    except ValueError as error:
        return _oauth_error("invalid_request", str(error))

    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    if not _client_redirect_is_allowed(client_id, redirect_uri or CHATGPT_STABLE_REDIRECT_URI):
        return _oauth_error("invalid_client", "Unknown ChatGPT client", 401)
    if request.headers.get("authorization") or form.get("client_secret"):
        return _oauth_error("invalid_client", "This public client must use token endpoint authentication method none", 401)

    grant_type = form.get("grant_type")
    if grant_type == "authorization_code":
        try:
            code = _verify(form.get("code", ""), token_type="authorization_code")
        except OAuthTokenError:
            return _oauth_error("invalid_grant", "Invalid or expired authorization code")
        if code.get("client_id") != client_id or code.get("redirect_uri") != redirect_uri:
            return _oauth_error("invalid_grant", "Authorization code does not match this client")
        requested_resource = (form.get("resource") or config.resource).rstrip("/")
        if code.get("resource") != config.resource or requested_resource != config.resource:
            return _oauth_error("invalid_target", "Authorization code is not valid for this resource")
        verifier = form.get("code_verifier", "")
        if not _PKCE_RE.fullmatch(verifier):
            return _oauth_error("invalid_grant", "Invalid PKCE code verifier")
        challenge = _b64encode(hashlib.sha256(verifier.encode()).digest())
        if not hmac.compare_digest(challenge, str(code.get("code_challenge", ""))):
            return _oauth_error("invalid_grant", "Incorrect PKCE code verifier")
        return _issue_tokens(
            client_id=client_id,
            resource=config.resource,
            scope=str(code.get("scope", OAUTH_SCOPE)),
            subject=str(code.get("sub", "server-owner")),
        )

    if grant_type == "refresh_token":
        try:
            refresh = _verify(form.get("refresh_token", ""), token_type="refresh_token")
        except OAuthTokenError:
            return _oauth_error("invalid_grant", "Invalid or expired refresh token")
        if refresh.get("client_id") != client_id or refresh.get("aud") != config.resource:
            return _oauth_error("invalid_grant", "Refresh token does not match this client or resource")
        requested_scope = form.get("scope") or str(refresh.get("scope", ""))
        if requested_scope != OAUTH_SCOPE:
            return _oauth_error("invalid_scope", "Unsupported scope")
        return _issue_tokens(
            client_id=client_id,
            resource=config.resource,
            scope=OAUTH_SCOPE,
            subject=str(refresh.get("sub", "server-owner")),
        )

    return _oauth_error("unsupported_grant_type", "Use authorization_code or refresh_token")


def validate_access_token(value: str) -> dict[str, Any] | None:
    try:
        payload = _verify(value, token_type="access_token")
        config = oauth_configuration()
        if payload.get("aud") != config.resource:
            return None
        if OAUTH_SCOPE not in str(payload.get("scope", "")).split():
            return None
        if payload.get("client_id") not in {CHATGPT_STABLE_CLIENT_ID} and not _CALLBACK_CLIENT_RE.fullmatch(
            str(payload.get("client_id", ""))
        ):
            return None
        return payload
    except (OAuthConfigurationError, OAuthTokenError):
        return None


def www_authenticate_header(*, error: str = "invalid_token", description: str = "Authentication required") -> str:
    config = oauth_configuration()
    metadata_url = f"{config.issuer}/.well-known/oauth-protected-resource"
    return (
        f'Bearer resource_metadata="{metadata_url}", scope="{OAUTH_SCOPE}", '
        f'error="{error}", error_description="{description}"'
    )
