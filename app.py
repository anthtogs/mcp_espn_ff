"""Vercel ASGI entrypoint for the ESPN Fantasy Football MCP server."""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from espn_fantasy_server import mcp
from oauth import (
    MCP_ENDPOINT,
    OAuthConfigurationError,
    authorization_server_metadata,
    authorize,
    oauth_configuration,
    protected_resource_metadata,
    token,
    validate_access_token,
    www_authenticate_header,
)


@mcp.custom_route("/", methods=["GET"])
async def service_info(_: Request) -> JSONResponse:
    try:
        oauth_enabled = oauth_configuration().enabled
    except OAuthConfigurationError:
        oauth_enabled = False
    return JSONResponse(
        {
            "name": "ESPN Fantasy Football MCP Server",
            "transport": "Streamable HTTP",
            "mcp_endpoint": MCP_ENDPOINT,
            "health_endpoint": "/health",
            "oauth": {
                "enabled": oauth_enabled,
                "protected_resource_metadata": "/.well-known/oauth-protected-resource",
                "authorization_server_metadata": "/.well-known/oauth-authorization-server",
            },
        }
    )


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
@mcp.custom_route("/.well-known/oauth-protected-resource/api/mcp", methods=["GET"])
async def oauth_protected_resource(request: Request) -> JSONResponse:
    return await protected_resource_metadata(request)


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request: Request) -> JSONResponse:
    return await authorization_server_metadata(request)


@mcp.custom_route("/oauth/authorize", methods=["GET", "POST"])
async def oauth_authorize(request: Request) -> Response:
    return await authorize(request)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request: Request) -> Response:
    return await token(request)


# Vercel terminates TLS and validates the public Host header before forwarding to
# the ASGI function, so disabling SDK-level DNS rebinding checks is appropriate.
_mcp_app = mcp.streamable_http_app(
    streamable_http_path=MCP_ENDPOINT,
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)


class BearerAuthMiddleware:
    """Protect MCP with OAuth access tokens or the legacy MCP_API_KEY."""

    def __init__(self, asgi_app: Callable[..., Awaitable[None]]) -> None:
        self.asgi_app = asgi_app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http" or scope.get("path") != MCP_ENDPOINT:
            await self.asgi_app(scope, receive, send)
            return

        expected_api_key = os.getenv("MCP_API_KEY")
        private_credentials_present = bool(os.getenv("ESPN_S2") or os.getenv("ESPN_SWID"))
        try:
            oauth_config = oauth_configuration()
        except OAuthConfigurationError as error:
            await self._json_error(send, 503, str(error))
            return

        if not expected_api_key and not oauth_config.enabled and not private_credentials_present:
            await self.asgi_app(scope, receive, send)
            return

        if private_credentials_present and not expected_api_key and not oauth_config.enabled:
            await self._json_error(
                send,
                503,
                "Configure OAuth or MCP_API_KEY whenever ESPN credentials are present.",
            )
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        bearer = supplied[7:] if supplied.lower().startswith("bearer ") else ""
        api_key_valid = bool(
            expected_api_key
            and bearer
            and hmac.compare_digest(bearer.encode(), expected_api_key.encode())
        )
        oauth_valid = bool(bearer and oauth_config.enabled and validate_access_token(bearer))
        if not api_key_valid and not oauth_valid:
            await self._json_error(send, 401, "Unauthorized", authenticate=True)
            return

        await self.asgi_app(scope, receive, send)

    @staticmethod
    async def _json_error(
        send: Callable[..., Awaitable[None]],
        status: int,
        detail: str,
        *,
        authenticate: bool = False,
    ) -> None:
        body = json.dumps({"detail": detail}).encode()
        headers = [(b"content-type", b"application/json")]
        if authenticate:
            try:
                config = oauth_configuration()
                challenge = (
                    www_authenticate_header().encode()
                    if config.enabled
                    else b"Bearer"
                )
            except OAuthConfigurationError:
                challenge = b"Bearer"
            headers.append((b"www-authenticate", challenge))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


app = BearerAuthMiddleware(_mcp_app)
