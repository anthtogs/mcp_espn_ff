"""Vercel ASGI entrypoint for the ESPN Fantasy Football MCP server."""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from espn_fantasy_server import mcp


MCP_ENDPOINT = "/api/mcp"


@mcp.custom_route("/", methods=["GET"])
async def service_info(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "ESPN Fantasy Football MCP Server",
            "transport": "Streamable HTTP",
            "mcp_endpoint": MCP_ENDPOINT,
            "health_endpoint": "/health",
        }
    )


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


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
    """Protect the MCP route with MCP_API_KEY without affecting health routes."""

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

        expected = os.getenv("MCP_API_KEY")
        private_credentials_present = bool(os.getenv("ESPN_S2") or os.getenv("ESPN_SWID"))
        if not expected and not private_credentials_present:
            await self.asgi_app(scope, receive, send)
            return

        if not expected:
            await self._json_error(
                send,
                503,
                "MCP_API_KEY must be configured whenever ESPN credentials are present.",
            )
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        wanted = f"Bearer {expected}"
        if not hmac.compare_digest(supplied, wanted):
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
            headers.append((b"www-authenticate", b"Bearer"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


app = BearerAuthMiddleware(_mcp_app)
