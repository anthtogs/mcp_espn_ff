from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from urllib.parse import parse_qs, urlparse

import pytest
from mcp import Client
from starlette.testclient import TestClient

import espn_fantasy_server as server
from app import app
from oauth import CHATGPT_STABLE_CLIENT_ID, CHATGPT_STABLE_REDIRECT_URI


@pytest.fixture(scope="module")
def http_client() -> TestClient:
    # The MCP SDK's session manager is deliberately single-start, matching one
    # ASGI process lifespan, so all HTTP checks share one app client.
    with TestClient(app) as client:
        yield client


def test_health_and_service_info(http_client: TestClient) -> None:
    assert http_client.get("/health").json() == {"status": "ok"}
    info = http_client.get("/").json()
    assert info["mcp_endpoint"] == "/api/mcp"
    assert info["transport"] == "Streamable HTTP"


def test_private_credentials_require_remote_auth(
    monkeypatch: pytest.MonkeyPatch, http_client: TestClient
) -> None:
    monkeypatch.setenv("ESPN_S2", "secret-cookie")
    monkeypatch.setenv("ESPN_SWID", "{secret-id}")
    monkeypatch.delenv("MCP_API_KEY", raising=False)

    response = http_client.post("/api/mcp", json={})
    assert response.status_code == 503


def test_remote_auth_rejects_wrong_token(
    monkeypatch: pytest.MonkeyPatch, http_client: TestClient
) -> None:
    monkeypatch.setenv("MCP_API_KEY", "correct-token")

    response = http_client.post(
        "/api/mcp",
        json={},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"

    response = http_client.post(
        "/api/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        },
        headers={
            "Authorization": "Bearer correct-token",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "espn-fantasy-football"


def test_chatgpt_oauth_discovery_and_pkce_flow(
    monkeypatch: pytest.MonkeyPatch, http_client: TestClient
) -> None:
    issuer = "http://127.0.0.1:8000"
    resource = f"{issuer}/api/mcp"
    monkeypatch.setenv("OAUTH_ISSUER_URL", issuer)
    monkeypatch.setenv("MCP_RESOURCE_URL", resource)
    monkeypatch.setenv("OAUTH_SIGNING_SECRET", "s" * 32)
    monkeypatch.setenv("OAUTH_LOGIN_PASSWORD", "owner-passphrase")
    monkeypatch.delenv("MCP_API_KEY", raising=False)

    protected = http_client.get("/.well-known/oauth-protected-resource")
    assert protected.status_code == 200
    assert protected.json() == {
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": ["fantasy:read"],
        "resource_name": "ESPN Fantasy Football MCP",
        "resource_documentation": f"{issuer}/",
        "bearer_methods_supported": ["header"],
    }

    metadata = http_client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == issuer
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["client_id_metadata_document_supported"] is True
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]

    unauthenticated = http_client.post("/api/mcp", json={})
    assert unauthenticated.status_code == 401
    assert "resource_metadata=" in unauthenticated.headers["www-authenticate"]
    assert 'scope="fantasy:read"' in unauthenticated.headers["www-authenticate"]

    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    authorize_response = http_client.get(
        "/oauth/authorize",
        params={
            "client_id": CHATGPT_STABLE_CLIENT_ID,
            "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state",
            "scope": "fantasy:read",
            "resource": resource,
        },
    )
    assert authorize_response.status_code == 200
    match = re.search(r'name="request" value="([^"]+)"', authorize_response.text)
    assert match is not None
    pending_request = match.group(1)

    wrong_password = http_client.post(
        "/oauth/authorize",
        data={
            "request": pending_request,
            "password": "wrong",
            "decision": "allow",
        },
        follow_redirects=False,
    )
    assert wrong_password.status_code == 200
    assert "Incorrect passphrase" in wrong_password.text

    approved = http_client.post(
        "/oauth/authorize",
        data={
            "request": pending_request,
            "password": "owner-passphrase",
            "decision": "allow",
        },
        follow_redirects=False,
    )
    assert approved.status_code == 302
    callback = urlparse(approved.headers["location"])
    callback_query = parse_qs(callback.query)
    assert f"{callback.scheme}://{callback.netloc}{callback.path}" == CHATGPT_STABLE_REDIRECT_URI
    assert callback_query["state"] == ["test-state"]
    assert callback_query["iss"] == [issuer]

    token_response = http_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CHATGPT_STABLE_CLIENT_ID,
            "redirect_uri": CHATGPT_STABLE_REDIRECT_URI,
            "code": callback_query["code"][0],
            "code_verifier": verifier,
            "resource": resource,
        },
    )
    assert token_response.status_code == 200
    tokens = token_response.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "fantasy:read"
    assert tokens["refresh_token"]

    initialized = http_client.post(
        "/api/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "oauth-pytest", "version": "1"},
            },
        },
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    assert initialized.status_code == 200

    refreshed = http_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CHATGPT_STABLE_CLIENT_ID,
            "refresh_token": tokens["refresh_token"],
            "resource": resource,
        },
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"] != tokens["access_token"]


def test_credentials_must_be_configured_as_a_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ESPN_S2", "secret-cookie")
    monkeypatch.delenv("ESPN_SWID", raising=False)

    with pytest.raises(server.ESPNConfigurationError):
        server._credentials()


def test_mcp_server_registers_data_tools_without_cookie_arguments() -> None:
    async def inspect_tools() -> None:
        async with Client(server.mcp) as client:
            result = await client.list_tools()
            names = {tool.name for tool in result.tools}
            assert names == {
                "get_league_info",
                "get_team_roster",
                "get_team_info",
                "get_player_stats",
                "get_league_standings",
                "get_matchup_info",
            }
            serialized = " ".join(
                str(tool.input_schema) for tool in result.tools
            ).lower()
            assert "espn_s2" not in serialized
            assert "swid" not in serialized
            assert all(tool.annotations.read_only_hint for tool in result.tools)
            assert all(
                tool.meta == {
                    "securitySchemes": [
                        {"type": "oauth2", "scopes": ["fantasy:read"]}
                    ]
                }
                for tool in result.tools
            )

    asyncio.run(inspect_tools())
