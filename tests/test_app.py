from __future__ import annotations

import asyncio

import pytest
from mcp import Client
from starlette.testclient import TestClient

import espn_fantasy_server as server
from app import app


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

    asyncio.run(inspect_tools())
