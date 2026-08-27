# ESPN Fantasy Football MCP Server

An MCP server that exposes ESPN fantasy football league, team, roster, player,
standings, and matchup data. It supports local stdio clients and a stateless
Streamable HTTP endpoint suitable for Vercel. Remote HTTP supports ChatGPT's
OAuth 2.1 authorization-code flow with PKCE/S256 as well as a legacy static
bearer key for other MCP clients.

## MCP tools

- `get_league_info`
- `get_team_roster`
- `get_team_info`
- `get_player_stats`
- `get_league_standings`
- `get_matchup_info`

ESPN cookies are intentionally not accepted as tool arguments. For a private
league they are read from server-side environment variables, keeping them out
of MCP transcripts and tool-call logs.

## Local stdio

Install dependencies and run the original local transport:

```bash
uv sync
uv run espn_fantasy_server.py
```

Example Claude Desktop configuration:

```json
{
  "mcpServers": {
    "espn-fantasy-football": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp_espn_ff",
        "run",
        "espn_fantasy_server.py"
      ],
      "env": {
        "ESPN_S2": "your-espn-s2-cookie",
        "ESPN_SWID": "{your-swid-cookie}"
      }
    }
  }
}
```

Omit the `env` section for public leagues.

## Local Streamable HTTP

```bash
uv run uvicorn app:app --host 127.0.0.1 --port 8000
```

- Service information: `http://127.0.0.1:8000/`
- Health check: `http://127.0.0.1:8000/health`
- MCP endpoint: `http://127.0.0.1:8000/api/mcp`

## Environment variables

Copy `.env.example` to a local, ignored environment file or configure the
variables in Vercel. Do not commit their values.

| Variable | Required | Purpose |
| --- | --- | --- |
| `ESPN_S2` | Private leagues | ESPN `espn_s2` cookie value |
| `ESPN_SWID` | Private leagues | ESPN `SWID` cookie value, usually including braces |
| `MCP_API_KEY` | With private credentials | Protects the remote MCP endpoint with a bearer token |
| `OAUTH_SIGNING_SECRET` | ChatGPT OAuth | HMAC signing secret of at least 32 random bytes |
| `OAUTH_LOGIN_PASSWORD` | ChatGPT OAuth | Private passphrase entered by the server owner during account linking |
| `OAUTH_ISSUER_URL` | Production OAuth | Canonical public origin, for example `https://mcp-espn-ff.vercel.app` |
| `MCP_RESOURCE_URL` | Production OAuth | Canonical MCP URL, for example `https://mcp-espn-ff.vercel.app/api/mcp` |
| `LOG_LEVEL` | No | Python log level; defaults to `INFO` |

If ESPN credentials are present without either a complete OAuth configuration
or `MCP_API_KEY`, `/api/mcp` returns `503` rather than exposing private league
data publicly. Legacy clients can continue to send:

```text
Authorization: Bearer <MCP_API_KEY>
```

### ChatGPT OAuth

With the four OAuth variables configured, ChatGPT discovers authentication from:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

The server accepts ChatGPT's Client ID Metadata Document identity, uses the
stable ChatGPT OAuth callback, requires authorization-code + PKCE/S256, echoes
the MCP resource audience into signed tokens, and returns an OAuth discovery
challenge on unauthenticated MCP requests. The six ESPN tools declare the
read-only `fantasy:read` OAuth scope.

In ChatGPT, create a custom plugin/connector with this server URL:

```text
https://mcp-espn-ff.vercel.app/api/mcp
```

Choose OAuth with Client ID Metadata Documents when the builder offers a client
registration choice. The authorization page will ask for
`OAUTH_LOGIN_PASSWORD`; ESPN cookies are never shown to ChatGPT.

## Deploy to Vercel

The repository includes an explicit Python ASGI entrypoint and Vercel function
configuration. From a linked Vercel project:

```bash
vercel link
vercel env add ESPN_S2 production --sensitive
vercel env add ESPN_SWID production --sensitive
vercel env add MCP_API_KEY production --sensitive
vercel env add OAUTH_SIGNING_SECRET production --sensitive
vercel env add OAUTH_LOGIN_PASSWORD production --sensitive
vercel env add OAUTH_ISSUER_URL production
vercel env add MCP_RESOURCE_URL production
vercel --prod
```

You may deploy first without secrets to use public leagues. Before using a
private league, configure both ESPN cookies and at least one complete remote
authentication method, then redeploy. OAuth access tokens expire after one
hour; the server also issues renewed 30-day refresh tokens so ChatGPT can
maintain the connection.

## Tests

```bash
uv run pytest
```

The tests cover ASGI imports and lifespan, OAuth discovery, the consent and
PKCE token flow, bearer protection, credential validation, refresh tokens, and
MCP tool registration without making ESPN network requests.

## Acknowledgements

[cwendt94/espn-api](https://github.com/cwendt94/espn-api) provides the ESPN API
wrapper used by this server.
