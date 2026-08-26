# ESPN Fantasy Football MCP Server

An MCP server that exposes ESPN fantasy football league, team, roster, player,
standings, and matchup data. It supports local stdio clients and a stateless
Streamable HTTP endpoint suitable for Vercel.

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
| `LOG_LEVEL` | No | Python log level; defaults to `INFO` |

If either ESPN credential is present without `MCP_API_KEY`, `/api/mcp` returns
`503` rather than exposing private league data publicly. With an API key,
remote clients must send:

```text
Authorization: Bearer <MCP_API_KEY>
```

## Deploy to Vercel

The repository includes an explicit Python ASGI entrypoint and Vercel function
configuration. From a linked Vercel project:

```bash
vercel link
vercel env add ESPN_S2 production --sensitive
vercel env add ESPN_SWID production --sensitive
vercel env add MCP_API_KEY production --sensitive
vercel --prod
```

You may deploy first without secrets to use public leagues. Add all three
secrets before using a private league, then redeploy so the new deployment
receives them.

## Tests

```bash
uv run pytest
```

The tests cover ASGI imports and lifespan, health routes, bearer protection,
credential validation, and MCP tool registration without making ESPN network
requests.

## Acknowledgements

[cwendt94/espn-api](https://github.com/cwendt94/espn-api) provides the ESPN API
wrapper used by this server.
