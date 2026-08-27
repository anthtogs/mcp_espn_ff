"""ESPN Fantasy Football tools exposed through Model Context Protocol."""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import threading
from typing import Any

from espn_api.football import League
from mcp.server import MCPServer
from mcp.types import ToolAnnotations


LOGGER = logging.getLogger("mcp_espn_ff")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())


def default_season() -> int:
    """Return the active NFL fantasy season."""
    today = dt.datetime.now(dt.timezone.utc).date()
    return today.year if today.month >= 7 else today.year - 1


CURRENT_YEAR = default_season()
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)
OAUTH_TOOL_META = {
    "securitySchemes": [{"type": "oauth2", "scopes": ["fantasy:read"]}]
}


class ESPNConfigurationError(RuntimeError):
    """Raised when ESPN credential environment variables are incomplete."""


def _credentials() -> tuple[str | None, str | None]:
    espn_s2 = os.getenv("ESPN_S2") or None
    swid = os.getenv("ESPN_SWID") or None
    if bool(espn_s2) != bool(swid):
        raise ESPNConfigurationError(
            "Private leagues require both ESPN_S2 and ESPN_SWID environment variables."
        )
    return espn_s2, swid


def _credential_fingerprint(espn_s2: str | None, swid: str | None) -> str:
    if not espn_s2 or not swid:
        return "public"
    return hashlib.sha256(f"{espn_s2}\0{swid}".encode()).hexdigest()


class ESPNFantasyFootballAPI:
    """Create and reuse ESPN league clients without retaining raw credentials in keys."""

    def __init__(self, max_cached_leagues: int = 32) -> None:
        self._leagues: dict[tuple[int, int, str], League] = {}
        self._lock = threading.Lock()
        self._max_cached_leagues = max_cached_leagues

    def clear_cache(self) -> None:
        with self._lock:
            self._leagues.clear()

    def get_league(self, league_id: int, year: int = CURRENT_YEAR) -> League:
        if league_id <= 0:
            raise ValueError("league_id must be a positive integer")
        if year < 2000 or year > dt.datetime.now(dt.timezone.utc).year + 1:
            raise ValueError("year must be a valid ESPN fantasy football season")

        espn_s2, swid = _credentials()
        cache_key = (league_id, year, _credential_fingerprint(espn_s2, swid))

        with self._lock:
            cached = self._leagues.get(cache_key)
        if cached is not None:
            return cached

        LOGGER.info("Creating ESPN league client league_id=%s year=%s", league_id, year)
        league = League(
            league_id=league_id,
            year=year,
            espn_s2=espn_s2,
            swid=swid,
        )

        with self._lock:
            if len(self._leagues) >= self._max_cached_leagues:
                self._leagues.pop(next(iter(self._leagues)))
            return self._leagues.setdefault(cache_key, league)


def _error_message(error: Exception) -> str:
    message = str(error)
    lowered = message.lower()
    if "401" in message or "private" in lowered or "unauthorized" in lowered:
        return (
            "ESPN rejected access to this league. For a private league, configure "
            "ESPN_S2 and ESPN_SWID on the server, then redeploy."
        )
    return f"ESPN request failed: {message}"


def _team_by_id(league: League, team_id: int) -> Any:
    # ESPN team ids are not guaranteed to match list positions in every season.
    for team in league.teams:
        if getattr(team, "team_id", None) == team_id:
            return team
    if 1 <= team_id <= len(league.teams):
        return league.teams[team_id - 1]
    raise ValueError(f"team_id must identify one of the league's {len(league.teams)} teams")


api = ESPNFantasyFootballAPI()
mcp = MCPServer(
    "espn-fantasy-football",
    version="0.3.0",
    description="Read ESPN fantasy football league, roster, player, standings, and matchup data.",
    instructions=(
        "Use the requested league id and season. Private-league credentials are configured "
        "by the server owner and must never be requested from the user in tool arguments."
    ),
)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_league_info(league_id: int, year: int = CURRENT_YEAR) -> dict[str, Any] | str:
    """Get basic information about an ESPN fantasy football league."""
    try:
        league = api.get_league(league_id, year)
        return {
            "name": league.settings.name,
            "year": league.year,
            "current_week": league.current_week,
            "nfl_week": league.nfl_week,
            "team_count": len(league.teams),
            "teams": [team.team_name for team in league.teams],
            "scoring_type": league.settings.scoring_type,
        }
    except Exception as error:
        LOGGER.exception("Unable to retrieve league info")
        return _error_message(error)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_team_roster(
    league_id: int, team_id: int, year: int = CURRENT_YEAR
) -> dict[str, Any] | str:
    """Get a team's roster and player totals."""
    try:
        league = api.get_league(league_id, year)
        team = _team_by_id(league, team_id)
        return {
            "team_id": getattr(team, "team_id", team_id),
            "team_name": team.team_name,
            "owners": team.owners,
            "wins": team.wins,
            "losses": team.losses,
            "roster": [
                {
                    "name": player.name,
                    "position": player.position,
                    "pro_team": player.proTeam,
                    "points": player.total_points,
                    "projected_points": player.projected_total_points,
                }
                for player in team.roster
            ],
        }
    except Exception as error:
        LOGGER.exception("Unable to retrieve team roster")
        return _error_message(error)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_team_info(
    league_id: int, team_id: int, year: int = CURRENT_YEAR
) -> dict[str, Any] | str:
    """Get a team's record, scoring totals, transactions, and final standing."""
    try:
        league = api.get_league(league_id, year)
        team = _team_by_id(league, team_id)
        return {
            "team_id": getattr(team, "team_id", team_id),
            "team_name": team.team_name,
            "owners": team.owners,
            "wins": team.wins,
            "losses": team.losses,
            "ties": team.ties,
            "points_for": team.points_for,
            "points_against": team.points_against,
            "acquisitions": team.acquisitions,
            "drops": team.drops,
            "trades": team.trades,
            "playoff_pct": team.playoff_pct,
            "final_standing": team.final_standing,
            "outcomes": team.outcomes,
        }
    except Exception as error:
        LOGGER.exception("Unable to retrieve team info")
        return _error_message(error)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_player_stats(
    league_id: int, player_name: str, year: int = CURRENT_YEAR
) -> dict[str, Any] | str:
    """Find a rostered player by partial name and return season totals."""
    try:
        league = api.get_league(league_id, year)
        query = player_name.strip().casefold()
        if not query:
            raise ValueError("player_name cannot be empty")

        for team in league.teams:
            for player in team.roster:
                if query in player.name.casefold():
                    return {
                        "name": player.name,
                        "position": player.position,
                        "pro_team": player.proTeam,
                        "fantasy_team": team.team_name,
                        "points": player.total_points,
                        "projected_points": player.projected_total_points,
                        "injured": player.injured,
                    }
        return f"Player '{player_name}' was not found on a roster in league {league_id}."
    except Exception as error:
        LOGGER.exception("Unable to retrieve player stats")
        return _error_message(error)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_league_standings(league_id: int, year: int = CURRENT_YEAR) -> list[dict[str, Any]] | str:
    """Get standings sorted by wins and then points scored."""
    try:
        league = api.get_league(league_id, year)
        teams = sorted(
            league.teams,
            key=lambda team: (team.wins, team.points_for),
            reverse=True,
        )
        return [
            {
                "rank": rank,
                "team_id": getattr(team, "team_id", None),
                "team_name": team.team_name,
                "owners": team.owners,
                "wins": team.wins,
                "losses": team.losses,
                "ties": team.ties,
                "points_for": team.points_for,
                "points_against": team.points_against,
            }
            for rank, team in enumerate(teams, start=1)
        ]
    except Exception as error:
        LOGGER.exception("Unable to retrieve league standings")
        return _error_message(error)


@mcp.tool(annotations=READ_ONLY_ANNOTATIONS, meta=OAUTH_TOOL_META)
def get_matchup_info(
    league_id: int, week: int | None = None, year: int = CURRENT_YEAR
) -> list[dict[str, Any]] | str:
    """Get matchup scores for a week, defaulting to the league's current week."""
    try:
        league = api.get_league(league_id, year)
        selected_week = league.current_week if week is None else week
        if selected_week < 1 or selected_week > 18:
            raise ValueError("week must be between 1 and 18")

        results: list[dict[str, Any]] = []
        for matchup in league.box_scores(selected_week):
            away_team = matchup.away_team
            away_score = matchup.away_score if away_team else 0
            if not away_team:
                winner = "BYE"
            elif matchup.home_score > away_score:
                winner = "HOME"
            elif away_score > matchup.home_score:
                winner = "AWAY"
            else:
                winner = "TIE"
            results.append(
                {
                    "week": selected_week,
                    "home_team": matchup.home_team.team_name,
                    "home_score": matchup.home_score,
                    "away_team": away_team.team_name if away_team else "BYE",
                    "away_score": away_score,
                    "winner": winner,
                }
            )
        return results
    except Exception as error:
        LOGGER.exception("Unable to retrieve matchup information")
        return _error_message(error)


def main() -> None:
    """Run the original local stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
