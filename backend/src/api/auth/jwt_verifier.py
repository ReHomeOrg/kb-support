"""Верификация Keycloak Bearer JWT (RS256) и маппинг клеймов в `Principal` (#29).

Любая ошибка верификации (подпись/iss/aud/exp/nbf/kid/формат/sub) → 401 (fail-closed).
Маппинг клеймов (конвенция Keycloak protocol-mappers, см. README):
- `sub` → user_id (UUID);
- `kbs_kind` (requester/operator/service/agent, default requester) → kind;
- `kbs_teams` (list) → teams (валидные TicketTeam);
- `kbs_act_sub` (UUID) → on_behalf_of (делегирование Консьержа, on-behalf-of;
  CC-1 / token-exchange RFC 8693). Читается ТОЛЬКО при `kbs_kind=agent`;
- `scope` (OAuth, space-separated) → scopes.
"""

from __future__ import annotations

import uuid
from typing import Any

import jwt

from api.auth.jwks import JwksCache, JwksUnknownKeyError
from api.auth.principal import Principal, PrincipalKind
from api.errors import ProblemException
from api.tickets.enums import TicketTeam

_KIND_VALUES = {kind.value for kind in PrincipalKind}
_TEAM_VALUES = {team.value for team in TicketTeam}


def _parse_kind(value: object) -> PrincipalKind:
    if isinstance(value, str) and value in _KIND_VALUES:
        return PrincipalKind(value)
    return PrincipalKind.REQUESTER


def _parse_act_sub(value: object) -> uuid.UUID | None:
    """`kbs_act_sub` → UUID делегированного пользователя; невалидное → None (fail-closed)."""
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except ValueError:
            return None
    return None


def claims_to_principal(claims: dict[str, Any]) -> Principal:
    """Собрать `Principal` из проверенных клеймов токена."""
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except (KeyError, ValueError) as exc:
        raise ProblemException.unauthorized(detail="Token sub is not a valid uuid") from exc
    raw_teams = claims.get("kbs_teams") or []
    teams = frozenset(
        TicketTeam(team) for team in raw_teams if isinstance(team, str) and team in _TEAM_VALUES
    )
    scopes = frozenset(str(claims.get("scope", "")).split())
    kind = _parse_kind(claims.get("kbs_kind"))
    # Делегирование (on-behalf-of) читаем ТОЛЬКО у агента (defense-in-depth): даже
    # если act_sub-mapper по ошибке навесят на не-agent клиента, имперсонации не будет.
    on_behalf_of = (
        _parse_act_sub(claims.get("kbs_act_sub")) if kind is PrincipalKind.AGENT else None
    )
    return Principal(
        user_id=user_id,
        kind=kind,
        scopes=scopes,
        teams=teams,
        on_behalf_of=on_behalf_of,
    )


class JwtVerifier:
    """Проверяет подпись/claims Keycloak JWT и возвращает `Principal`."""

    def __init__(
        self,
        *,
        jwks: JwksCache,
        issuer: str,
        audience: str,
        algorithms: list[str],
        leeway: int,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        self._leeway = leeway

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                raise jwt.InvalidTokenError("missing kid")
            key = await self._jwks.get_key(kid)
            claims = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._audience or None,
                issuer=self._issuer or None,
                leeway=self._leeway,
                options={"require": ["exp", "sub"], "verify_aud": bool(self._audience)},
            )
        except (jwt.PyJWTError, JwksUnknownKeyError) as exc:
            raise ProblemException.unauthorized(detail="Invalid bearer token") from exc
        return claims_to_principal(claims)
