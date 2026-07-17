"""Unit-тесты верификатора Keycloak JWT (валидный → Principal; негативы → 401)."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from api.auth.jwks import JwksCache
from api.auth.jwt_verifier import JwtVerifier
from api.auth.principal import PrincipalKind
from api.errors import ProblemException
from api.tickets.enums import TicketTeam
from tests.unit.auth.conftest import AUDIENCE, ISSUER, TokenMaker


@pytest.fixture
def verifier(stub_fetcher: Callable[[str], Awaitable[dict[str, Any]]]) -> JwtVerifier:
    cache = JwksCache("u", ttl_seconds=300, fetcher=stub_fetcher)
    return JwtVerifier(jwks=cache, issuer=ISSUER, audience=AUDIENCE, algorithms=["RS256"], leeway=0)


@pytest.mark.asyncio
async def test_valid_token_maps_to_principal(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    user_id = uuid.uuid4()
    token = make_token(
        {
            "sub": str(user_id),
            "kbs_kind": "operator",
            "kbs_teams": ["support", "legal"],
            "scope": "tickets:read tickets:write",
        }
    )
    principal = await verifier.verify(token)
    assert principal.user_id == user_id
    assert principal.kind is PrincipalKind.OPERATOR
    assert principal.teams == frozenset({TicketTeam.SUPPORT, TicketTeam.LEGAL})
    assert "tickets:read" in principal.scopes


@pytest.mark.asyncio
async def test_defaults_when_claims_absent(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    principal = await verifier.verify(make_token())
    assert principal.kind is PrincipalKind.REQUESTER
    assert principal.teams == frozenset()
    assert principal.scopes == frozenset()


@pytest.mark.asyncio
async def test_invalid_team_values_ignored(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    principal = await verifier.verify(make_token({"kbs_teams": ["support", "bogus"]}))
    assert principal.teams == frozenset({TicketTeam.SUPPORT})


@pytest.mark.asyncio
async def test_agent_delegation_claim_maps_to_on_behalf_of(
    verifier: JwtVerifier, make_token: TokenMaker
) -> None:
    agent_sub = uuid.uuid4()
    user_sub = uuid.uuid4()
    token = make_token({"sub": str(agent_sub), "kbs_kind": "agent", "kbs_act_sub": str(user_sub)})
    principal = await verifier.verify(token)
    assert principal.kind is PrincipalKind.AGENT
    assert principal.is_agent is True
    assert principal.on_behalf_of == user_sub
    assert principal.effective_user_id == user_sub


@pytest.mark.asyncio
async def test_act_sub_maps_to_acting_agent(
    verifier: JwtVerifier, make_token: TokenMaker
) -> None:
    # Новая схема CC-1: sub = ПОЛЬЗОВАТЕЛЬ (обмен impersonation), act.sub = агент.
    user_sub = uuid.uuid4()
    token = make_token(
        {
            "sub": str(user_sub),
            "act": {"sub": "kb-concierge-m2m"},
            "azp": "kb-concierge-m2m",
        }
    )
    principal = await verifier.verify(token)
    assert principal.acting_agent == "kb-concierge-m2m"
    assert principal.is_agent is True
    # sub уже = пользователь → on_behalf_of не ставится, видимость от sub.
    assert principal.on_behalf_of is None
    assert principal.user_id == user_sub
    assert principal.effective_user_id == user_sub


@pytest.mark.asyncio
async def test_act_sub_and_legacy_act_sub_conflict_401(
    verifier: JwtVerifier, make_token: TokenMaker
) -> None:
    # Оба клейма делегирования одновременно → неоднозначность → 401 (David, вопрос 4).
    token = make_token(
        {
            "act": {"sub": "kb-concierge-m2m"},
            "azp": "kb-concierge-m2m",
            "kbs_act_sub": str(uuid.uuid4()),
        }
    )
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(token)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_act_sub_azp_mismatch_401(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    # Целостность: act.sub должен совпадать с azp; рассинхрон → 401 (подделка).
    token = make_token({"act": {"sub": "kb-concierge-m2m"}, "azp": "someone-else"})
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(token)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_act_sub_without_azp_accepted(
    verifier: JwtVerifier, make_token: TokenMaker
) -> None:
    # Нет azp — целостность не проверяем (мягко), act.sub принимается.
    principal = await verifier.verify(make_token({"act": {"sub": "kb-concierge-m2m"}}))
    assert principal.acting_agent == "kb-concierge-m2m"
    assert principal.is_agent is True


@pytest.mark.asyncio
async def test_invalid_act_sub_ignored(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    # Агент с битым act_sub: fail-closed → on_behalf_of None, видимость от своего sub.
    principal = await verifier.verify(
        make_token({"kbs_kind": "agent", "kbs_act_sub": "not-a-uuid"})
    )
    assert principal.on_behalf_of is None
    assert principal.effective_user_id == principal.user_id


@pytest.mark.asyncio
async def test_act_sub_ignored_for_non_agent(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    # Defense-in-depth: act_sub у не-agent субъекта НЕ даёт делегирования, даже если валиден.
    user_sub = uuid.uuid4()
    principal = await verifier.verify(
        make_token({"kbs_kind": "requester", "kbs_act_sub": str(user_sub)})
    )
    assert principal.kind is PrincipalKind.REQUESTER
    assert principal.on_behalf_of is None
    assert principal.effective_user_id == principal.user_id


@pytest.mark.asyncio
async def test_expired_token_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(make_token(exp_delta=-10))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_wrong_signature_rejected(
    verifier: JwtVerifier, make_token: TokenMaker, other_private_pem: str
) -> None:
    # Подписан чужим ключом, но kid указывает на наш публичный → mismatch.
    token = make_token(key=other_private_pem)
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(token)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_wrong_audience_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(make_token({"aud": "some-other-service"}))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(make_token({"iss": "https://evil.example/realms/x"}))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_unknown_kid_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(make_token(kid="unknown-kid"))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_malformed_token_rejected(verifier: JwtVerifier) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify("not.a.valid.jwt")
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_non_uuid_sub_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(make_token({"sub": "not-a-uuid"}))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_token_without_kid_rejected(verifier: JwtVerifier, make_token: TokenMaker) -> None:
    token = make_token(kid=None)
    with pytest.raises(ProblemException) as exc:
        await verifier.verify(token)
    assert exc.value.status == 401
