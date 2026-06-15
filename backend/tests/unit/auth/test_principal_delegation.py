"""Unit-тесты делегирования в `Principal` (FR-9.7): effective_user_id / is_agent."""

from __future__ import annotations

import uuid

from api.auth.principal import Principal, PrincipalKind


def test_non_agent_effective_user_is_self() -> None:
    uid = uuid.uuid4()
    principal = Principal(user_id=uid, kind=PrincipalKind.REQUESTER)
    assert principal.is_agent is False
    assert principal.on_behalf_of is None
    assert principal.effective_user_id == uid


def test_agent_effective_user_is_delegated() -> None:
    agent_sub = uuid.uuid4()
    user_sub = uuid.uuid4()
    principal = Principal(user_id=agent_sub, kind=PrincipalKind.AGENT, on_behalf_of=user_sub)
    assert principal.is_agent is True
    assert principal.effective_user_id == user_sub


def test_agent_without_delegation_falls_back_to_self() -> None:
    # kbs_kind=agent без kbs_act_sub: on_behalf_of=None → видимость от своего sub
    # (fail-closed; делегирования нет, агент не получает чужих данных).
    agent_sub = uuid.uuid4()
    principal = Principal(user_id=agent_sub, kind=PrincipalKind.AGENT)
    assert principal.is_agent is True
    assert principal.effective_user_id == agent_sub
