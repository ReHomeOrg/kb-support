"""Unit-тесты storage-level фильтра видимости (NFR-1.2) — проверка SQL-условия."""

from __future__ import annotations

import uuid

from api.auth.principal import Principal, PrincipalKind
from api.tickets.access import visibility_filter
from api.tickets.enums import TicketTeam


def _sql(principal: Principal) -> str:
    """Скомпилированное SQL-условие с подставленными литералами (default dialect)."""
    return str(visibility_filter(principal).compile(compile_kwargs={"literal_binds": True}))


def test_requester_filter_is_owner_only() -> None:
    sql = _sql(Principal(user_id=uuid.uuid4(), kind=PrincipalKind.REQUESTER))
    assert "requester_id" in sql
    assert "team" not in sql


def test_operator_filter_is_owner_or_team() -> None:
    sql = _sql(
        Principal(
            user_id=uuid.uuid4(),
            kind=PrincipalKind.OPERATOR,
            teams=frozenset({TicketTeam.SUPPORT}),
        )
    )
    assert "requester_id" in sql
    assert "team" in sql
    assert "support" in sql


def test_operator_without_team_is_owner_only() -> None:
    sql = _sql(Principal(user_id=uuid.uuid4(), kind=PrincipalKind.OPERATOR, teams=frozenset()))
    assert "team" not in sql


def test_agent_filter_uses_delegated_user_not_agent() -> None:
    """Агент on-behalf-of: видимость по делегированному пользователю (G7), не по sub агента."""
    agent_sub = uuid.uuid4()
    user_sub = uuid.uuid4()
    sql = _sql(Principal(user_id=agent_sub, kind=PrincipalKind.AGENT, on_behalf_of=user_sub))
    # SQL рендерит UUID без дефисов → сравниваем hex-форму.
    assert user_sub.hex in sql
    assert agent_sub.hex not in sql
    assert "team" not in sql
