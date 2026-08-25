"""Инвариант: claims-тип ⇒ инициализированное разбирательство (issue #215).

Претензионная заявка обязана иметь `case_state`, `TicketCaseDetails` и срок
рассмотрения. Без них решение и переходы отвечают 422 — то есть претензию нельзя
вести вообще, хотя по типу она претензионная.

Инициализация держалась на одном пути — generic `POST /tickets`. Claims-тип умеют
выставлять ещё два: эскалация из чата (`TicketFromChat.type` принимает все четыре
claims-типа) и PATCH оператора. Здесь проверены все три плюс то, что повторная
инициализация не откатывает уже начатое разбирательство.

Требует Postgres (CI service container / локально POSTGRES_AVAILABLE=1).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from api.auth.dependencies import get_current_principal
from api.auth.principal import Principal, PrincipalKind
from api.auth.scopes import STAFF_ADMIN_SCOPE
from api.config import get_settings
from api.db import get_session
from api.main import app
from api.tickets.enums import TicketTeam

pytestmark = pytest.mark.skipif(
    "CI" not in os.environ and "POSTGRES_AVAILABLE" not in os.environ,
    reason="Требует живой Postgres (CI service / POSTGRES_AVAILABLE=1).",
)

_SERVICE = Principal(user_id=uuid.uuid4(), kind=PrincipalKind.SERVICE)


def _use(principal: Principal) -> None:
    app.dependency_overrides[get_current_principal] = lambda: principal


def _operator(team: TicketTeam = TicketTeam.SUPPORT) -> Principal:
    return Principal(user_id=uuid.uuid4(), kind=PrincipalKind.OPERATOR, teams=frozenset({team}))


def _admin() -> Principal:
    """Оператор со staff-admin: видит заявки вне своей команды (заявка из чата — без team)."""
    return Principal(
        user_id=uuid.uuid4(),
        kind=PrincipalKind.OPERATOR,
        scopes=frozenset({STAFF_ADMIN_SCOPE}),
        teams=frozenset({TicketTeam.SUPPORT}),
    )


@pytest.fixture(autouse=True)
def _override_db_session() -> Iterator[None]:
    """NullPool-движок на текущем event loop (паттерн integration-тестов — cross-loop asyncpg)."""
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _get_test_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _get_test_session
    yield
    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_principal, None)
    asyncio.run(engine.dispose())


def _get(client: TestClient, ticket_id: str) -> dict[str, object]:
    resp = client.get(f"/api/v1/support/tickets/{ticket_id}")
    assert resp.status_code == 200, resp.text
    return dict(resp.json()["data"])


def _patch(client: TestClient, ticket_id: str, **body: object) -> Response:
    return client.patch(f"/api/v1/support/tickets/{ticket_id}", json=body)


def _assert_case_initialized(data: dict[str, object]) -> None:
    assert data["case_state"] == "CLAIM_SUBMITTED", "разбирательство не начато"
    assert data["case_details"] is not None, "нет TicketCaseDetails"
    assert data["resolution_due_at"] is not None, "не выставлен срок рассмотрения"


def test_generic_create_initializes_the_case(client: TestClient) -> None:
    """Контрольный путь: он работал и раньше — фиксируем как эталон."""
    _use(_operator())
    created = client.post(
        "/api/v1/support/tickets", json={"subject": "Претензия", "type": "COMPENSATION"}
    )
    assert created.status_code == 201, created.text

    _assert_case_initialized(_get(client, created.json()["data"]["id"]))


def test_chat_escalation_with_claims_type_initializes_the_case(client: TestClient) -> None:
    """Эскалация из AI-чата несёт claims-тип — разбирательство должно начаться.

    Раньше комментарий в коде утверждал, что claims-типы этим путём недостижимы;
    схема `TicketFromChat` принимает их все четыре, и заявка получалась
    претензионной по типу, но без разбирательства.
    """
    requester_id = uuid.uuid4()
    _use(_SERVICE)
    created = client.post(
        "/api/v1/support/tickets/from-chat",
        json={
            "chat_session_id": str(uuid.uuid4()),
            "requester_id": str(requester_id),
            "type": "INSURANCE",
            "transcript": [{"role": "user", "content": "залив у соседей"}],
        },
    )
    assert created.status_code == 201, created.text
    ticket_id = created.json()["data"]["id"]

    # Читаем от имени заявителя: заявка из чата приходит без команды, и оператор её
    # по видимости не увидит (visibility_filter — по своим командам).
    _use(Principal(user_id=requester_id, kind=PrincipalKind.REQUESTER))
    _assert_case_initialized(_get(client, ticket_id))


def test_reclassifying_a_ticket_into_a_claims_type_initializes_the_case(
    client: TestClient,
) -> None:
    """Оператор переклассифицировал обычную заявку в претензионную."""
    _use(_operator())
    created = client.post("/api/v1/support/tickets", json={"subject": "Вопрос", "type": "OTHER"})
    assert created.status_code == 201, created.text
    ticket_id = created.json()["data"]["id"]
    assert _get(client, ticket_id)["case_state"] is None, "предусловие: разбирательства нет"

    assert _patch(client, ticket_id, type="GUARANTEE").status_code == 200

    _assert_case_initialized(_get(client, ticket_id))


def test_reclassifying_does_not_restart_an_ongoing_case(client: TestClient) -> None:
    """Уже начатое разбирательство повторная инициализация не откатывает.

    `apply_claim_intake` сбрасывает case_state в CLAIM_SUBMITTED и пересчитывает срок
    рассмотрения, а детали 1:1 — второй вызов на ведущемся деле вернул бы его к
    началу и потерял бы стадию.
    """
    _use(_operator())
    created = client.post(
        "/api/v1/support/tickets", json={"subject": "Претензия", "type": "COMPENSATION"}
    )
    ticket_id = created.json()["data"]["id"]
    assert (
        client.post(
            f"/api/v1/support/tickets/{ticket_id}/case-state",
            json={"case_state": "UNDER_REVIEW"},
        ).status_code
        == 200
    )

    assert _patch(client, ticket_id, priority="high").status_code == 200

    assert _get(client, ticket_id)["case_state"] == "UNDER_REVIEW", "стадия сохранена"
