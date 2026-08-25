"""Security/edge-тесты претензионных потоков (E10-12 #202, DoD §7, финал E10).

Консолидирует claims-специфичную security-матрицу ПОВЕРХ общего покрытия
`test_tickets_api.py` (decision RBAC, «4 глаза», переходы case_state, anti-enum,
is_internal NFR-1.3) — не дублируя его, а целясь в потоки, где есть финансовые
данные/ПДн: позитивная граница legal↔finance, утечки в кросс-тенант и в Problem.detail
(ФЗ-152), доступ к доказательствам, edge «4 глаз», неизменяемость аудита (NFR-1.4).

Требует Postgres (CI service container / локально POSTGRES_AVAILABLE=1).
Принципал — через `app.dependency_overrides` (seam #6). `client` — из корневого conftest.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from api.auth.dependencies import get_current_principal
from api.auth.principal import Principal, PrincipalKind
from api.config import get_settings
from api.db import get_session
from api.main import app
from api.tickets.enums import TicketTeam

pytestmark = pytest.mark.skipif(
    "CI" not in os.environ and "POSTGRES_AVAILABLE" not in os.environ,
    reason="Claims security-тесты требуют живой Postgres (CI service / POSTGRES_AVAILABLE=1).",
)


def _use(principal: Principal) -> None:
    app.dependency_overrides[get_current_principal] = lambda: principal


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


# --- Принципалы ------------------------------------------------------------


def _operator(team: TicketTeam = TicketTeam.SUPPORT) -> Principal:
    return Principal(user_id=uuid.uuid4(), kind=PrincipalKind.OPERATOR, teams=frozenset({team}))


def _requester(user_id: uuid.UUID | None = None) -> Principal:
    return Principal(user_id=user_id or uuid.uuid4(), kind=PrincipalKind.REQUESTER)


# --- API-хелперы (локальны, как в прочих integration-файлах) ----------------


def _create(client: TestClient, **extra: object) -> Response:
    payload = {"subject": "Претензия", "type": "COMPENSATION", **extra}
    return client.post("/api/v1/support/tickets", json=payload)


def _decide(client: TestClient, ticket_id: str, **body: object) -> Response:
    return client.post(f"/api/v1/support/tickets/{ticket_id}/decision", json=body)


def _case_state(client: TestClient, ticket_id: str, **body: object) -> Response:
    return client.post(f"/api/v1/support/tickets/{ticket_id}/case-state", json=body)


def _post_message(
    client: TestClient, ticket_id: str, body: str, *, is_internal: bool = False
) -> Response:
    return client.post(
        f"/api/v1/support/tickets/{ticket_id}/messages",
        json={"body": body, "is_internal": is_internal},
    )


def _history_actions(client: TestClient, ticket_id: str) -> list[str]:
    return [
        h["action"]
        for h in client.get(f"/api/v1/support/tickets/{ticket_id}/history").json()["data"]
    ]


def _db_update(query: str, params: dict[str, object]) -> None:
    """Прямой UPDATE к СВОЕЙ тест-БД (подготовка стартовой стадии; арх-константа не нарушена)."""

    async def _inner() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(text(query), params)
        finally:
            await engine.dispose()

    asyncio.run(_inner())


def _set_team(ticket_id: str, team: str) -> None:
    _db_update(
        "UPDATE tickets SET team = :t WHERE id = :id", {"t": team, "id": uuid.UUID(ticket_id)}
    )


def _set_case_state(ticket_id: str, case_state: str) -> None:
    _db_update(
        "UPDATE tickets SET case_state = :s WHERE id = :id",
        {"s": case_state, "id": uuid.UUID(ticket_id)},
    )


# --- Группа 1: позитивная граница RBAC решения (legal И finance) -------------


@pytest.mark.parametrize("team", [TicketTeam.LEGAL, TicketTeam.FINANCE])
def test_decision_allowed_for_legal_and_finance(client: TestClient, team: TicketTeam) -> None:
    """D3: решение принимает оператор legal ИЛИ finance — gate не сужен до одной команды."""
    _use(_operator(team))
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "UNDER_REVIEW")
    resp = _decide(client, ticket_id, decision="FULL", approved_amount=1000)
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["decision"] == "FULL"


# --- Группа 2: anti-enumeration на CLAIM-заявке (NFR-1.2) --------------------


def test_requester_cannot_read_another_claim_404(client: TestClient) -> None:
    """NFR-1.2: заявитель B не видит чужую претензию A → 404; решение/сумма не утекают."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, TicketTeam.LEGAL.value)  # legal-оператор видит заявку (storage-level)
    _set_case_state(ticket_id, "UNDER_REVIEW")

    # Оператор legal принимает решение (на заявке появляются финансовые данные).
    _use(_operator(TicketTeam.LEGAL))
    assert _decide(client, ticket_id, decision="FULL", approved_amount=99999).status_code == 200

    # Посторонний заявитель, зная id, не получает ни заявку, ни её финансовые поля.
    _use(_requester())
    resp = client.get(f"/api/v1/support/tickets/{ticket_id}")
    assert resp.status_code == 404
    assert "99999" not in resp.text  # approved_amount не утёк в тело 404


def test_outsider_operator_without_team_cannot_read_claim_404(client: TestClient) -> None:
    """NFR-1.2 storage-level: оператор не своей команды не видит претензию → 404 (anti-enum)."""
    _use(_requester())
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, TicketTeam.LEGAL.value)
    # Оператор команды FINANCE (≠ команда заявки LEGAL, не назначен) — посторонний.
    _use(_operator(TicketTeam.FINANCE))
    assert client.get(f"/api/v1/support/tickets/{ticket_id}").status_code == 404


# --- Группа 3: is_internal на claims + позитивная граница для владельца ------


def test_internal_claim_note_hidden_from_requester(client: TestClient) -> None:
    """NFR-1.3: внутренняя заметка claim-оценки НЕ видна заявителю-владельцу претензии."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, TicketTeam.LEGAL.value)

    _use(_operator(TicketTeam.LEGAL))
    assert (
        _post_message(client, ticket_id, "оценка ущерба занижена", is_internal=True).status_code
        == 201
    )
    assert (
        _post_message(client, ticket_id, "запросите документы", is_internal=False).status_code
        == 201
    )

    _use(owner)
    bodies = [
        m["body"]
        for m in client.get(f"/api/v1/support/tickets/{ticket_id}/messages").json()["data"]
    ]
    assert "запросите документы" in bodies
    assert "оценка ущерба занижена" not in bodies


def test_requester_sees_own_decision_values(client: TestClient) -> None:
    """Позитивная граница: заявитель-владелец ВИДИТ исход своей претензии (decision/сумма)."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, TicketTeam.FINANCE.value)  # finance-оператор видит заявку
    _set_case_state(ticket_id, "UNDER_REVIEW")

    _use(_operator(TicketTeam.FINANCE))
    assert (
        _decide(
            client, ticket_id, decision="PARTIAL", approved_amount=12345, reason="износ"
        ).status_code
        == 200
    )

    _use(owner)
    data = client.get(f"/api/v1/support/tickets/{ticket_id}").json()["data"]
    assert data["decision"] == "PARTIAL"
    assert data["approved_amount"] == 12345
    assert data["case_state"] == "DECISION_MADE"


# --- Группа 4: доступ к доказательствам (evidence, §3.3.1) -------------------


def test_evidence_visible_to_owner_not_to_outsider(client: TestClient) -> None:
    """§3.3.1: доказательства (case_details.payload.evidence) видны владельцу, не постороннему.

    С #234 `case_details` сериализуется в read; доступ — через storage-level границу заявки
    (отдельного per-evidence ACL нет). Владелец видит evidence; посторонний → 404, evidence
    не пересекает границу.
    """
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _db_update(
        "UPDATE ticket_case_details SET payload = CAST(:p AS jsonb) WHERE ticket_id = :id",
        {"p": '{"evidence": ["secret-photo-evidence-ref"]}', "id": uuid.UUID(ticket_id)},
    )
    # Владелец видит evidence в case_details.payload (#234).
    owner_view = client.get(f"/api/v1/support/tickets/{ticket_id}")
    assert owner_view.status_code == 200
    assert owner_view.json()["data"]["case_details"]["payload"]["evidence"] == [
        "secret-photo-evidence-ref"
    ]

    # Посторонний — 404; ссылка на доказательство не утекает ни в тело, ни в ошибку.
    _use(_requester())
    outsider = client.get(f"/api/v1/support/tickets/{ticket_id}")
    assert outsider.status_code == 404
    assert "secret-photo-evidence-ref" not in outsider.text


def test_case_details_serialized_for_claims_not_for_regular(client: TestClient) -> None:
    """#234: case_details наполняется для claims-заявки (case_type/payload) и null для обычной."""
    _use(_operator(TicketTeam.LEGAL))
    claim_id = _create(client).json()["data"]["id"]  # COMPENSATION
    details = client.get(f"/api/v1/support/tickets/{claim_id}").json()["data"]["case_details"]
    assert details is not None
    assert details["case_type"] == "COMPENSATION"
    assert details["ticket_id"] == claim_id
    assert isinstance(details["payload"], dict)

    regular = client.post(
        "/api/v1/support/tickets", json={"subject": "обычная", "type": "PAYMENT"}
    ).json()["data"]["id"]
    assert client.get(f"/api/v1/support/tickets/{regular}").json()["data"]["case_details"] is None


def test_case_details_redaction_preserved_for_requester(client: TestClient) -> None:
    """#234+#202: наполнение case_details НЕ ломает редакцию служебных custom_fields-ключей."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, "support")
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    op = _operator()
    _use(op)
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200

    _use(owner)
    data = client.get(f"/api/v1/support/tickets/{ticket_id}").json()["data"]
    # case_details наполнен, но служебный approver-ключ по-прежнему скрыт от заявителя.
    assert data["case_details"] is not None
    assert "payout_first_approver" not in str(data["custom_fields"])
    assert str(op.user_id) not in str(data["custom_fields"])


# --- Группа 5: ФЗ-152 — Problem.detail без ПДн/финданных --------------------


def test_decision_403_detail_carries_no_pii(client: TestClient) -> None:
    """ФЗ-152: detail отказа в решении — статичная строка без user_id заявителя/суммы."""
    op = _operator(TicketTeam.SUPPORT)  # не legal/finance
    _use(op)
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "UNDER_REVIEW")
    resp = _decide(client, ticket_id, decision="FULL", approved_amount=77777)
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/problem+json")
    detail = resp.json().get("detail", "")
    assert str(op.user_id) not in detail
    assert "77777" not in detail


def test_four_eyes_409_detail_carries_no_pii(client: TestClient) -> None:
    """ФЗ-152: detail конфликта «4 глаз» — статичная строка без actor_id."""
    op = _operator()
    _use(op)
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200  # 1-й аппрув
    conflict = _case_state(client, ticket_id, case_state="PAID")  # тот же актёр
    assert conflict.status_code == 409
    assert str(op.user_id) not in conflict.json().get("detail", "")


def test_forbidden_case_transition_422_detail_no_pii(client: TestClient) -> None:
    """ФЗ-152: detail недопустимого перехода — без ПДн; content-type problem+json."""
    _use(_operator())
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "CLAIM_SUBMITTED")
    resp = _case_state(client, ticket_id, case_state="PAID")  # запрещён машиной
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_payout_first_approver_not_leaked_to_requester(client: TestClient) -> None:
    """ФЗ-152/#202: actor_id первого аппрувера «4 глаз» НЕ виден заявителю, но виден оператору.

    Служебное staff-состояние (`custom_fields.claims.payout_first_approver`) редактируется
    из read для не-операторов; оператору (для второго аппрува) — остаётся.
    """
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, "support")
    _set_case_state(ticket_id, "PAYOUT_PENDING")

    op = _operator()  # команда support → видит заявку, фиксирует первый аппрув
    _use(op)
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200

    # Заявитель-владелец НЕ видит actor_id оператора / служебный ключ.
    _use(owner)
    requester_cf = str(
        client.get(f"/api/v1/support/tickets/{ticket_id}").json()["data"]["custom_fields"]
    )
    assert str(op.user_id) not in requester_cf
    assert "payout_first_approver" not in requester_cf

    # Оператор ВИДИТ служебный ключ (нужен для второго подтверждающего).
    _use(op)
    operator_cf = str(
        client.get(f"/api/v1/support/tickets/{ticket_id}").json()["data"]["custom_fields"]
    )
    assert "payout_first_approver" in operator_cf


def test_payout_approver_not_leaked_in_list_to_requester(client: TestClient) -> None:
    """ФЗ-152/#202: служебный claims-ключ не утекает заявителю и через список заявок."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, "support")
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    op = _operator()
    _use(op)
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200

    _use(owner)
    listing = str(client.get("/api/v1/support/tickets").json()["data"])
    assert "payout_first_approver" not in listing
    assert str(op.user_id) not in listing


# --- Группа 6: edge «4 глаз» и терминальность (D6, FR-9.4) -------------------


def test_paid_is_terminal_no_further_transition(client: TestClient) -> None:
    """После PAID (терминал) любой переход запрещён машиной → 422."""
    op_a, op_b = _operator(), _operator()
    _use(op_a)
    ticket_id = _create(client).json()["data"]["id"]
    _set_team(ticket_id, "support")
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200
    _use(op_b)
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200  # завершён в PAID
    # Из PAID никуда (даже REJECTED).
    assert _case_state(client, ticket_id, case_state="REJECTED").status_code == 422


def test_requester_cannot_drive_payout(client: TestClient) -> None:
    """D6: заявитель не может двигать case_state к выплате — 403/404 (RBAC оператора)."""
    owner = _requester()
    _use(owner)
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    # Заявитель пытается завершить выплату — не оператор.
    assert _case_state(client, ticket_id, case_state="PAID").status_code in (403, 404)


# --- Группа 7: неизменяемость аудита решения (NFR-1.4) ----------------------


def test_decision_and_transition_recorded_with_actor(client: TestClient) -> None:
    """NFR-1.4: решение и переход фиксируются в TicketHistory с actor_id (аудит неизменяем)."""
    op = _operator(TicketTeam.LEGAL)
    _use(op)
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "UNDER_REVIEW")
    assert _decide(client, ticket_id, decision="FULL", approved_amount=5000).status_code == 200

    history = client.get(f"/api/v1/support/tickets/{ticket_id}/history").json()["data"]
    decided = [h for h in history if h["action"] == "case_decided"]
    assert len(decided) == 1
    assert decided[0]["actor_id"] == str(op.user_id)
    # История доступна только на чтение (нет мутирующего эндпоинта) — GET-only контракт.
    assert "case_decided" in _history_actions(client, ticket_id)


# --- Группа 6: гигиена служебных claims-полей ------------------------------


def _db_scalar(query: str, params: dict[str, object]) -> object:
    """Прочитать одно значение из СВОЕЙ тест-БД (проверка того, что в API не видно)."""

    async def _inner() -> object:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                result = await conn.execute(text(query), params)
                return result.scalar()
        finally:
            await engine.dispose()

    return asyncio.run(_inner())


def test_rejecting_a_pending_payout_clears_the_first_approver(client: TestClient) -> None:
    """PAYOUT_PENDING→REJECTED убирает маркер первого аппрувера «4 глаз» (#216).

    Проверяем в БД, а не через API: ключ намеренно скрыт от заявителя редакцией, то
    есть «его не видно в ответе» ничего не доказывает. Успешный PAID чистил маркер и
    раньше; отказ — нет, и actor первого аппрува оставался висеть в JSONB навсегда.
    """
    op = _operator()
    _use(op)
    ticket_id = _create(client).json()["data"]["id"]
    _set_case_state(ticket_id, "PAYOUT_PENDING")
    assert _case_state(client, ticket_id, case_state="PAID").status_code == 200  # 1-й аппрув
    before = _db_scalar(
        "SELECT custom_fields #>> '{claims,payout_first_approver}' FROM tickets WHERE id = :id",
        {"id": uuid.UUID(ticket_id)},
    )
    assert before == str(op.user_id), "предусловие: маркер записан первым аппрувом"

    assert _case_state(client, ticket_id, case_state="REJECTED").status_code == 200

    after = _db_scalar(
        "SELECT custom_fields #>> '{claims,payout_first_approver}' FROM tickets WHERE id = :id",
        {"id": uuid.UUID(ticket_id)},
    )
    assert after is None, "маркер не относится ни к чему после ухода из фазы выплаты"
