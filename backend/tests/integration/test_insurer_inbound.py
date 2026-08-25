"""Integration-тесты inbound webhook страховщика (E10-8 PR-C #198) — требуют Postgres.

Покрывают: m2m-only (не-SERVICE → 403); config-gate/anti-spoofing (нет секрета или
невалидная подпись → 403); валидный приём → проставляет insurance_event_id + триггерит
outbound ticket.insurance_event; идемпотентность по insurance_event_id; 404 на чужую/
не-INSURANCE заявку. Доставка outbound замокана.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import os
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from api.auth.dependencies import get_current_principal
from api.auth.principal import Principal, PrincipalKind
from api.config import get_settings
from api.db import get_session
from api.main import app
from api.tickets.case_repository import TicketCaseDetailsRepository
from api.tickets.enums import TicketTeam
from api.webhooks.events import WebhookDelivery
from api.webhooks.signing import compute_signature

pytestmark = pytest.mark.skipif(
    "CI" not in os.environ and "POSTGRES_AVAILABLE" not in os.environ,
    reason="Inbound webhook требует живой Postgres (CI service container / POSTGRES_AVAILABLE=1).",
)

_SECRET = "test-insurer-inbound-secret-1234"
_INSURER_EVENTS = "/api/v1/support/insurer-events"

_SERVICE = Principal(user_id=uuid.uuid4(), kind=PrincipalKind.SERVICE)
_OPERATOR = Principal(
    user_id=uuid.uuid4(), kind=PrincipalKind.OPERATOR, teams=frozenset({TicketTeam.SUPPORT})
)


def _use(principal: Principal) -> None:
    app.dependency_overrides[get_current_principal] = lambda: principal


@pytest.fixture(autouse=True)
def _override_db_session() -> Iterator[None]:
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


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def _enable_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Включить инбаунд-секрет (по умолчанию пусто → fail-closed)."""
    replacement = get_settings().model_copy(update={"insurer_inbound_secret": _SECRET})
    monkeypatch.setattr("api.webhooks.inbound.get_settings", lambda: replacement)


def _signed(body: dict[str, str]) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    ts = int(datetime.datetime.now(datetime.UTC).timestamp())
    sig = f"t={ts},v1={compute_signature(payload=raw, secret=_SECRET, timestamp=ts)}"
    return raw, {"Content-Type": "application/json", "X-Signature": sig}


def _create_insurance_claim(client: TestClient) -> str:
    _use(_OPERATOR)
    created = client.post(
        "/api/v1/support/tickets", json={"subject": "страховой случай", "type": "INSURANCE"}
    )
    assert created.status_code == 201, created.text
    return str(created.json()["data"]["number"])


def test_non_service_principal_forbidden(client: TestClient) -> None:
    _use(_OPERATOR)
    raw, headers = _signed(
        {"ticket_number": "RH-2026-00001", "insurance_event_id": str(uuid.uuid4())}
    )
    assert client.post(_INSURER_EVENTS, content=raw, headers=headers).status_code == 403


def test_secret_off_is_fail_closed(client: TestClient) -> None:
    # Дефолтный insurer_inbound_secret пуст → приём отклоняется даже от SERVICE.
    _use(_SERVICE)
    raw, headers = _signed(
        {"ticket_number": "RH-2026-00001", "insurance_event_id": str(uuid.uuid4())}
    )
    assert client.post(_INSURER_EVENTS, content=raw, headers=headers).status_code == 403


def test_invalid_signature_forbidden(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_secret(monkeypatch)
    _use(_SERVICE)
    body = json.dumps({"ticket_number": "RH-2026-00001", "insurance_event_id": str(uuid.uuid4())})
    resp = client.post(
        _INSURER_EVENTS,
        content=body.encode(),
        headers={"Content-Type": "application/json", "X-Signature": "t=123,v1=deadbeef"},
    )
    assert resp.status_code == 403


def test_unknown_or_non_insurance_404(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_secret(monkeypatch)
    # неизвестный номер
    _use(_SERVICE)
    raw, headers = _signed(
        {"ticket_number": "RH-9999-99999", "insurance_event_id": str(uuid.uuid4())}
    )
    assert client.post(_INSURER_EVENTS, content=raw, headers=headers).status_code == 404

    # существующая, но НЕ INSURANCE (PAYMENT, case_state=None) → 404
    _use(_OPERATOR)
    payment = client.post("/api/v1/support/tickets", json={"subject": "s", "type": "PAYMENT"})
    number = payment.json()["data"]["number"]
    _use(_SERVICE)
    raw, headers = _signed({"ticket_number": number, "insurance_event_id": str(uuid.uuid4())})
    assert client.post(_INSURER_EVENTS, content=raw, headers=headers).status_code == 404


def test_valid_sets_event_and_triggers_outbound(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[WebhookDelivery] = []

    async def _fake(url: str, secret: str, delivery: WebhookDelivery, settings: object) -> None:
        captured.append(delivery)

    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _fake)
    _enable_secret(monkeypatch)

    number = _create_insurance_claim(client)
    # подписка на исходящее insurance_event (чтобы триггер был наблюдаем)
    _use(
        Principal(
            user_id=uuid.uuid4(),
            kind=PrincipalKind.OPERATOR,
            scopes=frozenset({"staff_admin"}),
            teams=frozenset({TicketTeam.SUPPORT}),
        )
    )
    sub = client.post(
        "/api/v1/support/webhooks",
        json={
            "url": f"https://ins-{uuid.uuid4().hex}.example.com/h",
            "events": ["ticket.insurance_event"],
        },
    )
    assert sub.status_code == 201, sub.text

    event_id = str(uuid.uuid4())
    _use(_SERVICE)
    raw, headers = _signed({"ticket_number": number, "insurance_event_id": event_id})
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["data"]["insurance_event_id"] == event_id
    assert captured, "переход insurance_event_id должен триггерить outbound insurance_event"
    assert all(d.event == "ticket.insurance_event" for d in captured)

    # Идемпотентность: повтор той же доставки → no-op, без нового триггера.
    before = len(captured)
    repeat = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert repeat.status_code == 202
    assert len(captured) == before, "повтор того же insurance_event_id не должен ретриггерить"


# --- E10-10 PR-C (#200): вердикт страховщика → insurer_status + системный case_state (D2) ---


def _to_under_review(client: TestClient, ticket_id: str) -> None:
    """Перевести claims-заявку CLAIM_SUBMITTED → UNDER_REVIEW оператором (для вердикта)."""
    _use(_OPERATOR)
    resp = client.post(
        f"/api/v1/support/tickets/{ticket_id}/case-state", json={"case_state": "UNDER_REVIEW"}
    )
    assert resp.status_code == 200, resp.text


def _ticket_id_by_number(client: TestClient, number: str) -> str:
    _use(_OPERATOR)
    listing = client.get("/api/v1/support/tickets", params={"limit": 100})
    assert listing.status_code == 200, listing.text
    for item in listing.json()["data"]:
        if str(item["number"]) == number:
            return str(item["id"])
    raise AssertionError(f"ticket {number} not found")


def _get_ticket(client: TestClient, ticket_id: str) -> dict[str, object]:
    _use(_OPERATOR)
    resp = client.get(f"/api/v1/support/tickets/{ticket_id}")
    assert resp.status_code == 200, resp.text
    return dict(resp.json()["data"])


def test_backward_compatible_without_verdict_fields(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E10-8 чистый приём (только insurance_event_id) работает без новых полей."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    _use(_SERVICE)
    raw, headers = _signed({"ticket_number": number, "insurance_event_id": str(uuid.uuid4())})
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    # case_state не сдвинут вердиктом (его нет) — остался CLAIM_SUBMITTED.
    assert resp.json()["data"]["case_state"] == "CLAIM_SUBMITTED"


def test_verdict_approved_moves_case_state_without_our_decision(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """APPROVED из UNDER_REVIEW → DECISION_MADE; ticket.decision НЕ трогается (D2)."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _to_under_review(client, ticket_id)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_status": "approved_by_insurer",
            "insurer_decision": "APPROVED",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["data"]["case_state"] == "DECISION_MADE"
    data = _get_ticket(client, ticket_id)
    assert data["decision"] is None, "наш decide() НЕ применяется на вердикт страховщика (D2)"


def test_verdict_rejected_moves_to_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _to_under_review(client, ticket_id)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_decision": "REJECTED",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    data = resp.json()["data"]
    assert data["case_state"] == "REJECTED"
    # #211: вердикт REJECTED — терминал claims → заявка системно закрыта в RESOLVED
    # (иначе INSURANCE-заявка осталась бы под SLA-эскалацией; путь insurer-webhook).
    assert data["status"] == "RESOLVED"


def test_status_only_saved_without_state_change(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Только insurer_status (без decision) → сохранён в payload, case_state не двигается."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _to_under_review(client, ticket_id)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_status": "in_progress_at_insurer",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["data"]["case_state"] == "UNDER_REVIEW", "статус не двигает case_state"
    assert _insurer_status_in_payload(ticket_id) == "in_progress_at_insurer"


def test_illegal_verdict_transition_warns_keeps_state_but_saves_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Вердикт из CLAIM_SUBMITTED (скачок в DECISION_MADE запрещён) → 202, case_state не изменён,
    но insurer_status сохранён (упавший inbound = потеря доставки, поэтому НЕ 422)."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)  # остаётся CLAIM_SUBMITTED
    ticket_id = _ticket_id_by_number(client, number)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_status": "approved_by_insurer",
            "insurer_decision": "APPROVED",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    assert resp.json()["data"]["case_state"] == "CLAIM_SUBMITTED", "запрещённый сдвиг не применён"
    assert _insurer_status_in_payload(ticket_id) == "approved_by_insurer"


def test_verdict_replay_same_event_id_is_noop(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Повтор того же insurance_event_id с вердиктом → early-return, без повторного сдвига."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _to_under_review(client, ticket_id)

    event_id = str(uuid.uuid4())
    _use(_SERVICE)
    raw, headers = _signed(
        {"ticket_number": number, "insurance_event_id": event_id, "insurer_decision": "REJECTED"}
    )
    first = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert first.status_code == 202
    assert first.json()["data"]["case_state"] == "REJECTED"
    # Повтор той же доставки — идемпотентный no-op (тот же event_id), состояние стабильно.
    repeat = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert repeat.status_code == 202
    assert repeat.json()["data"]["case_state"] == "REJECTED"


def test_status_stored_when_case_details_missing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Защитная create-ветка: если TicketCaseDetails отсутствует, insurer_status создаёт детали
    (а не падает). При интейке детали есть, поэтому удаляем их напрямую перед приёмом."""
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _delete_case_details(ticket_id)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_status": "created_from_verdict",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)
    assert resp.status_code == 202, resp.text
    assert _insurer_status_in_payload(ticket_id) == "created_from_verdict"


async def _noop_deliver(url: str, secret: str, delivery: object, settings: object) -> None:
    return None


def _delete_case_details(ticket_id: str) -> None:
    """Удалить TicketCaseDetails заявки напрямую (NullPool) — для покрытия create-ветки."""

    async def _run() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as session:
                repo = TicketCaseDetailsRepository(session)
                details = await repo.get_by_ticket(uuid.UUID(ticket_id))
                if details is not None:
                    await session.delete(details)
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_run())


def _insurer_status_in_payload(ticket_id: str) -> str | None:
    """Прочитать InsurancePayload.insurer_status напрямую из БД (NullPool)."""

    async def _read() -> str | None:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with factory() as session:
                repo = TicketCaseDetailsRepository(session)
                details = await repo.get_by_ticket(uuid.UUID(ticket_id))
                if details is None:
                    return None
                value = (details.payload or {}).get("insurer_status")
                return str(value) if value is not None else None
        finally:
            await engine.dispose()

    return asyncio.run(_read())


def _close(client: TestClient, ticket_id: str) -> None:
    """Закрыть заявку оператором (как в жизни: разобрались и закрыли)."""
    _use(_OPERATOR)
    resp = client.patch(f"/api/v1/support/tickets/{ticket_id}", json={"status": "CLOSED"})
    assert resp.status_code == 200, resp.text


def test_event_on_closed_claim_is_accepted_not_lost(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Событие страховщика по ЗАКРЫТОЙ заявке принимается, а не теряется в 404 (#222).

    Страховщик присылает вердикт тогда, когда присылает; оператор мог закрыть заявку
    раньше. Прежний резолв (`find_active_by_number`, писался под приём почты) исключал
    CLOSED — событие отвергалось, `insurance_event_id` не проставлялся, и связь с
    выплатой терялась молча.
    """
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _close(client, ticket_id)

    _use(_SERVICE)
    event_id = str(uuid.uuid4())
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": event_id,
            "insurer_status": "approved_by_insurer",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)

    assert resp.status_code == 202, resp.text
    data = _get_ticket(client, ticket_id)
    assert str(data["insurance_event_id"]) == event_id


def test_verdict_on_closed_claim_is_recorded_but_does_not_reopen_the_case(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Вердикт по закрытой заявке фиксируется, но case_state не двигает.

    Автоматический сдвиг воскресил бы разбирательство, которое оператор уже закрыл, —
    беззвучно, и заявка на выплату оказалась бы в работе без человека, знающего, почему
    её закрывали. Факт при этом сохранён: дальше решает оператор, переоткрывая руками.
    """
    monkeypatch.setattr("api.webhooks.dispatcher.deliver_webhook", _noop_deliver)
    _enable_secret(monkeypatch)
    number = _create_insurance_claim(client)
    ticket_id = _ticket_id_by_number(client, number)
    _to_under_review(client, ticket_id)
    before = _get_ticket(client, ticket_id)["case_state"]
    _close(client, ticket_id)

    _use(_SERVICE)
    raw, headers = _signed(
        {
            "ticket_number": number,
            "insurance_event_id": str(uuid.uuid4()),
            "insurer_decision": "APPROVED",
        }
    )
    resp = client.post(_INSURER_EVENTS, content=raw, headers=headers)

    assert resp.status_code == 202, resp.text
    data = _get_ticket(client, ticket_id)
    assert data["case_state"] == before, "закрытую заявку вердикт не переоткрывает"
    assert data["insurance_event_id"] is not None, "но сам факт события сохранён"


def test_unknown_number_still_returns_404(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Расширение резолва не должно превращать 404 в утечку: чужой номер — по-прежнему 404."""
    _enable_secret(monkeypatch)
    _use(_SERVICE)
    raw, headers = _signed(
        {"ticket_number": "RH-2099-99999", "insurance_event_id": str(uuid.uuid4())}
    )

    assert client.post(_INSURER_EVENTS, content=raw, headers=headers).status_code == 404
