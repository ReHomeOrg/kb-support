"""Inbound webhook страховщика (E10-8 PR-C #198 / E10-10 PR-C #200; ADR-0015 D8, ADR-0017 D2).

`POST /api/v1/support/insurer-events` — m2m (kind=SERVICE, anti-spoofing) + верификация
входящей HMAC-подписи `X-Signature` по общему `insurer_inbound_secret` (config-gated,
fail-closed: пустой секрет → приём отклоняется, инертно до ops). Находит claims-заявку
INSURANCE по номеру (m2m-контекст, без visibility-filter — как from-email), проставляет
`insurance_event_id` + строку аудита → триггерит outbound `ticket.insurance_event` (D8).
**E10-10 (ADR-0017 D2):** опц. `insurer_status` фиксируется в `InsurancePayload.insurer_status`,
опц. `insurer_decision` СИСТЕМНО двигает case_state по машине E10-2 (APPROVED→DECISION_MADE,
REJECTED→REJECTED). Наш `decide()` НЕ применяем, `ticket.decision` НЕ трогаем (вердикт —
страховщика, не наш). Запрещённый/невозможный переход → WARN + 202 (НЕ 422: упавший inbound =
потеря доставки), `insurer_status` всё равно сохранён. Идемпотентность по `insurance_event_id`.
Боевой контракт страховщика — при провижининге.
"""

from __future__ import annotations

import datetime
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_principal
from api.auth.principal import Principal, PrincipalKind
from api.config import get_settings
from api.db import get_session
from api.errors import ProblemException
from api.observability.logging import get_logger
from api.tickets.actions import resolve_on_terminal_case
from api.tickets.case_repository import TicketCaseDetailsRepository
from api.tickets.case_state_machine import is_allowed_case_transition
from api.tickets.enums import (
    CaseType,
    InsurerDecision,
    TicketCaseState,
    TicketStatus,
    TicketType,
)
from api.tickets.history import TicketHistoryAction, TicketHistoryRepository
from api.tickets.models import Ticket
from api.tickets.repository import TicketRepository
from api.tickets.schemas import TicketEnvelope, TicketRead
from api.webhooks.dispatcher import schedule_webhook_event
from api.webhooks.enums import WebhookEvent
from api.webhooks.schemas import InsurerEventIngest
from api.webhooks.signing import verify_signature

router = APIRouter(prefix="/api/v1/support", tags=["Webhooks"])

_logger = get_logger("webhooks.insurer")

# Вердикт страховщика → целевой case_state (ADR-0017 D2; provisional). Оба достижимы из
# UNDER_REVIEW/INSPECTION по CASE_ALLOWED_TRANSITIONS. PARTIAL не вводим (FR-9.8, деньги
# не считаем).
_VERDICT_CASE_STATE: dict[InsurerDecision, TicketCaseState] = {
    InsurerDecision.APPROVED: TicketCaseState.DECISION_MADE,
    InsurerDecision.REJECTED: TicketCaseState.REJECTED,
}


async def _store_insurer_status(session: AsyncSession, ticket: Ticket, insurer_status: str) -> None:
    """Зафиксировать статусный лейбл страховщика в `InsurancePayload.insurer_status`.

    Create-or-update деталей претензии (паттерн `actions._record_regress_due_at`): при интейке
    INSURANCE детали создаются (apply_claim_intake), но защищаемся от их отсутствия. Реассайн
    payload — JSONB не трекает in-place мутацию (урок MutableDict)."""
    repo = TicketCaseDetailsRepository(session)
    details = await repo.get_by_ticket(ticket.id)
    if details is None:
        await repo.create(ticket.id, CaseType.INSURANCE, payload={"insurer_status": insurer_status})
        return
    payload = dict(details.payload or {})
    payload["insurer_status"] = insurer_status
    await repo.update_payload(details, payload)


def _apply_insurer_verdict(ticket: Ticket, decision: InsurerDecision) -> tuple[str, str] | None:
    """Системный сдвиг case_state по вердикту страховщика (ADR-0017 D2). Возвращает (from, to)
    при фактическом сдвиге, иначе None (no-op либо запрещённый переход — WARN, без 422).

    `case_state is None` исключён выше (404 на не-INSURANCE). `decide()`/`ticket.decision` НЕ
    трогаются: решение по INSURANCE — за страховщиком. Предикат `is_allowed_case_transition`
    (НЕ `transition_case_state`, который бросает 422)."""
    current = TicketCaseState(ticket.case_state)
    target = _VERDICT_CASE_STATE[decision]
    if current == target:
        return None  # идемпотентный no-op — журнал не засоряем
    if not is_allowed_case_transition(current, target):
        # ФЗ-152: только ticket_id + состояния (case_state — не ПДн), без payload/тела.
        _logger.warning(
            "insurer verdict transition not allowed ticket=%s %s->%s",
            ticket.id,
            current.value,
            target.value,
        )
        return None
    ticket.case_state = target.value
    return (current.value, target.value)


def _resolve_request_id(raw: str | None) -> uuid.UUID:
    # Дубль admin-роутеров — будет вынесен в общий хелпер (#219).
    if raw:
        try:
            return uuid.UUID(raw)
        except ValueError:
            pass
    return uuid.uuid4()


def _envelope(ticket: Ticket, x_request_id: str | None) -> TicketEnvelope:
    return TicketEnvelope(
        data=TicketRead.model_validate(ticket), request_id=_resolve_request_id(x_request_id)
    )


@router.post(
    "/insurer-events",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=TicketEnvelope,
    summary="Приём webhook страховщика",
)
async def receive_insurer_event(
    request: Request,
    payload: InsurerEventIngest,
    background: BackgroundTasks,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_session),
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
) -> TicketEnvelope:
    # m2m-only: страховщик шлёт m2m; не-SERVICE → нельзя (anti-spoofing, ADR-0015 D8).
    if principal.kind is not PrincipalKind.SERVICE:
        raise ProblemException.forbidden(
            detail="Insurer event ingestion is a service-to-service operation"
        )
    settings = get_settings()
    secret = settings.insurer_inbound_secret
    raw = await request.body()  # точные байты, которые подписал страховщик
    signature = request.headers.get("X-Signature", "")
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    # Config-gate + anti-spoofing: пустой секрет (выключено) ИЛИ невалидная/просроченная
    # подпись → 403 (fail-closed). raw в лог/ошибку не попадает (ФЗ-152).
    if not secret or not verify_signature(
        payload=raw,
        secret=secret,
        header=signature,
        now=now,
        tolerance_seconds=settings.webhook_timestamp_tolerance_seconds,
    ):
        raise ProblemException.forbidden(detail="Invalid or missing webhook signature")

    # Резолв, принимающий и закрытые заявки: событие страховщика — факт, а не новая
    # переписка (#222). Ответ по существу остаётся тем же — см. гейт ниже.
    ticket = await TicketRepository(session).find_insurance_claim_by_number(payload.ticket_number)
    # 404 anti-enum: не наша заявка / не претензионная INSURANCE.
    if ticket is None or ticket.case_state is None or ticket.type != TicketType.INSURANCE.value:
        raise ProblemException.not_found(detail="Insurance claim ticket not found")

    # Идемпотентность по insurance_event_id: повтор той же доставки → no-op (без ретриггера).
    if ticket.insurance_event_id == payload.insurance_event_id:
        return _envelope(ticket, x_request_id)

    previous = ticket.insurance_event_id
    ticket.insurance_event_id = payload.insurance_event_id

    # E10-10 (ADR-0017 D2): фиксация вердикта страховщика. Статусный лейбл → InsurancePayload;
    # вердикт → системный сдвиг case_state (никаких decide()/ticket.decision). Всё в одной
    # транзакции с записью insurance_event_id (единый commit ниже).
    if payload.insurer_status is not None:
        await _store_insurer_status(session, ticket, payload.insurer_status)
    # На ЗАКРЫТОЙ заявке вердикт только фиксируется, но case_state не двигается.
    # Автоматический сдвиг воскресил бы разбирательство, которое оператор уже закрыл,
    # причём беззвучно — и заявка на выплату оказалась бы в работе без человека,
    # который знает, почему её закрывали. Факт при этом не теряется: событие, статус
    # и вердикт записаны, дальше решает оператор, переоткрывая заявку руками.
    is_closed = ticket.status == TicketStatus.CLOSED.value
    case_change = (
        _apply_insurer_verdict(ticket, payload.insurer_decision)
        if payload.insurer_decision is not None and not is_closed
        else None
    )
    if is_closed and payload.insurer_decision is not None:
        _logger.warning(
            "insurer verdict on closed ticket recorded without case shift ticket=%s",
            ticket.id,
        )

    history = TicketHistoryRepository(session)
    to_value: dict[str, object] = {"insurance_event_id": str(payload.insurance_event_id)}
    if payload.insurer_status is not None:
        to_value["insurer_status"] = payload.insurer_status
    if payload.insurer_decision is not None:
        to_value["insurer_decision"] = payload.insurer_decision.value
    await history.record(
        ticket.id,
        principal.user_id,
        TicketHistoryAction.INSURANCE_EVENT_RECEIVED,
        from_value={"insurance_event_id": str(previous) if previous else None},
        to_value=to_value,
    )
    if case_change is not None:
        await history.record(
            ticket.id,
            principal.user_id,
            TicketHistoryAction.CASE_STATE_CHANGED,
            from_value={"case_state": case_change[0]},
            to_value={"case_state": case_change[1]},
        )
        # Вердикт REJECTED → case_state терминальный → системное закрытие заявки (#211):
        # тот же путь, что decide/transition/payout — иначе INSURANCE-заявка остаётся под
        # SLA-эскалацией (фильтр воркера по ticket.status).
        await resolve_on_terminal_case(session, history, ticket, principal.user_id)
    await session.commit()
    await session.refresh(ticket)
    # Триггер outbound ticket.insurance_event (D8) — fire-after подписчикам (ПОСЛЕ commit).
    # Это доставка подписчикам (webhooks/dispatcher), НЕ insurer-outbound PR-B — петли нет.
    await schedule_webhook_event(
        background, session, ticket, WebhookEvent.INSURANCE_EVENT, settings
    )
    return _envelope(ticket, x_request_id)
