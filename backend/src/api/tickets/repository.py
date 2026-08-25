"""Доступ к данным заявок. Контроль доступа — на уровне SQL-запроса (NFR-1.2)."""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, and_, literal, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.analytics.metrics import record_ticket_created
from api.auth.principal import Principal
from api.automation.enums import AutomationTrigger
from api.sla.assignment import apply_sla
from api.tickets.access import visibility_filter
from api.tickets.claims_intake import CLAIMS_TYPES, apply_claim_intake
from api.tickets.enums import (
    AccessLevel,
    AuthorType,
    TicketChannel,
    TicketPriority,
    TicketStatus,
    TicketType,
)
from api.tickets.history import TicketHistoryAction, TicketHistoryRepository, record_changes
from api.tickets.messages import TicketMessage
from api.tickets.models import Ticket
from api.tickets.numbering import generate_ticket_number
from api.tickets.pagination import (
    SortSpec,
    decode_cursor,
    encode_cursor,
    get_sort_spec,
    keyset_predicate,
    order_by_clause,
    row_cursor_value,
)
from api.tickets.schemas import TicketCreate, TicketFromChat, TicketUpdate
from api.tickets.sla_metrics import record_resolution
from api.tickets.sla_pause import apply_pause_accounting
from api.tickets.sla_query import resolution_breached_clause, resolution_not_breached_clause


@dataclass(frozen=True)
class TicketFilters:
    """Фильтры списка заявок (значения enum — уже строки)."""

    status: str | None = None
    type: str | None = None
    priority: str | None = None
    channel: str | None = None
    team: str | None = None
    assignee_id: uuid.UUID | None = None
    requester_id: uuid.UUID | None = None
    premises_id: uuid.UUID | None = None
    tag: str | None = None
    sla_breached: bool | None = None


# Поля, изменения которых пишутся в журнал §3.7 (см. _FIELD_ACTIONS).
_AUDITED_FIELDS = ("status", "priority", "type", "team", "tags")


def apply_status_side_effects(ticket: Ticket, old_status: str) -> None:
    """Lifecycle-эффекты смены статуса (ТЗ §3.1): счётчик переоткрытий и метки.

    Общий хелпер для PATCH (#8) и action-эндпоинтов (#12).
    """
    if ticket.status == old_status:
        return
    now = datetime.datetime.now(datetime.UTC)
    # Учёт пауз SLA (E4-4 #88): вход/выход PENDING/WAITING → сдвиг resolution_due_at.
    apply_pause_accounting(ticket, old_status, now)
    if ticket.status == TicketStatus.REOPENED.value:
        ticket.reopened_count += 1
    elif ticket.status == TicketStatus.RESOLVED.value:
        first_resolution = ticket.resolved_at is None
        ticket.resolved_at = now
        # TTR/breach — только на ПЕРВОМ решении (REOPENED→RESOLVED не задваивает, #91).
        if first_resolution:
            record_resolution(ticket)
    elif ticket.status == TicketStatus.CLOSED.value:
        ticket.closed_at = now


_CHAT_SUBJECT_FALLBACK = "Эскалация из AI-чата"


def _derive_subject_from_transcript(payload: TicketFromChat) -> str:
    """Тема, если не задана в payload: первая непустая реплика пользователя
    (обрезка до 300), иначе фиксированный фолбэк. Без эвристик/генерации —
    самопис доменной логики не вводим (CLAUDE.md)."""
    for turn in payload.transcript or []:
        text_value = turn.content.strip()
        if turn.role == "user" and text_value:
            return text_value[:300]
    return _CHAT_SUBJECT_FALLBACK


def _chat_custom_fields(payload: TicketFromChat) -> dict[str, Any]:
    """custom_fields для заявки из чата: transcript как вспомогательный контекст
    оператора. Пусто, если transcript не передан."""
    if not payload.transcript:
        return {}
    return {"chat_transcript": [turn.model_dump(mode="json") for turn in payload.transcript]}


class TicketRepository:
    """Репозиторий заявок поверх `AsyncSession` (commit — на стороне вызывающего)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._history = TicketHistoryRepository(session)

    async def _run_automation(self, ticket: Ticket, trigger: str) -> None:
        """Прогнать правила автоматизации (E5-5 #107) в той же транзакции (best-effort,
        не роняет операцию заявки — ADR-0008 Реш.4/6).

        Локальный импорт разрывает цикл `tickets.repository → automation.engine →
        automation.actions → tickets.actions → tickets.repository`."""
        from api.automation.engine import run_rules

        await run_rules(self._session, ticket, trigger)

    async def _ensure_claim_intake(self, ticket: Ticket) -> None:
        """Инициализировать разбирательство, если заявка стала claims-типом и его ещё нет.

        Инвариант: claims-тип ⇒ инициализированное разбирательство (case_state,
        TicketCaseDetails, срок рассмотрения). Раньше он держался только на generic
        `create`, а claims-тип умеют выставлять ещё два пути: эскалация из чата
        (`TicketFromChat.type` принимает все четыре claims-типа) и PATCH оператора.
        Заявка оказывалась claims-типом с `case_state=None`: решение и переходы
        отвечали 422, то есть претензию нельзя было вести вообще.

        Повторно НЕ инициализируем: `apply_claim_intake` сбрасывает case_state в
        CLAIM_SUBMITTED и пересчитывает срок рассмотрения, а детали 1:1 — второй
        вызов на уже начатом разбирательстве откатил бы его к началу.
        """
        if ticket.type in CLAIMS_TYPES and ticket.case_state is None:
            await apply_claim_intake(self._session, ticket)

    async def create(self, payload: TicketCreate, principal: Principal) -> Ticket:
        """Создать заявку.

        `requester_id`: оператор может создать от имени заявителя (из payload);
        заявитель — только от своего имени (из принципала, payload игнорируется).
        """
        requester_id = principal.user_id
        if principal.is_operator and payload.requester_id is not None:
            requester_id = payload.requester_id

        ticket = Ticket(
            number=await generate_ticket_number(self._session),
            subject=payload.subject,
            description=payload.description or "",
            type=payload.type.value,
            status=TicketStatus.NEW.value,
            priority=(payload.priority or TicketPriority.NORMAL).value,
            channel=(payload.channel or TicketChannel.WEB_FORM).value,
            access_level=AccessLevel.LOGGED.value,
            requester_id=requester_id,
            premises_id=payload.premises_id,
            booking_id=payload.booking_id,
            tags=payload.tags or [],
            custom_fields=payload.custom_fields or {},
        )
        self._session.add(ticket)
        await self._session.flush()
        # SLA-матчинг + дедлайны (E4-3 #87) — после flush (нужен created_at).
        await apply_sla(self._session, ticket)
        record_ticket_created(ticket)  # rate входящих (FR-7.3, #168)
        # Приём претензии (E10-5 #195): инициализация case_state + TicketCaseDetails для
        # claims-типов. ПОСЛЕ flush и ДО _run_automation — чтобы on_create-правила (D8)
        # видели уже инициализированное разбирательство. Только generic create несёт
        # claims-каналы (from_chat/from_email форсят AI_CHAT/EMAIL — claims недостижимы).
        await self._ensure_claim_intake(ticket)
        # ФЗ-152 / §3.7: первая запись журнала — создание. actor = принципал
        # (для оператора-от-имени-заявителя actor — оператор, requester_id — заявитель).
        await self._history.record(
            ticket.id,
            principal.user_id,
            TicketHistoryAction.CREATED,
            to_value={"status": ticket.status},
        )
        # Автоматизация on_create (#107) — после журналирования создания.
        await self._run_automation(ticket, AutomationTrigger.ON_CREATE.value)
        return ticket

    async def find_active_by_chat_session(self, chat_session_id: uuid.UUID) -> Ticket | None:
        """Активная (не CLOSED) заявка для chat-сессии, в обход visibility-filter.

        Дедуп эскалаций — это m2m-операция (SERVICE-принципал), а не чтение
        оператором: visibility_filter здесь НЕ применяется (для SERVICE он отдал
        бы пусто и дедуп молча сломался бы). Закрытые заявки не считаются —
        повторная эскалация после закрытия создаёт новую (см. частичный uniq).
        """
        stmt = (
            select(Ticket)
            .where(
                Ticket.chat_session_id == chat_session_id,
                Ticket.status != TicketStatus.CLOSED.value,
            )
            .order_by(Ticket.created_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def find_active_by_number(self, number: str) -> Ticket | None:
        """Активная (не CLOSED) заявка по человекочитаемому номеру, в обход
        visibility-filter (E7-3, #145). Приём email — m2m/worker-контекст (как дедуп
        чата): visibility_filter здесь НЕ применяется. `number` уникален → детерминирован.
        CLOSED не считается — ответ на закрытую заявку создаёт новую (ADR-0010 Реш.3).
        """
        stmt = select(Ticket).where(
            Ticket.number == number,
            Ticket.status != TicketStatus.CLOSED.value,
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def find_insurance_claim_by_number(self, number: str) -> Ticket | None:
        """INSURANCE-заявка по номеру, ВКЛЮЧАЯ закрытые (E10-8, issue #222).

        Отдельный резолв от `find_active_by_number` намеренно. Тот исключает CLOSED,
        потому что писался под приём почты: ответ на закрытую заявку — новая переписка,
        и заводить его в закрытую нельзя (ADR-0010 Реш.3). Событие от страховщика —
        не переписка, а факт: страховщик присылает вердикт тогда, когда присылает, и
        оператор мог закрыть заявку раньше. С прежним резолвом такое событие получало
        404, `insurance_event_id` не проставлялся, и связь с выплатой терялась молча.

        Тип и claims-контекст проверяет вызывающий (404 anti-enum).
        """
        stmt = select(Ticket).where(Ticket.number == number)
        return (await self._session.execute(stmt)).scalars().first()

    async def find_guarantee_by_reference(self, reference: str) -> Ticket | None:
        """GUARANTEE-заявка по `custom_fields.guarantee_reference` (идемпотентность приёма
        сигнала платёжного контура, E10-10 PR-A; m2m-контекст, без visibility-filter).

        JSONB `->>` поиск (не индексирован — uniq-индекс = hardening-follow-up, ADR-0017 A1).
        Найдена → повторный сигнал не двоит заявку."""
        stmt = select(Ticket).where(
            Ticket.type == TicketType.GUARANTEE.value,
            Ticket.custom_fields["guarantee_reference"].astext == reference,
        )
        return (await self._session.execute(stmt)).scalars().first()

    async def find_message_by_email_id(self, email_message_id: str) -> TicketMessage | None:
        """Сообщение по Message-ID входящего письма (E7-3, #145) — дедуп идемпотентного
        приёма и recovery после гонки на частичном uniq. Без visibility-filter (m2m)."""
        stmt = select(TicketMessage).where(TicketMessage.email_message_id == email_message_id)
        return (await self._session.execute(stmt)).scalars().first()

    async def create_from_chat(
        self, payload: TicketFromChat, principal: Principal
    ) -> tuple[Ticket, bool]:
        """Создать заявку из эскалации AI-чата (kb-search → m2m). Возвращает
        `(ticket, created)`: при повторной эскалации той же сессии — существующую
        активную заявку и `created=False` (идемпотентность).

        `requester_id` берётся ИЗ payload (m2m-вызов, принципал — SERVICE);
        `channel` форсирован AI_CHAT; transcript кладётся в `custom_fields`.
        """
        existing = await self.find_active_by_chat_session(payload.chat_session_id)
        if existing is not None:
            return existing, False

        ticket = Ticket(
            number=await generate_ticket_number(self._session),
            subject=payload.subject or _derive_subject_from_transcript(payload),
            # description NOT NULL в модели — задаём явно (transcript хранится в
            # custom_fields, не дублируется в description).
            description="",
            type=(payload.type or TicketType.OTHER).value,
            status=TicketStatus.NEW.value,
            priority=TicketPriority.NORMAL.value,
            channel=TicketChannel.AI_CHAT.value,
            access_level=AccessLevel.LOGGED.value,
            requester_id=payload.requester_id,
            premises_id=payload.premises_id,
            booking_id=payload.booking_id,
            chat_session_id=payload.chat_session_id,
            tags=[],
            custom_fields=_chat_custom_fields(payload),
        )
        self._session.add(ticket)
        try:
            await self._session.flush()
        except IntegrityError:
            # Гонка: параллельная эскалация той же сессии успела создать заявку
            # (частичный uniq отклонил нашу). Откат + возврат победившей.
            await self._session.rollback()
            existing = await self.find_active_by_chat_session(payload.chat_session_id)
            if existing is None:  # pragma: no cover — теоретически недостижимо
                raise
            return existing, False

        # SLA только для вновь созданной заявки (идемпотентный возврат existing —
        # выше, дедлайны не пересчитываются). После flush — created_at доступен.
        await apply_sla(self._session, ticket)
        record_ticket_created(ticket)  # rate входящих (FR-7.3, #168) — только new-ветка
        # Эскалация из чата умеет нести claims-тип (COMPENSATION/GUARANTEE/INSURANCE/
        # ACCEPTANCE_ACT) — разбирательство инициализируем здесь же, до on_create-правил.
        await self._ensure_claim_intake(ticket)
        await self._history.record(
            ticket.id,
            principal.user_id,
            TicketHistoryAction.CREATED,
            to_value={"status": ticket.status},
        )
        # Автоматизация on_create (#107) — только для вновь созданной заявки
        # (идемпотентный возврат existing выше правил не запускает).
        await self._run_automation(ticket, AutomationTrigger.ON_CREATE.value)
        return ticket, True

    async def create_from_email(
        self, *, subject: str, requester_id: uuid.UUID, custom_fields: dict[str, Any]
    ) -> Ticket:
        """Создать заявку из входящего письма (E7-3, #145). channel=EMAIL,
        `description=""` — тело письма живёт в первом TicketMessage (решение Архитектора:
        email-native, без дублирования ПДн). `requester_id` — резолв/sentinel (ingestion,
        sender не доверяем). actor журнала — requester_id. Хвост (flush/SLA/history/
        automation) зеркалит create_from_chat."""
        ticket = Ticket(
            number=await generate_ticket_number(self._session),
            subject=subject,
            description="",
            type=TicketType.OTHER.value,
            status=TicketStatus.NEW.value,
            priority=TicketPriority.NORMAL.value,
            channel=TicketChannel.EMAIL.value,
            access_level=AccessLevel.LOGGED.value,
            requester_id=requester_id,
            tags=[],
            custom_fields=custom_fields,
        )
        self._session.add(ticket)
        await self._session.flush()
        await apply_sla(self._session, ticket)
        record_ticket_created(ticket)  # rate входящих (FR-7.3, #168)
        await self._history.record(
            ticket.id,
            requester_id,
            TicketHistoryAction.CREATED,
            to_value={"status": ticket.status},
        )
        await self._run_automation(ticket, AutomationTrigger.ON_CREATE.value)
        return ticket

    async def add_email_message(
        self,
        ticket_id: uuid.UUID,
        *,
        author_id: uuid.UUID,
        body: str,
        attachments: list[str],
        email_message_id: str | None,
    ) -> TicketMessage:
        """Добавить входящее письмо как сообщение (E7-3, #145). НЕ `messages.create`:
        автор — из резолва/sentinel (sender не доверяем), не из принципала; несёт
        `email_message_id` (дедуп). `is_internal=False` всегда — входящее письмо не
        может стать внутренней заметкой (NFR-1.3). flush может бросить IntegrityError
        на частичном uniq (дедуп) — обрабатывает вызывающий (ingestion)."""
        message = TicketMessage(
            ticket_id=ticket_id,
            author_id=author_id,
            author_type=AuthorType.REQUESTER.value,
            body=body,
            is_internal=False,
            attachments=attachments,
            email_message_id=email_message_id,
        )
        self._session.add(message)
        await self._session.flush()
        return message

    async def get_for_principal(self, ticket_id: uuid.UUID, principal: Principal) -> Ticket | None:
        """Вернуть заявку, если она видима субъекту, иначе None (→ 404)."""
        stmt = select(Ticket).where(Ticket.id == ticket_id, visibility_filter(principal))
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    def _list_conditions(
        self, principal: Principal, filters: TicketFilters
    ) -> list[ColumnElement[bool]]:
        """Видимость (NFR-1.2) + фильтры — всё в SQL."""
        conditions: list[ColumnElement[bool]] = [visibility_filter(principal)]
        if filters.status is not None:
            conditions.append(Ticket.status == filters.status)
        if filters.type is not None:
            conditions.append(Ticket.type == filters.type)
        if filters.priority is not None:
            conditions.append(Ticket.priority == filters.priority)
        if filters.channel is not None:
            conditions.append(Ticket.channel == filters.channel)
        if filters.team is not None:
            conditions.append(Ticket.team == filters.team)
        if filters.assignee_id is not None:
            conditions.append(Ticket.assignee_id == filters.assignee_id)
        if filters.requester_id is not None:
            conditions.append(Ticket.requester_id == filters.requester_id)
        if filters.premises_id is not None:
            conditions.append(Ticket.premises_id == filters.premises_id)
        if filters.tag is not None:
            # tag = ANY(tags) — заявка содержит указанный тег.
            conditions.append(Ticket.tags.any(literal(filters.tag)))
        if filters.sla_breached is not None:
            # Единый источник предиката breach (api.tickets.sla_query) — тот же,
            # что использует SLA-воркер (#90), без дублирования семантики.
            now = datetime.datetime.now(datetime.UTC)
            conditions.append(
                resolution_breached_clause(now)
                if filters.sla_breached
                else resolution_not_breached_clause(now)
            )
        return conditions

    async def list_tickets(
        self,
        principal: Principal,
        *,
        filters: TicketFilters,
        sort: str | None,
        cursor: str | None,
        limit: int,
    ) -> tuple[list[Ticket], str | None, bool]:
        """Список видимых заявок с фильтрами, сортировкой и keyset-пагинацией.

        Возвращает (строки, next_cursor, has_more). Невалидный cursor → ValueError.
        """
        spec: SortSpec = get_sort_spec(sort)
        conditions = self._list_conditions(principal, filters)
        if cursor is not None:
            value, cursor_id = decode_cursor(cursor)
            conditions.append(keyset_predicate(spec, value, cursor_id))
        stmt = (
            select(Ticket)
            .where(and_(*conditions))
            .order_by(*order_by_clause(spec))
            .limit(limit + 1)
        )
        rows = list((await self._session.execute(stmt)).scalars().all())
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (
            encode_cursor(row_cursor_value(rows[-1], spec), rows[-1].id)
            if has_more and rows
            else None
        )
        return rows, next_cursor, has_more

    async def apply_update(
        self, ticket: Ticket, payload: TicketUpdate, principal: Principal
    ) -> Ticket:
        """Применить частичное обновление, lifecycle-эффекты и запись в журнал.

        Валидация перехода статуса и RBAC выполняются вызывающим (router) ДО
        вызова. Здесь — только мутация + аудит изменений отслеживаемых полей.
        """
        fields_set = payload.model_fields_set
        before: dict[str, Any] = {field: getattr(ticket, field) for field in _AUDITED_FIELDS}
        old_status = ticket.status

        if "subject" in fields_set and payload.subject is not None:
            ticket.subject = payload.subject
        if "status" in fields_set and payload.status is not None:
            ticket.status = payload.status.value
        if "priority" in fields_set and payload.priority is not None:
            ticket.priority = payload.priority.value
        if "type" in fields_set and payload.type is not None:
            ticket.type = payload.type.value
        if "team" in fields_set and payload.team is not None:
            ticket.team = payload.team.value
        if "tags" in fields_set and payload.tags is not None:
            ticket.tags = payload.tags
        if "custom_fields" in fields_set and payload.custom_fields is not None:
            ticket.custom_fields = payload.custom_fields

        apply_status_side_effects(ticket, old_status)
        await self._session.flush()
        # Оператор мог переклассифицировать заявку в claims-тип: без инициализации
        # разбирательства она осталась бы с case_state=None, и вести претензию было
        # бы нечем. Уже начатое разбирательство не трогаем (см. _ensure_claim_intake).
        await self._ensure_claim_intake(ticket)

        after: dict[str, Any] = {field: getattr(ticket, field) for field in _AUDITED_FIELDS}
        await record_changes(self._history, ticket.id, principal.user_id, before, after)
        # Автоматизация on_update (#107) — после журналирования изменений оператора.
        await self._run_automation(ticket, AutomationTrigger.ON_UPDATE.value)
        return ticket
