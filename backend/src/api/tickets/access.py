"""Storage-level фильтр видимости заявок (NFR-1.2, ADR-0003).

Фильтр применяется в SQL-запросе (не в Python), чтобы недоступные заявки не
покидали БД. Заявитель видит только свои (`requester_id`); оператор — заявки
своих команд (`team ∈ principal.teams`). Недоступная заявка неотличима от
несуществующей → вызывающий код отдаёт 404 (anti-enumeration).

Делегирование (CC-1, on-behalf-of): для агента (`kbs_kind=agent` + `kbs_act_sub`) видимость
«своих» заявок считается от ИМЕНИ пользователя через `principal.effective_user_id`
(а не сервис-принципала агента, G7). Для остальных субъектов `effective_user_id`
== `user_id`, поведение не меняется.
"""

from __future__ import annotations

from sqlalchemy import ColumnElement, or_

from api.auth.principal import Principal
from api.tickets.models import Ticket


def visibility_filter(principal: Principal) -> ColumnElement[bool]:
    """SQL-условие видимости заявок для данного субъекта."""
    conditions: list[ColumnElement[bool]] = [Ticket.requester_id == principal.effective_user_id]
    if principal.is_operator and principal.teams:
        conditions.append(Ticket.team.in_([team.value for team in principal.teams]))
    return or_(*conditions)
