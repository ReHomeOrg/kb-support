"""Модель аутентифицированного субъекта (`Principal`) для RBAC kb-support.

Результат верификации токена/сессии. Интерфейс зафиксирован на E1 (#6); реальный
верификатор (Keycloak JWT RS256/JWKS, CookieAuth) наполнит модель в #29 без
изменения сигнатуры: `sub` → `user_id`, realm/client-роли → `teams`/`scopes`.

См. ADR-0003 (контуры), NFR-1.2 (RBAC), CLAUDE.md (scope считается только
бэкендом из проверенного токена — не из payload).
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from api.auth.scopes import STAFF_ADMIN_SCOPE, STAFF_SUPERVISOR_SCOPE, STAFF_SUPPORT_SCOPE
from api.tickets.enums import TicketTeam


class PrincipalKind(str, enum.Enum):
    """Тип субъекта.

    REQUESTER — заявитель (видит только свои заявки). OPERATOR — сотрудник
    поддержки (видит заявки своих команд). SERVICE — m2m-вызов (напр. kb-search
    при эскалации из чата, E3). AGENT — ИИ-агент-оркестратор «Консьерж»,
    действует on-behalf-of пользователя (делегирование, CC-1 / token-exchange).
    """

    REQUESTER = "requester"
    OPERATOR = "operator"
    SERVICE = "service"
    AGENT = "agent"


@dataclass(frozen=True)
class Principal:
    """Аутентифицированный субъект запроса.

    `teams` заполняется для операторов и определяет видимость заявок по командам
    (storage-level фильтр, NFR-1.2). `scopes` — гранулярные права из токена.
    `on_behalf_of` — sub пользователя, от имени которого действует агент
    (**легаси**-делегирование `kbs_act_sub`); для не-агентных субъектов — None.
    `acting_agent` — clientId агента из стандартного RFC 8693 `act.sub` (новая
    схема CC-1: `sub` уже = пользователь, `act.sub` лишь фиксирует, что действует
    агент). Легаси `on_behalf_of` и новый `acting_agent` **взаимоисключающие**
    (одновременно в токене → 401 в верификаторе).
    """

    user_id: uuid.UUID
    kind: PrincipalKind
    scopes: frozenset[str] = field(default_factory=frozenset)
    teams: frozenset[TicketTeam] = field(default_factory=frozenset)
    on_behalf_of: uuid.UUID | None = None
    acting_agent: str | None = None

    @property
    def is_operator(self) -> bool:
        """Является ли субъект оператором (доступ к заявкам по командам)."""
        return self.kind is PrincipalKind.OPERATOR

    @property
    def is_agent(self) -> bool:
        """Является ли субъект ИИ-агентом-оркестратором (Консьерж, делегирование CC-1).

        True как для легаси-схемы (`kbs_kind=agent`), так и для новой (стандартный
        `act.sub` — агент действует от имени пользователя, `acting_agent` заполнен)."""
        return self.kind is PrincipalKind.AGENT or self.acting_agent is not None

    @property
    def effective_user_id(self) -> uuid.UUID:
        """Пользователь, от чьего ИМЕНИ применяются права видимости.

        Легаси-схема (`kbs_kind=agent` + `kbs_act_sub`): делегированный пользователь
        (`on_behalf_of`). Новая схема (`act.sub`): `sub` УЖЕ = пользователь (обмен
        impersonation), `on_behalf_of=None` → сам `user_id`. Для остальных — `user_id`.
        RBAC-фильтры видимости опираются на это поле, чтобы агент видел данные
        ПОЛЬЗОВАТЕЛЯ, а не сервис-принципала (G7)."""
        return self.on_behalf_of if self.on_behalf_of is not None else self.user_id

    @property
    def is_staff_admin(self) -> bool:
        """Есть ли у субъекта админ-скоуп (настройка SLA/business hours, §6).

        Гранулярное право из проверенного токена — не привязано к `kind` (оператор
        с этим скоупом администрирует конфигурацию; см. `auth/scopes.py`)."""
        return STAFF_ADMIN_SCOPE in self.scopes

    @property
    def is_staff_support(self) -> bool:
        """Есть ли у субъекта скоуп управления шаблонами (CannedResponse CRUD, FR-5.1).

        Гранулярное право из проверенного токена (ADR-0009); см. `auth/scopes.py`."""
        return STAFF_SUPPORT_SCOPE in self.scopes

    @property
    def is_staff_supervisor(self) -> bool:
        """Есть ли у субъекта скоуп супервайзера (аналитика — панель/отчёты, FR-7.1/7.2).

        **Аддитивно** (ADR-0011 Решение 1): проверяет СТРОГО наличие `staff_supervisor` в
        токене, НЕ выводит из `staff_support` и наоборот — Keycloak выдаёт супервайзеру оба
        скоупа отдельно. См. `auth/scopes.py`."""
        return STAFF_SUPERVISOR_SCOPE in self.scopes
