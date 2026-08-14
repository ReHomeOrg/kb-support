import Link from "next/link";

import { auth, signOut } from "@/auth";

import { Brand } from "./Brand";

/**
 * Шапка рабочего места оператора: бренд, навигация, текущий оператор, выход.
 * Серверный компонент — берёт сессию из Auth.js; форма «Выйти» вызывает серверный
 * signOut. Пункт «Панель» (аналитика) виден всем операторам; доступ супервайзера
 * гейтит бэкенд (403 на странице) — фронт права не вычисляет (ADR-0003).
 */
export async function OperatorHeader() {
  const session = await auth();
  const operator = session?.user?.email ?? session?.user?.name ?? "оператор";

  return (
    <header className="flex items-center justify-between border-b pb-4">
      <div className="flex items-center gap-6">
        <Brand />
        <nav className="flex items-center gap-4 text-sm" aria-label="Навигация">
          <Link href="/tickets" className="text-gray-600 hover:text-gray-900">
            Заявки
          </Link>
          <Link href="/dashboard" className="text-gray-600 hover:text-gray-900">
            Панель
          </Link>
          <Link href="/reports" className="text-gray-600 hover:text-gray-900">
            Отчёты
          </Link>
          {/* L1: кросс-переход в CRM-продажи (отдельный сервис, тот же Keycloak-realm
              → SSO без повторного логина). Внешний href, не next/link. */}
          <a href="https://rehome.one/staff/crm" className="text-gray-600 hover:text-gray-900">
            Продажи (CRM) ↗
          </a>
        </nav>
      </div>
      <div className="flex items-center gap-3 text-sm">
        <span className="text-gray-500">{operator}</span>
        <form
          action={async () => {
            "use server";
            await signOut({ redirectTo: "/login" });
          }}
        >
          <button type="submit" className="text-gray-600 underline hover:text-gray-900">
            Выйти
          </button>
        </form>
      </div>
    </header>
  );
}
