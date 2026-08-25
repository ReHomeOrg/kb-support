#!/usr/bin/env bash
# Ручной деплой kb-support — замена deploy.yml, пока биллинг GitHub Actions
# заблокирован и джобы падают за три секунды, не начав ни одного шага.
#
# Отличие от CI: образы собираются НА ХОСТЕ и подставляются локально, без
# реестра — push не нужен, compose найдёт локальный тег. Registry-кредов у
# ручного пути нет, и это же экономит две передачи образа по сети.
#
#   scripts/manual-deploy.sh --sha 087b9ad --stack staging
#   scripts/manual-deploy.sh --sha 087b9ad --stack prod
#
# ⚠️ Пины KB_SUPPORT_*_TAG живут в ОБЩЕМ /opt/rehome/<stack>/.env, который
# deploy_backend.yml монорепо переписывает целиком из секрета ENV_FILE_*.
# После каждого монорепо-деплоя эти ключи исчезают, и compose разрешает
# ${KB_SUPPORT_BACKEND_TAG:-latest} в :latest. Поэтому скрипт всегда пишет
# пины заново и печатает прежнее значение — расхождение должно быть видно.
set -euo pipefail

HOST="${KBS_DEPLOY_HOST:-root@95.213.154.92}"
REG="cr.selcloud.ru/rehome"
SHA="" ; STACK=""

while [ $# -gt 0 ]; do
  case "$1" in
    --sha)   SHA="$2";   shift 2 ;;
    --stack) STACK="$2"; shift 2 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SHA" ] && [ -n "$STACK" ] || { echo "нужно: --sha <sha7> --stack <staging|prod>" >&2; exit 2; }
case "$STACK" in staging|prod) ;; *) echo "--stack: только staging или prod" >&2; exit 2 ;; esac

say() { printf '\n▶ %s\n' "$*"; }

say "Доставляю исходники $SHA"
COPYFILE_DISABLE=1 tar --exclude='._*' --exclude=.git --exclude=node_modules --exclude=__pycache__ --exclude=.next -czf - . \
  | ssh "$HOST" "rm -rf /tmp/kbs-$SHA && mkdir -p /tmp/kbs-$SHA && tar -xzf - -C /tmp/kbs-$SHA"

ssh "$HOST" "STACK='$STACK' SHA='$SHA' REG='$REG' sh -s" <<'REMOTE'
set -e
ENVF=/opt/rehome/$STACK/.env
SRC=/tmp/kbs-$SHA

# Тот же замок, что берут деплои монорепо — мутации docker на хосте строго по одной.
exec 9>/tmp/rehome-deploy.lock
flock -w 900 9 || { echo "не дождался блокировки хоста"; exit 1; }

echo "▶ Диск: $(df -h / | awk 'NR==2{print $4" из "$2}')"
docker builder prune -af --filter "until=72h" >/dev/null 2>&1 || true
echo "  после чистки: $(df -h / | awk 'NR==2{print $4}')"

# AppleDouble-мусор: BSD-tar на macOS кладёт `._<имя>` рядом с каждым файлом с
# расширенными атрибутами. Alembic берёт versions/*.py по МАСКЕ, `._x.py` под неё
# подходит, файл бинарный — `SyntaxError: source code string cannot contain null
# bytes`, и читается это как порча исходников, а не как мусор упаковки.
junk=$(find "$SRC" -name '._*' | head -5)
[ -z "$junk" ] || { echo "❌ в исходниках AppleDouble-мусор, пересоберите архив:"; echo "$junk"; exit 1; }

echo "▶ Собираю бэкенд"; docker build -q -t $REG/rehome-kb-support-backend:$SHA  "$SRC/backend"  >/dev/null
echo "▶ Собираю фронт";  docker build -q -t $REG/rehome-kb-support-frontend:$SHA "$SRC/frontend" >/dev/null

echo "▶ Прежние пины: $(grep -E '^KB_SUPPORT' $ENVF | tr '\n' ' ' || echo '(отсутствуют — compose брал :latest)')"
set_env() {
  if grep -q "^$1=" "$ENVF"; then sed -i "s|^$1=.*|$1=$2|" "$ENVF"; else echo "$1=$2" >> "$ENVF"; fi
}
set_env KB_SUPPORT_BACKEND_TAG  "$SHA"
set_env KB_SUPPORT_FRONTEND_TAG "$SHA"

cd /app
echo "▶ Поднимаю службы $STACK"
docker compose -p "$STACK" --env-file "$ENVF" up -d --no-deps \
  postgres-support kb-support-backend kb-support-frontend 2>&1 | grep -viE 'variable is not set' || true

# Дождаться здоровья ДО миграций. Без ожидания `exec` попадает в контейнер,
# который ещё пересоздаётся, и alembic падает с «source code string cannot
# contain null bytes» — читается как порча исходников, хотя это просто гонка.
C=rehome-kb-support-backend-$STACK
echo "▶ Жду готовности $C"
for i in $(seq 1 40); do
  st=$(docker inspect "$C" --format '{{.State.Health.Status}}' 2>/dev/null || echo unknown)
  [ "$st" = "healthy" ] && { echo "  здоров (попытка $i)"; break; }
  [ "$i" = "40" ] && { echo "❌ не дождался здоровья: $st"; exit 1; }
  sleep 3
done

echo "▶ Миграции"
docker compose -p "$STACK" --env-file "$ENVF" exec -T kb-support-backend alembic upgrade head 2>&1 | tail -3
docker compose -p "$STACK" --env-file "$ENVF" exec -T kb-support-backend alembic current 2>&1 | tail -1

docker exec rehome-nginx nginx -s reload 2>/dev/null || true

echo "▶ Смоук"
code=$(docker exec "$C" curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/healthz)
[ "$code" = "200" ] || { echo "❌ /healthz → $code"; exit 1; }
echo "  /healthz → 200"
docker ps --filter "name=kb-support" --format '{{.Names}} | {{.Image}} | {{.Status}}' | grep "$STACK"
echo "✅ kb-support $STACK на $SHA"
REMOTE
