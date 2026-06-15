#!/usr/bin/env bash
# Единая точка входа в vulnrag.
#   ./run.sh          — поднять Qdrant и запустить API (по умолчанию)
#   ./run.sh serve    — то же самое
#   ./run.sh sync     — разовая/ежедневная синхронизация базы уязвимостей
#   ./run.sh test     — прогнать тесты (сервисы не нужны)
#
# Окно дат для sync задаётся переменной VULNRAG_NVD_START_DATE, напр.:
#   VULNRAG_NVD_START_DATE=2026-03-15T00:00:00 ./run.sh sync
set -euo pipefail
cd "$(dirname "$0")"

PY=venv/bin/python
VENV=venv/bin
PORT="${VULNRAG_API_PORT:-8000}"
QDRANT_URL="http://${VULNRAG_QDRANT_HOST:-localhost}:${VULNRAG_QDRANT_PORT:-6333}"

[ -x "$PY" ] || { echo "Нет venv ($PY). Создай: python -m venv venv && $VENV/pip install -e '.[dev]'"; exit 1; }

wait_qdrant() {
  docker compose up -d
  echo -n "Жду Qdrant ($QDRANT_URL)"
  until curl -sf "$QDRANT_URL/" >/dev/null 2>&1; do echo -n "."; sleep 1; done
  echo " готов."
}

cmd="${1:-serve}"
case "$cmd" in
  serve)
    wait_qdrant
    count=$(curl -s "$QDRANT_URL/collections/vulnerabilities" 2>/dev/null \
            | "$PY" -c "import sys,json;print(json.load(sys.stdin).get('result',{}).get('points_count',0))" 2>/dev/null || echo 0)
    if [ "${count:-0}" = "0" ]; then
      echo "ВНИМАНИЕ: коллекция пуста. Сначала наполни базу:  ./run.sh sync"
    else
      echo "В базе записей: $count"
    fi
    echo "API: http://localhost:$PORT  (POST /query, GET /health, GET /stats)"
    exec "$VENV/uvicorn" vulnrag.api.server:app --host 0.0.0.0 --port "$PORT"
    ;;
  sync)
    wait_qdrant
    exec "$PY" scripts/run_sync.py
    ;;
  test)
    exec "$VENV/pytest" -q
    ;;
  *)
    echo "usage: ./run.sh [serve|sync|test]"; exit 1
    ;;
esac
