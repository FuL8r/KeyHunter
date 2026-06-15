# vulnrag

RAG-система для проверки уязвимостей через локальную открытую LLM. Отвечает на вопросы
вида «безопасен ли log4j 2.14.1?» по данным баз уязвимостей (NVD, CISA KEV, OSV),
с **программным сопоставлением версий** (а не только семантикой) и локальной генерацией
ответа через `qwen2.5:3b`.

## Стек

- **Qdrant** — векторное хранилище (Docker)
- **Ollama** — `bge-m3` (эмбеддинги, мультиязычный) + `qwen2.5:3b` (генерация)
- **FastAPI** — HTTP-интерфейс
- Прямой пайплайн без LlamaIndex: `parse → retrieve (фильтр по метаданным + семантика) → match (проверка диапазона версий) → answer (grounded-синтез)`

## Быстрый старт

```bash
# 0. Зависимости (один раз)
python -m venv venv && venv/bin/pip install -e ".[dev]"
ollama pull bge-m3 && ollama pull qwen2.5:3b

# 1. Наполнить базу (Qdrant поднимется автоматически).
#    Узкое окно = быстрее. Полный 2019+ без переменной — это часы.
VULNRAG_NVD_START_DATE=2026-03-15T00:00:00 ./run.sh sync

# 2. Запустить API
./run.sh serve            # http://localhost:8000

# Тесты (сервисы не нужны)
./run.sh test
```

`run.sh` — единая точка входа: `serve` (по умолчанию), `sync`, `test`.

> Первый `sync` — разовый бэкафилл (узкое место — эмбеддинг на CPU). Дальше
> ежедневные дельты идут минуты. Запускать `sync` по расписанию: cron/systemd-timer на
> `venv/bin/python scripts/run_sync.py`.

## API

Базовый URL: `http://localhost:8000`

### `GET /health`
Проверка живости.
```json
{ "status": "ok" }
```

### `GET /stats`
Размер корпуса.
```json
{ "cve_count": 12873 }
```

### `POST /query`
Главный эндпоинт. Тело запроса:

| Поле | Тип | Обяз. | Описание |
|------|-----|-------|----------|
| `question` | string | да | Вопрос на русском или английском |
| `lang` | string\|null | нет | Зарезервировано; язык сейчас определяется автоматически по тексту вопроса |

Пример:
```bash
curl -s -X POST localhost:8000/query \
  -H 'content-type: application/json' \
  -d '{"question":"Безопасен ли log4j 2.14.1?"}' | venv/bin/python -m json.tool
```

Ответ:
```json
{
  "verdict": "vulnerable",
  "answer": "Уязвимо: CVE-2021-44228 (CRITICAL). Обновите до 2.15.0 ...",
  "cves": [
    {
      "cve_id": "CVE-2021-44228",
      "severity": "CRITICAL",
      "fixed_versions": ["2.15.0"],
      "references": ["https://logging.apache.org/log4j/2.x/security.html"]
    }
  ],
  "lang": "ru"
}
```

#### Поле `verdict`
| Значение | Смысл |
|----------|-------|
| `vulnerable` | Указанная версия попадает в уязвимый диапазон хотя бы одного CVE |
| `unconfirmed` | Компонент найден, но версия не указана — есть потенциально применимые CVE |
| `safe` | Компонент есть в базе, но указанная версия вне всех известных уязвимых диапазонов |
| `not_found` | По запросу в корпусе ничего не найдено |

При `safe` и `not_found` массив `cves` пустой, а `answer` — шаблонный текст
(LLM не вызывается — защита от галлюцинаций). При `vulnerable`/`unconfirmed`
ответ генерирует `qwen2.5:3b` строго по найденному контексту.

#### Поле `cves[]`
| Поле | Описание |
|------|----------|
| `cve_id` | Идентификатор CVE |
| `severity` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` или `null` |
| `fixed_versions` | Версии, в которых исправлено (если известно) |
| `references` | Ссылки на advisory/патчи |

## Использование из Python / ноутбука

```python
from vulnrag.factory import build_components   # реальный Qdrant + Ollama
from vulnrag.query.answer import answer

store, emb, llm = build_components()
r = answer("Безопасен ли log4j 2.14.1?", embedder=emb, store=store, llm=llm)
print(r.verdict, r.cves)
```

Готовый smoke-ноутбук с golden-кейсами: `notebooks/eval.ipynb`.

## Конфигурация

Конфиг задаётся файлом `.env` в корне проекта (читается автоматически) или
переменными окружения. Скопируй шаблон и заполни нужное:

```bash
cp .env.example .env
```

`.env` в `.gitignore` — ключи не попадут в git. Реальные переменные окружения
имеют приоритет над `.env`. Поля (префикс `VULNRAG_`):

| Переменная | По умолчанию | Назначение |
|-----------|--------------|-----------|
| `VULNRAG_NVD_START_DATE` | `2019-01-01` | С какой даты тянуть NVD при первом бэкафилле |
| `VULNRAG_NVD_API_KEY` | — | Ключ NVD (поднимает лимит запросов ~в 6 раз) |
| `VULNRAG_QDRANT_HOST` / `_PORT` | `localhost` / `6333` | Адрес Qdrant |
| `VULNRAG_COLLECTION` | `vulnerabilities` | Имя коллекции |
| `VULNRAG_EMBED_MODEL` / `_DIM` | `bge-m3` / `1024` | Модель эмбеддингов и размерность |
| `VULNRAG_LLM_MODEL` | `qwen2.5:3b` | Модель генерации |
| `VULNRAG_OLLAMA_HOST` | `http://localhost:11434` | Адрес Ollama |
| `VULNRAG_TOP_K` | `8` | Сколько кандидатов доставать |
| `VULNRAG_SYNC_STATE_PATH` | `sync_state.json` | Файл состояния синхронизации |

## Источники данных

- **NVD (CVE)** — база, описания, CVSS, CPE-диапазоны версий. Тянется окнами ≤120 дней.
- **CISA KEV** — флаг реально эксплуатируемых уязвимостей.
- **OSV** — `fixed_versions` по экосистемам пакетов.

Синхронизация изолирует источники: падение KEV/OSV не мешает индексации NVD,
курсор упавшего источника не сдвигается.

## Известные ограничения / TODO

- **OSV-адаптер** обращается к `/v1/query` с `{"id": ...}` и получает `400` — получение
  по CVE-ID идёт через `GET /v1/vulns/{id}`. Сейчас обогащение `fixed_versions` не работает
  (вердикт считается по NVD-диапазонам и без этого). Требует исправления.
- Свежие CVE часто без CPE («Awaiting Analysis») — для них компонент/версия неизвестны.
- OSV-запрос по каждому CVE не масштабируется на полный бэкафилл — нужен батч/дамп.
- Промпт под русский язык можно подтюнить (`qwen2.5:3b` отвечает суховато).

## Тесты

```bash
./run.sh test        # или: venv/bin/pytest -q
```
Тесты не требуют сети/сервисов: Qdrant используется in-memory (`:memory:`), Ollama
подменяется фейками.
