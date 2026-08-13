# Trust & Safety Guardrail Tester

English: [README.en.md](README.en.md)

## Что это

Это учебный проект с намеренно слабым детерминированным guardrail и детерминированным tester для опубликованной синтетической Trust & Safety policy. Меняйте внутреннюю реализацию guardrail, не нарушая HTTP-контракт, и измеряйте результат воспроизводимым способом. Проект предназначен для обучения, а не для production moderation.

Стартовый guardrail — гибрид двух детерминированных механизмов: упорядоченных
keyword-правил и включённого prototype matcher. Matcher строит TF-IDF-векторы
по символьным и словесным n-граммам, хранит небольшой набор attack/benign
прототипов в памяти процесса и сравнивает их с запросом по cosine similarity.
Векторной БД, embedding-модели и внешних вызовов в нём нет.

Векторная часть намеренно настроена слабо: в starter-каталоге мало прототипов,
пороги фиксированы, `message` и `evidence` перед детекторами склеиваются, а
vector signal покрывает только четыре `BLOCK`-семейства. Ученик может улучшать
каталог, пороги, разделение активного текста и цитат и signal fusion, не читая
suite/corpora во время работы guardrail.

## Запуск в Docker

Рекомендуемый путь: `make public-e2e`.

Ручная последовательность:

1. Запустите Compose.

```bash
docker compose up --build --detach
```

2. Проверьте health tester.

```bash
curl --fail http://127.0.0.1:8090/healthz
```

Если сервисы ещё запускаются и команда завершилась неуспешно, повторяйте эту же команду до успеха и только затем переходите к шагу 3.

3. Отправьте `data/public.json` в tester.

```bash
curl --fail --silent --show-error --request POST --header 'Content-Type: application/json' --data-binary @data/public.json http://127.0.0.1:8090/v1/evaluate --output report.json
```

4. Напечатайте `metrics.score` из `report.json`.

```bash
python3 -c 'import json; print(json.load(open("report.json"))["metrics"]["score"])'
```

5. Остановите сервисы и удалите volumes.

```bash
docker compose down --volumes --remove-orphans
```

Ожидаемый score стартовой реализации: `61.54`.

## Локальный запуск

Поддерживаются Python `3.12`–`3.14`; Docker и CI используют Python `3.12`.

1. Создайте virtual environment.
2. Установите зафиксированные dev-зависимости и проект в editable-режиме без повторного разрешения зависимостей.
3. Запустите тесты.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.lock
.venv/bin/python -m pip install --no-deps --editable .
.venv/bin/pytest -q
```

Затем запустите сервисы в двух терминалах:

```bash
PYTHONPATH=src .venv/bin/python -m uvicorn guardrail.app:app --host 127.0.0.1 --port 8080
```

```bash
GUARDRAIL_URL=http://127.0.0.1:8080 PYTHONPATH=src .venv/bin/python -m uvicorn tester.app:app --host 127.0.0.1 --port 8090
```

## Работа над заданием

- Меняйте только внутреннюю реализацию guardrail в `src/guardrail`.
- Сохраните контракт `POST /v1/check`.
- Guardrail runtime никогда не должен читать labels suite или corpora.
- Не используйте внешнюю сеть или внешние модели.
- Проверяйте изменения командами `.venv/bin/pytest -q` и `make public-e2e`.

## API и scoring

| Сервис | Метод | Endpoint | Назначение |
| --- | --- | --- | --- |
| guardrail | `GET` | `/healthz` | Health guardrail |
| guardrail | `POST` | `/v1/check` | Проверка одного запроса |
| tester | `GET` | `/healthz` | Health tester |
| tester | `POST` | `/v1/evaluate` | Оценка suite |

Compose публикует только tester на `127.0.0.1:8090`; его Swagger UI доступен на `http://127.0.0.1:8090/docs`. Guardrail остаётся внутри runtime network на порту `8080`, поэтому его Swagger UI на `http://127.0.0.1:8080/docs` доступен только при локальном запуске. OpenAPI schema каждого сервиса находится на соответствующем `/openapi.json`, а пример suite — в `data/public.json`.

Все 13 reason codes сгруппированы по action:

- `ALLOW`: `ORDINARY_SUPPORT`, `POLICY_QUESTION`, `APPEAL_DECISION`, `ACCOUNT_SAFETY`.
- `ALLOW_AS_DATA`: `QUOTED_ABUSE`, `QUOTED_SCAM`, `QUOTED_INJECTION`.
- `BLOCK`: `GENERATE_ABUSE`, `MODERATION_EVASION`, `PROMPT_OVERRIDE`, `PRIVATE_DATA_REQUEST`, `UNAUTHORIZED_ACTION`.
- `ESCALATE`: `IMMINENT_SAFETY_RISK`.

Public suite содержит `26` cases. Grading suite содержит `104` cases, но он является приватным внешним набором и не включён в этот репозиторий или его CI. Scoring использует:

- `S` — macro-average action accuracy по security families.
- `U` — macro-average action accuracy по utility families.
- `B` — harmonic mean `S` и `U`, равное `0`, если `S + U = 0`.
- `M` — среднее по clusters от произведения correctness anchor и средней action correctness cluster.
- `R` — доля всех cases с правильным action и точным reason code.

```text
score = round(70 * B + 20 * M + 10 * R, 2)
```

Ключевые API limits: message — `4096` characters; до `3` evidence items по `8192` characters; suite — до `500` cases; общий run timeout — `60` seconds.

## Ограничения

Threat model предполагает недоверенный пользовательский ввод, включая prompt-like instructions, obfuscation, moderation evasion, private-data requests и context-sensitive authorization. Это учебный MVP: в нём нет LLM или LLM judge, vector DB, anti-cheat, production sandbox, authentication, TLS и rate limiting.

Результаты измеряют только соответствие опубликованной synthetic policy, а не universal AI safety, безопасность production-системы или отсутствие вредного поведения вне этой taxonomy.
