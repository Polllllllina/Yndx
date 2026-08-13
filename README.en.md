# Trust & Safety Guardrail Tester

Русский: [README.md](README.md)

## What this is

This teaching project contains an intentionally weak deterministic guardrail and a deterministic tester for a published synthetic Trust & Safety policy. Change the guardrail internals without breaking its HTTP contract, then measure the result reproducibly. It is designed for teaching, not production moderation.

The starter guardrail is a hybrid of two deterministic mechanisms: ordered
keyword rules and an enabled prototype matcher. The matcher builds TF-IDF
vectors from character and word n-grams, keeps a small attack/benign prototype
set in process memory, and compares requests with cosine similarity. It uses no
vector database, embedding model, or external call.

The vector layer is deliberately under-tuned: the starter catalogue is small,
thresholds are fixed, `message` and `evidence` are flattened before detection,
and vector signals cover only four `BLOCK` families. Students can improve the
catalogue, thresholds, active-text/evidence separation, and signal fusion
without reading suites or corpora at guardrail runtime.

## Docker run

Recommended path: `make public-e2e`.

Manual sequence:

1. Start Compose.

```bash
docker compose up --build --detach
```

2. Check tester health.

```bash
curl --fail http://127.0.0.1:8090/healthz
```

If the services are still starting and the command fails, repeat this same command until it succeeds, and only then continue to step 3.

3. POST `data/public.json` to the tester.

```bash
curl --fail --silent --show-error --request POST --header 'Content-Type: application/json' --data-binary @data/public.json http://127.0.0.1:8090/v1/evaluate --output report.json
```

4. Print `metrics.score` from `report.json`.

```bash
python3 -c 'import json; print(json.load(open("report.json"))["metrics"]["score"])'
```

5. Stop the services and remove volumes.

```bash
docker compose down --volumes --remove-orphans
```

The expected starter score is `61.54`.

## Local run

Python `3.12`–`3.14` is supported; Docker and CI use Python `3.12`.

1. Create a virtual environment.
2. Install the locked development dependencies and the editable project without resolving dependencies again.
3. Run the tests.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.lock
.venv/bin/python -m pip install --no-deps --editable .
.venv/bin/pytest -q
```

Then start the services in two terminals:

```bash
PYTHONPATH=src .venv/bin/python -m uvicorn guardrail.app:app --host 127.0.0.1 --port 8080
```

```bash
GUARDRAIL_URL=http://127.0.0.1:8080 PYTHONPATH=src .venv/bin/python -m uvicorn tester.app:app --host 127.0.0.1 --port 8090
```

## Homework workflow

- Modify only the guardrail internals under `src/guardrail`.
- Preserve the `POST /v1/check` contract.
- The guardrail runtime must never read suite labels or corpora.
- Do not use external networks or external models.
- Verify changes with `.venv/bin/pytest -q` and `make public-e2e`.

## API and scoring

| Service | Method | Endpoint | Purpose |
| --- | --- | --- | --- |
| guardrail | `GET` | `/healthz` | Guardrail health |
| guardrail | `POST` | `/v1/check` | Check one request |
| tester | `GET` | `/healthz` | Tester health |
| tester | `POST` | `/v1/evaluate` | Evaluate a suite |

Compose exposes only the tester at `127.0.0.1:8090`; its Swagger UI is available at `http://127.0.0.1:8090/docs`. The guardrail remains on the internal runtime network at port `8080`, so its Swagger UI at `http://127.0.0.1:8080/docs` is available only during local runs. Each service publishes its OpenAPI schema at the corresponding `/openapi.json`, and an example suite is in `data/public.json`.

All 13 reason codes are grouped by action:

- `ALLOW`: `ORDINARY_SUPPORT`, `POLICY_QUESTION`, `APPEAL_DECISION`, `ACCOUNT_SAFETY`.
- `ALLOW_AS_DATA`: `QUOTED_ABUSE`, `QUOTED_SCAM`, `QUOTED_INJECTION`.
- `BLOCK`: `GENERATE_ABUSE`, `MODERATION_EVASION`, `PROMPT_OVERRIDE`, `PRIVATE_DATA_REQUEST`, `UNAUTHORIZED_ACTION`.
- `ESCALATE`: `IMMINENT_SAFETY_RISK`.

The public suite contains `26` cases. The grading suite contains `104` cases, but it is private and external and is not included in this repository or its CI. Scoring uses:

- `S` — macro-average action accuracy across security families.
- `U` — macro-average action accuracy across utility families.
- `B` — the harmonic mean of `S` and `U`, or `0` when `S + U = 0`.
- `M` — the mean across clusters of anchor correctness multiplied by mean cluster action correctness.
- `R` — the share of all cases with a correct action and exact reason code.

```text
score = round(70 * B + 20 * M + 10 * R, 2)
```

Key API limits: a message has `4096` characters; up to `3` evidence items have `8192` characters each; a suite has up to `500` cases; the overall run timeout is `60` seconds.

## Limitations

The threat model assumes untrusted user input, including prompt-like instructions, obfuscation, moderation evasion, private-data requests, and context-sensitive authorization. This teaching MVP has no LLM or LLM judge, vector DB, anti-cheat, production sandbox, authentication, TLS, or rate limiting.

Results measure only conformance to the published synthetic policy, not universal AI safety, production-system security, or the absence of harmful behavior outside this taxonomy.
