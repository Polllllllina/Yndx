#!/usr/bin/env bash

set -Eeuo pipefail

TESTER_HEALTH_URL="${TESTER_HEALTH_URL:-http://localhost:8090/healthz}"
EVALUATE_URL="${EVALUATE_URL:-http://localhost:8090/v1/evaluate}"
SUITE_PATH="${SUITE_PATH:-data/public.json}"
REPORT_PATH="${REPORT_PATH:-report.json}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-60}"
HEALTH_INTERVAL_SECONDS="${HEALTH_INTERVAL_SECONDS:-1}"
CURL_CONNECT_TIMEOUT_SECONDS="${CURL_CONNECT_TIMEOUT_SECONDS:-2}"
HEALTH_MAX_TIME_SECONDS="${HEALTH_MAX_TIME_SECONDS:-10}"
EVALUATION_MAX_TIME_SECONDS="${EVALUATION_MAX_TIME_SECONDS:-65}"

validate_configuration() {
    if [[ ! "$HEALTH_ATTEMPTS" =~ ^[1-9][0-9]*$ ]]; then
        echo "HEALTH_ATTEMPTS must be a positive integer" >&2
        return 2
    fi

    "$PYTHON_BIN" - \
        "HEALTH_INTERVAL_SECONDS=$HEALTH_INTERVAL_SECONDS" \
        "CURL_CONNECT_TIMEOUT_SECONDS=$CURL_CONNECT_TIMEOUT_SECONDS" \
        "HEALTH_MAX_TIME_SECONDS=$HEALTH_MAX_TIME_SECONDS" \
        "EVALUATION_MAX_TIME_SECONDS=$EVALUATION_MAX_TIME_SECONDS" <<'PY'
import math
import sys

for item in sys.argv[1:]:
    name, raw = item.split("=", 1)
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a finite, strictly positive number")
    if not math.isfinite(value) or value <= 0:
        raise SystemExit(f"{name} must be a finite, strictly positive number")
PY
}

validate_configuration

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "Docker Compose is required (docker compose or docker-compose)" >&2
    exit 127
fi

cleanup() {
    local exit_code="$?"
    trap - EXIT
    "${COMPOSE[@]}" down --volumes --remove-orphans || true
    exit "$exit_code"
}

trap cleanup EXIT

wait_for_health() {
    local name="$1"
    local url="$2"
    local attempt

    for ((attempt = 1; attempt <= HEALTH_ATTEMPTS; attempt += 1)); do
        if curl \
            --fail \
            --silent \
            --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" \
            --max-time "$HEALTH_MAX_TIME_SECONDS" \
            "$url" >/dev/null; then
            return 0
        fi
        sleep "$HEALTH_INTERVAL_SECONDS"
    done

    echo "timed out waiting for ${name} health endpoint: ${url}" >&2
    return 1
}

"${COMPOSE[@]}" up --build --detach
wait_for_health "tester" "$TESTER_HEALTH_URL"

curl \
    --fail \
    --silent \
    --show-error \
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" \
    --max-time "$EVALUATION_MAX_TIME_SECONDS" \
    --request POST \
    --header "Content-Type: application/json" \
    --data-binary "@${SUITE_PATH}" \
    --output "$REPORT_PATH" \
    "$EVALUATE_URL"

"$PYTHON_BIN" - "$REPORT_PATH" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
score = report["metrics"]["score"]
if isinstance(score, bool) or not isinstance(score, (int, float)):
    raise SystemExit("report metrics.score is not numeric")
print(score)
PY
