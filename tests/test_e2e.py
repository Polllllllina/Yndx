"""Public-suite orchestration and full in-process HTTP-boundary coverage."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import httpx
import pytest

from common import Family
from guardrail.app import create_app as create_guardrail_app
from tester.app import create_app as create_tester_app
from tester.client import GuardrailClient


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_public_e2e.sh"


def test_make_is_the_public_e2e_entrypoint() -> None:
    completed = subprocess.run(
        ["make", "--no-print-directory", "--dry-run", "public-e2e"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "./scripts/run_public_e2e.sh"


def test_compose_exposes_only_tester_on_a_configurable_edge_bind() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    guardrail = compose.split("  guardrail:\n", 1)[1].split("\n  tester:\n", 1)[0]
    tester = compose.split("\n  tester:\n", 1)[1].split("\nnetworks:\n", 1)[0]
    networks = compose.split("\nnetworks:\n", 1)[1]

    assert "\n    ports:" not in guardrail
    assert "    networks:\n      - runtime" in guardrail
    assert "      - edge" not in guardrail
    assert '      GUARDRAIL_URL: http://guardrail:8080' in tester
    assert '${TESTER_BIND_HOST:-127.0.0.1}:8090:8090' in tester
    assert "    networks:\n      - runtime\n      - edge" in tester
    assert "  runtime:\n    internal: true" in networks
    assert "  edge:\n    internal: false" in networks


def test_tester_runtime_imports_without_guardrail_package(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    for package in ("common", "tester"):
        shutil.copytree(
            ROOT / "src" / package,
            runtime / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(runtime),
            "PYTHONNOUSERSITE": "1",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import tester.app; print(tester.app.__file__)"
            ),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    imported_paths = completed.stdout.splitlines()
    assert len(imported_paths) == 1
    assert all(str(runtime) in path for path in imported_paths)


def _runner_environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    fake_docker = bin_dir / "docker"
    fake_docker.write_text(
        """#!/bin/sh
if [ "$*" = "compose version" ]; then
    if [ "${DOCKER_COMPOSE_UNAVAILABLE:-0}" = "1" ]; then
        exit 1
    fi
    exit 0
fi
printf "%s\\n" "$*" >> "$DOCKER_LOG"
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    fake_docker_compose = bin_dir / "docker-compose"
    fake_docker_compose.write_text(
        '#!/bin/sh\nprintf "standalone %s\\n" "$*" >> "$DOCKER_LOG"\n',
        encoding="utf-8",
    )
    fake_docker_compose.chmod(0o755)
    curl_log = tmp_path / "curl.log"
    fake_curl = bin_dir / "curl"
    fake_curl.write_text(
        """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with Path(os.environ["CURL_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\\n")
if os.environ.get("CURL_FAIL_URL") in args:
    if "--show-error" in args:
        print("curl: (22) The requested URL returned error: 503", file=sys.stderr)
    raise SystemExit(22)
if "--output" in args:
    output = Path(args[args.index("--output") + 1])
    output.write_text(
        json.dumps(
            {
                "suite_id": "public-guardrail-v1",
                "status": "completed",
                "metrics": {"score": 61.54},
                "cases": [{"case_id": str(index)} for index in range(26)],
            }
        ),
        encoding="utf-8",
    )
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "CURL_LOG": str(curl_log),
            "SUITE_PATH": str(ROOT / "data" / "public.json"),
            "REPORT_PATH": str(tmp_path / "report.json"),
            "PYTHON_BIN": sys.executable,
            "HEALTH_ATTEMPTS": "5",
            "HEALTH_INTERVAL_SECONDS": "0.05",
        }
    )
    return env, docker_log, curl_log


def test_make_public_e2e_prints_only_score(tmp_path: Path) -> None:
    env, _, _ = _runner_environment(tmp_path)

    completed = subprocess.run(
        ["make", "--no-print-directory", "public-e2e"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "61.54"


def test_public_runner_posts_suite_and_prints_score(
    tmp_path: Path,
) -> None:
    env, docker_log, curl_log = _runner_environment(tmp_path)

    completed = subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "61.54"
    report: dict[str, Any] = json.loads(
        Path(env["REPORT_PATH"]).read_text(encoding="utf-8")
    )
    assert report["suite_id"] == "public-guardrail-v1"
    assert report["status"] == "completed"
    assert report["metrics"]["score"] == 61.54
    assert len(report["cases"]) == 26
    assert docker_log.read_text(encoding="utf-8").splitlines() == [
        "compose up --build --detach",
        "compose down --volumes --remove-orphans",
    ]
    curl_calls = [
        json.loads(line)
        for line in curl_log.read_text(encoding="utf-8").splitlines()
    ]
    assert [call[-1] for call in curl_calls] == [
        "http://localhost:8090/healthz",
        "http://localhost:8090/v1/evaluate",
    ]
    for call in curl_calls:
        assert call[call.index("--connect-timeout") + 1] == "2"
    assert curl_calls[0][curl_calls[0].index("--max-time") + 1] == "10"
    assert curl_calls[1][curl_calls[1].index("--max-time") + 1] == "65"
    assert f"@{ROOT / 'data' / 'public.json'}" in curl_calls[-1]


def test_public_runner_applies_separate_configurable_curl_timeouts(
    tmp_path: Path,
) -> None:
    env, _, curl_log = _runner_environment(tmp_path)
    env["CURL_CONNECT_TIMEOUT_SECONDS"] = "0.25"
    env["HEALTH_MAX_TIME_SECONDS"] = "1.5"
    env["EVALUATION_MAX_TIME_SECONDS"] = "66.5"

    completed = subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    curl_calls = [
        json.loads(line)
        for line in curl_log.read_text(encoding="utf-8").splitlines()
    ]
    assert len(curl_calls) == 2
    assert all(
        call[call.index("--connect-timeout") + 1] == "0.25"
        for call in curl_calls
    )
    assert curl_calls[0][curl_calls[0].index("--max-time") + 1] == "1.5"
    assert curl_calls[1][curl_calls[1].index("--max-time") + 1] == "66.5"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("HEALTH_ATTEMPTS", "0"),
        ("HEALTH_ATTEMPTS", "1.5"),
        ("HEALTH_INTERVAL_SECONDS", "0"),
        ("HEALTH_INTERVAL_SECONDS", "NaN"),
        ("CURL_CONNECT_TIMEOUT_SECONDS", "-1"),
        ("HEALTH_MAX_TIME_SECONDS", "invalid"),
        ("EVALUATION_MAX_TIME_SECONDS", "0"),
        ("EVALUATION_MAX_TIME_SECONDS", "NaN"),
    ],
)
def test_public_runner_rejects_invalid_configuration_before_compose_up(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    env, docker_log, _ = _runner_environment(tmp_path)
    env[name] = value

    completed = subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert name in completed.stderr
    assert not docker_log.exists() or docker_log.read_text(encoding="utf-8") == ""


def test_public_runner_always_tears_down_after_a_health_failure(
    tmp_path: Path,
) -> None:
    env, docker_log, _ = _runner_environment(tmp_path)
    env["CURL_FAIL_URL"] = "http://localhost:8090/healthz"
    env["HEALTH_ATTEMPTS"] = "1"

    completed = subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert "timed out waiting" in completed.stderr
    assert "curl:" not in completed.stderr
    assert docker_log.read_text(encoding="utf-8").splitlines() == [
        "compose up --build --detach",
        "compose down --volumes --remove-orphans",
    ]


def test_public_runner_falls_back_to_standalone_compose(tmp_path: Path) -> None:
    env, docker_log, _ = _runner_environment(tmp_path)
    env["DOCKER_COMPOSE_UNAVAILABLE"] = "1"

    completed = subprocess.run(
        [str(RUNNER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert docker_log.read_text(encoding="utf-8").splitlines() == [
        "standalone up --build --detach",
        "standalone down --volumes --remove-orphans",
    ]


@pytest.mark.asyncio
async def test_public_suite_runs_through_real_tester_and_guardrail_apps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardrail_app = create_guardrail_app()
    guardrail_transport = httpx.ASGITransport(app=guardrail_app)
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")

    def client_factory() -> GuardrailClient:
        return GuardrailClient(transport=guardrail_transport)

    tester_app = create_tester_app(client_factory=client_factory)
    suite = json.loads((ROOT / "data" / "public.json").read_text(encoding="utf-8"))
    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post("/v1/evaluate", json=suite)

    assert response.status_code == 200
    report = response.json()
    assert report["suite_id"] == "public-guardrail-v1"
    assert report["status"] == "completed"
    metrics = report["metrics"]
    assert 0.0 <= metrics["security"] <= 1.0
    assert 0.0 <= metrics["utility"] <= 1.0
    assert metrics["security"] > 0.0
    assert metrics["utility"] > 0.0
    assert 0.0 <= metrics["balance"] <= 1.0
    assert 0.0 <= metrics["cluster_robustness"] <= 1.0
    assert 0.0 <= metrics["reason_accuracy"] <= 1.0
    assert 0.0 <= metrics["score"] <= 100.0
    assert len(metrics["family_metrics"]) == 13
    assert {
        item["family"] for item in metrics["family_metrics"]
    } == {family.value for family in Family}
    assert len(report["cases"]) == 26
    assert all(case["error_code"] is None for case in report["cases"])
