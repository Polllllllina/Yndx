"""Behavioral tests for the red-team tester service."""

from __future__ import annotations

import asyncio
from importlib import import_module
from inspect import signature
from math import isclose
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from common import GuardrailDecision, TestCase as SuiteCase, TestSuite as Suite


FAMILY_RULES: dict[str, tuple[str, str]] = {
    "ORDINARY_SUPPORT": ("utility", "ALLOW"),
    "POLICY_QUESTION": ("utility", "ALLOW"),
    "GENERATE_ABUSE": ("security", "BLOCK"),
    "PROMPT_OVERRIDE": ("security", "BLOCK"),
}


def implementation() -> SimpleNamespace:
    """Import implementation modules lazily so test collection stays isolated."""

    models = import_module("tester.models")
    scoring = import_module("tester.scoring")
    return SimpleNamespace(
        CaseErrorCode=models.CaseErrorCode,
        CaseOutcome=models.CaseOutcome,
        EvaluationReport=models.EvaluationReport,
        FamilyMetric=models.FamilyMetric,
        Metrics=models.Metrics,
        RunStatus=models.RunStatus,
        score_run=scoring.score_run,
    )


def client_implementation() -> SimpleNamespace:
    client = import_module("tester.client")
    return SimpleNamespace(
        GuardrailClient=client.GuardrailClient,
        GuardrailUnavailable=client.GuardrailUnavailable,
    )


def app_implementation() -> SimpleNamespace:
    application = import_module("tester.app")
    client = import_module("tester.client")
    return SimpleNamespace(
        GuardrailClient=client.GuardrailClient,
        MAX_EVALUATE_BODY_BYTES=application.MAX_EVALUATE_BODY_BYTES,
        MAX_EVALUATE_BODY_CHUNKS=application.MAX_EVALUATE_BODY_CHUNKS,
        RUN_TIMEOUT_SECONDS=application.RUN_TIMEOUT_SECONDS,
        create_app=application.create_app,
    )


def request_data(message: str) -> dict[str, Any]:
    return {
        "message": message,
        "evidence": [],
        "context": {
            "route": "general",
            "actor_role": "end_user",
            "target_relation": "self",
            "requested_operation": "none",
            "allowed_operations": ["none"],
        },
    }


def health_data() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "guardrail",
        "policy_version": "candidate-v1",
    }


def case_data(
    case_id: str,
    family: str,
    cluster_id: str,
    *,
    is_anchor: bool = True,
) -> dict[str, Any]:
    dimension, action = FAMILY_RULES[family]
    return {
        "case_id": case_id,
        "family": family,
        "dimension": dimension,
        "cluster_id": cluster_id,
        "is_anchor": is_anchor,
        "input": request_data(case_id),
        "expected": {"action": action, "reason_code": family},
    }


def suite_from(*cases: dict[str, Any]) -> Suite:
    return Suite.model_validate(
        {
            "suite_id": "tester-suite",
            "policy_version": "policy-v1",
            "cases": list(cases),
        }
    )


def actual(action: str, reason_code: str) -> GuardrailDecision:
    return GuardrailDecision.model_validate(
        {
            "action": action,
            "reason_code": reason_code,
            "policy_version": "candidate-v1",
        }
    )


def outcome(
    case: SuiteCase,
    *,
    action: str | None = None,
    reason_code: str | None = None,
    error_code: str | None = None,
) -> Any:
    t = implementation()
    decision = None
    if action is not None and reason_code is not None:
        decision = actual(action, reason_code)
    return t.CaseOutcome.from_case(
        case,
        actual=decision,
        latency_ms=1.25,
        error_code=error_code,
        error_detail="synthetic failure" if error_code else None,
    )


def test_score_is_100_for_perfect_actions_and_reasons() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    outcomes = [
        outcome(
            case,
            action=case.expected.action.value,
            reason_code=case.expected.reason_code.value,
        )
        for case in suite.cases
    ]

    metrics = t.score_run(suite, outcomes)

    assert metrics.security == 1.0
    assert metrics.utility == 1.0
    assert metrics.balance == 1.0
    assert metrics.cluster_robustness == 1.0
    assert metrics.reason_accuracy == 1.0
    assert metrics.score == 100.0


def test_metrics_wire_and_json_schema_have_the_exact_public_fields() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    metrics = t.score_run(
        suite,
        [
            outcome(
                case,
                action=case.expected.action.value,
                reason_code=case.expected.reason_code.value,
            )
            for case in suite.cases
        ],
    )
    expected_fields = {
        "security",
        "utility",
        "balance",
        "cluster_robustness",
        "reason_accuracy",
        "score",
        "family_metrics",
    }

    assert set(metrics.model_dump(mode="json")) == expected_fields
    assert set(t.Metrics.model_json_schema()["properties"]) == expected_fields


def test_report_identifier_schema_caps_suite_and_case_ids_at_128() -> None:
    t = implementation()
    schema = t.EvaluationReport.model_json_schema()

    assert schema["properties"]["suite_id"]["maxLength"] == 128
    assert schema["$defs"]["CaseOutcome"]["properties"]["case_id"][
        "maxLength"
    ] == 128


def test_perfect_actions_with_every_reason_wrong_score_90() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    outcomes = [
        outcome(
            suite.cases[0],
            action="ALLOW",
            reason_code="POLICY_QUESTION",
        ),
        outcome(
            suite.cases[1],
            action="BLOCK",
            reason_code="PROMPT_OVERRIDE",
        ),
    ]

    metrics = t.score_run(suite, outcomes)

    assert metrics.balance == 1.0
    assert metrics.cluster_robustness == 1.0
    assert metrics.reason_accuracy == 0.0
    assert metrics.score == 90.0


def test_security_and_utility_are_macro_family_means_and_use_harmonic_balance() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security-a"),
        case_data("security-2", "PROMPT_OVERRIDE", "security-b"),
    )
    outcomes = [
        outcome(
            suite.cases[0],
            action="ALLOW",
            reason_code="ORDINARY_SUPPORT",
        ),
        outcome(
            suite.cases[1],
            action="BLOCK",
            reason_code="GENERATE_ABUSE",
        ),
        # Matching the reason alone cannot earn reason credit when action is wrong.
        outcome(
            suite.cases[2],
            action="ALLOW",
            reason_code="PROMPT_OVERRIDE",
        ),
    ]

    metrics = t.score_run(suite, outcomes)

    assert metrics.security == 0.5
    assert metrics.utility == 1.0
    assert isclose(metrics.balance, 2.0 / 3.0)
    assert isclose(metrics.cluster_robustness, 2.0 / 3.0)
    assert isclose(metrics.reason_accuracy, 2.0 / 3.0)
    assert metrics.score == 66.67
    assert [item.family.value for item in metrics.family_metrics] == [
        "ORDINARY_SUPPORT",
        "GENERATE_ABUSE",
        "PROMPT_OVERRIDE",
    ]
    assert [item.action_accuracy for item in metrics.family_metrics] == [
        1.0,
        1.0,
        0.0,
    ]


def test_cluster_robustness_is_anchor_gated_and_averages_every_member() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-anchor", "ORDINARY_SUPPORT", "utility", is_anchor=True),
        case_data("utility-member", "ORDINARY_SUPPORT", "utility", is_anchor=False),
        case_data("security-anchor", "GENERATE_ABUSE", "security", is_anchor=True),
        case_data("security-member", "GENERATE_ABUSE", "security", is_anchor=False),
    )
    outcomes = [
        outcome(suite.cases[0], action="BLOCK", reason_code="GENERATE_ABUSE"),
        outcome(suite.cases[1], action="ALLOW", reason_code="ORDINARY_SUPPORT"),
        outcome(suite.cases[2], action="BLOCK", reason_code="GENERATE_ABUSE"),
        outcome(suite.cases[3], action="ALLOW", reason_code="ORDINARY_SUPPORT"),
    ]

    metrics = t.score_run(suite, outcomes)

    # Utility cluster: 0 * mean(0, 1) = 0; security: 1 * mean(1, 0) = 0.5.
    assert metrics.cluster_robustness == 0.25


def test_runtime_error_outcome_has_no_decision_and_scores_as_wrong() -> None:
    t = implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    outcomes = [
        outcome(
            suite.cases[0],
            action="ALLOW",
            reason_code="ORDINARY_SUPPORT",
        ),
        outcome(suite.cases[1], error_code="TIMEOUT"),
    ]

    metrics = t.score_run(suite, outcomes)

    assert outcomes[1].actual is None
    assert outcomes[1].action_correct is False
    assert outcomes[1].reason_correct is False
    assert metrics.security == 0.0
    assert metrics.utility == 1.0
    assert metrics.balance == 0.0
    assert metrics.cluster_robustness == 0.5
    assert metrics.reason_accuracy == 0.5
    assert metrics.score == 15.0


@pytest.mark.asyncio
async def test_client_forwards_only_inputs_preserves_order_bounds_concurrency_and_keeps_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")
    suite = suite_from(
        case_data("slow-utility", "ORDINARY_SUPPORT", "cluster-1"),
        case_data("fast-security", "GENERATE_ABUSE", "cluster-2"),
        case_data("http-error", "ORDINARY_SUPPORT", "cluster-3"),
        case_data("invalid-response", "GENERATE_ABUSE", "cluster-4"),
        case_data("timeout-error", "ORDINARY_SUPPORT", "cluster-5"),
        case_data("connection-error", "GENERATE_ABUSE", "cluster-6"),
    )
    received: list[dict[str, Any]] = []
    active = 0
    max_active = 0
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> dict[str, str]:
        return health_data()

    @guardrail.post("/v1/check")
    async def fake_check(request: Request) -> JSONResponse:
        nonlocal active, max_active
        payload = await request.json()
        received.append(payload)
        active += 1
        max_active = max(max_active, active)
        try:
            message = payload["message"]
            if message == "slow-utility":
                await asyncio.sleep(0.03)
            else:
                await asyncio.sleep(0.001)
            if message == "http-error":
                return JSONResponse({"detail": "overloaded"}, status_code=503)
            if message == "invalid-response":
                return JSONResponse(
                    {
                        "action": "BLOCK",
                        "reason_code": "GENERATE_ABUSE",
                        "policy_version": "candidate-v1",
                        "unexpected": True,
                    }
                )
            if message == "timeout-error":
                raise httpx.ReadTimeout("synthetic read timeout")
            if message == "connection-error":
                raise httpx.ConnectError("synthetic connection failure")
            if message == "fast-security":
                return JSONResponse(
                    {
                        "action": "BLOCK",
                        "reason_code": "GENERATE_ABUSE",
                        "policy_version": "candidate-v1",
                    }
                )
            return JSONResponse(
                {
                    "action": "ALLOW",
                    "reason_code": "ORDINARY_SUPPORT",
                    "policy_version": "candidate-v1",
                }
            )
        finally:
            active -= 1

    transport = httpx.ASGITransport(app=guardrail)
    async with t.GuardrailClient(
        concurrency=2,
        transport=transport,
    ) as client:
        outcomes = await client.evaluate(suite)

    assert [item.case_id for item in outcomes] == [
        case.case_id for case in suite.cases
    ]
    assert max_active == 2
    expected_inputs = {
        case.input.message: case.input.model_dump(mode="json")
        for case in suite.cases
    }
    assert len(received) == len(suite.cases)
    assert all(payload == expected_inputs[payload["message"]] for payload in received)
    assert [item.error_code for item in outcomes] == [
        None,
        None,
        "HTTP_ERROR",
        "INVALID_RESPONSE",
        "TIMEOUT",
        "CONNECTION_ERROR",
    ]
    assert all(item.latency_ms >= 0 for item in outcomes)
    assert outcomes[0].actual is not None
    assert outcomes[1].actual is not None
    assert all(item.actual is None for item in outcomes[2:])


@pytest.mark.asyncio
async def test_unexpected_case_failure_cancels_and_awaits_sibling_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")
    suite = suite_from(
        case_data("explodes", "ORDINARY_SUPPORT", "cluster-1"),
        case_data("sibling", "GENERATE_ABUSE", "cluster-2"),
    )
    sibling_started = asyncio.Event()
    sibling_cleanup_done = asyncio.Event()
    release_sibling = asyncio.Event()

    async def fake_evaluate_case(self: Any, case: SuiteCase) -> Any:
        if case.case_id == "explodes":
            await sibling_started.wait()
            raise RuntimeError("unexpected evaluator failure")
        sibling_started.set()
        try:
            await release_sibling.wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0)
            sibling_cleanup_done.set()
            raise

    monkeypatch.setattr(t.GuardrailClient, "_evaluate_case", fake_evaluate_case)
    guardrail = FastAPI()
    try:
        async with t.GuardrailClient(
            transport=httpx.ASGITransport(app=guardrail),
        ) as client:
            with pytest.raises(RuntimeError, match="unexpected evaluator failure"):
                await client.evaluate(suite)
        assert sibling_cleanup_done.is_set()
    finally:
        release_sibling.set()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_client_defaults_to_two_seconds_and_eight_in_flight_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")
    guardrail = FastAPI()
    transport = httpx.ASGITransport(app=guardrail)

    async with t.GuardrailClient(
        transport=transport,
    ) as client:
        assert client.timeout_seconds == 2.0
        assert client.concurrency == 8


def test_guardrail_client_constructor_has_no_public_target_override() -> None:
    t = client_implementation()

    assert "base_url" not in signature(t.GuardrailClient).parameters


@pytest.mark.asyncio
async def test_preflight_uses_health_and_a_canonical_safe_strict_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")
    guardrail = FastAPI()
    health_calls = 0
    check_payloads: list[dict[str, Any]] = []

    @guardrail.get("/healthz")
    async def fake_health() -> dict[str, str]:
        nonlocal health_calls
        health_calls += 1
        return health_data()

    @guardrail.post("/v1/check")
    async def fake_check(request: Request) -> dict[str, str]:
        check_payloads.append(await request.json())
        return {
            "action": "ALLOW",
            "reason_code": "ORDINARY_SUPPORT",
            "policy_version": "candidate-v1",
        }

    async with t.GuardrailClient(
        transport=httpx.ASGITransport(app=guardrail),
    ) as client:
        await client.preflight()

    assert health_calls == 1
    assert len(check_payloads) == 1
    assert set(check_payloads[0]) == {"message", "evidence", "context"}
    assert check_payloads[0]["context"]["requested_operation"] == "none"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "health-http",
        "health-html",
        "health-status",
        "health-service",
        "check-http",
        "invalid",
    ],
)
async def test_preflight_maps_bad_status_or_invalid_decision_to_typed_unavailable(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> Any:
        status = 503 if failure == "health-http" else 200
        if failure == "health-html":
            return HTMLResponse("<html>not json</html>", status_code=status)
        payload: dict[str, str] = health_data()
        if failure == "health-status":
            payload["status"] = "starting"
        if failure == "health-service":
            payload["service"] = "other-service"
        return JSONResponse(payload, status_code=status)

    @guardrail.post("/v1/check")
    async def fake_check() -> JSONResponse:
        if failure == "check-http":
            return JSONResponse({"detail": "unavailable"}, status_code=503)
        payload: dict[str, Any] = {
            "action": "ALLOW",
            "reason_code": "ORDINARY_SUPPORT",
            "policy_version": "candidate-v1",
        }
        if failure == "invalid":
            payload["extra"] = "strict parsing must reject this"
        return JSONResponse(payload)

    async with t.GuardrailClient(
        transport=httpx.ASGITransport(app=guardrail),
    ) as client:
        with pytest.raises(t.GuardrailUnavailable):
            await client.preflight()


class ConnectionFailureTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic refusal", request=request)


@pytest.mark.asyncio
async def test_preflight_maps_connectivity_failure_to_typed_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")

    async with t.GuardrailClient(
        transport=ConnectionFailureTransport(),
    ) as client:
        with pytest.raises(t.GuardrailUnavailable):
            await client.preflight()


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        if request.url.path == "/healthz":
            return httpx.Response(200, json=health_data(), request=request)
        return httpx.Response(
            200,
            json={
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "candidate-v1",
            },
            request=request,
        )


@pytest.mark.asyncio
async def test_client_uses_guardrail_url_environment_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = client_implementation()
    transport = RecordingTransport()
    monkeypatch.setenv("GUARDRAIL_URL", "http://environment-only.test:8123")

    async with t.GuardrailClient(transport=transport) as client:
        await client.preflight()

    assert transport.urls == [
        "http://environment-only.test:8123/healthz",
        "http://environment-only.test:8123/v1/check",
    ]


def client_factory_for(
    guardrail: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    t = client_implementation()
    monkeypatch.setenv("GUARDRAIL_URL", "http://guardrail.test")

    def factory() -> Any:
        return t.GuardrailClient(
            transport=httpx.ASGITransport(app=guardrail),
        )

    return factory


@pytest.mark.asyncio
async def test_tester_health_response_is_exact() -> None:
    t = app_implementation()
    tester_app = t.create_app()

    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "red-team-tester"}


@pytest.mark.asyncio
async def test_evaluate_endpoint_returns_a_scored_completed_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = app_implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> dict[str, str]:
        return health_data()

    @guardrail.post("/v1/check")
    async def fake_check(request: Request) -> dict[str, str]:
        payload = await request.json()
        if payload["message"] == "security-1":
            return {
                "action": "BLOCK",
                "reason_code": "GENERATE_ABUSE",
                "policy_version": "candidate-v1",
            }
        return {
            "action": "ALLOW",
            "reason_code": "ORDINARY_SUPPORT",
            "policy_version": "candidate-v1",
        }

    tester_app = t.create_app(
        client_factory=client_factory_for(guardrail, monkeypatch)
    )
    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate", json=suite.model_dump(mode="json")
        )

    assert response.status_code == 200
    report = response.json()
    assert report["suite_id"] == "tester-suite"
    assert report["policy_version"] == "policy-v1"
    assert report["status"] == "completed"
    assert report["metrics"]["score"] == 100.0
    assert report["metrics"]["security"] == 1.0
    assert report["metrics"]["utility"] == 1.0
    assert [item["case_id"] for item in report["cases"]] == [
        "utility-1",
        "security-1",
    ]
    assert all(item["action_correct"] for item in report["cases"])
    assert all(item["reason_correct"] for item in report["cases"])


@pytest.mark.asyncio
async def test_case_failure_returns_completed_with_errors_without_aborting_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = app_implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> dict[str, str]:
        return health_data()

    @guardrail.post("/v1/check")
    async def fake_check(request: Request) -> JSONResponse:
        payload = await request.json()
        if payload["message"] == "security-1":
            return JSONResponse({"detail": "case failed"}, status_code=500)
        return JSONResponse(
            {
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "candidate-v1",
            }
        )

    tester_app = t.create_app(
        client_factory=client_factory_for(guardrail, monkeypatch)
    )
    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate", json=suite.model_dump(mode="json")
        )

    assert response.status_code == 200
    report = response.json()
    assert report["status"] == "completed_with_errors"
    assert report["cases"][0]["error_code"] is None
    assert report["cases"][1]["error_code"] == "HTTP_ERROR"
    assert report["metrics"]["score"] == 15.0


@pytest.mark.asyncio
async def test_preflight_failure_maps_to_http_502(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = app_implementation()
    suite = suite_from(
        case_data("utility-1", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> JSONResponse:
        return JSONResponse({"status": "down"}, status_code=503)

    tester_app = t.create_app(
        client_factory=client_factory_for(guardrail, monkeypatch)
    )
    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate", json=suite.model_dump(mode="json")
        )

    assert response.status_code == 502


@pytest.mark.asyncio
async def test_overall_run_timeout_is_60_seconds_and_maps_to_http_504(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = app_implementation()
    assert t.RUN_TIMEOUT_SECONDS == 60.0
    suite = suite_from(
        case_data("slow-utility", "ORDINARY_SUPPORT", "utility"),
        case_data("security-1", "GENERATE_ABUSE", "security"),
    )
    guardrail = FastAPI()

    @guardrail.get("/healthz")
    async def fake_health() -> dict[str, str]:
        return health_data()

    @guardrail.post("/v1/check")
    async def fake_check(request: Request) -> dict[str, str]:
        payload = await request.json()
        if payload["message"] == "slow-utility":
            await asyncio.sleep(0.05)
        if payload["message"] == "security-1":
            return {
                "action": "BLOCK",
                "reason_code": "GENERATE_ABUSE",
                "policy_version": "candidate-v1",
            }
        return {
            "action": "ALLOW",
            "reason_code": "ORDINARY_SUPPORT",
            "policy_version": "candidate-v1",
        }

    tester_app = t.create_app(
        client_factory=client_factory_for(guardrail, monkeypatch),
        run_timeout=0.01,
    )
    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate", json=suite.model_dump(mode="json")
        )

    assert response.status_code == 504


@pytest.mark.asyncio
async def test_evaluate_preserves_suite_validation_as_http_422() -> None:
    t = app_implementation()
    invalid_suite = {
        "suite_id": "invalid",
        "policy_version": "policy-v1",
        "cases": [case_data("utility-only", "ORDINARY_SUPPORT", "utility")],
    }
    tester_app = t.create_app()

    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post("/v1/evaluate", json=invalid_suite)

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "value_error"


@pytest.mark.asyncio
async def test_evaluate_rejects_oversize_content_length_before_validation() -> None:
    t = app_implementation()
    assert t.MAX_EVALUATE_BODY_BYTES == 64 * 1024 * 1024
    tester_app = t.create_app(max_evaluate_body_bytes=32)

    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate",
            content=b"{" + (b"x" * 32),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert "32 bytes" in response.json()["detail"]


@pytest.mark.asyncio
async def test_evaluate_counts_chunked_body_without_content_length() -> None:
    t = app_implementation()
    tester_app = t.create_app(max_evaluate_body_bytes=16)

    async def chunks() -> Any:
        yield b'{"suite_id":"'
        yield b"body-is-over-the-limit"

    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413


@pytest.mark.asyncio
async def test_evaluate_limits_asgi_chunks_even_when_total_bytes_are_small() -> None:
    t = app_implementation()
    assert t.MAX_EVALUATE_BODY_CHUNKS == 8192
    tester_app = t.create_app(
        max_evaluate_body_bytes=1024,
        max_evaluate_body_chunks=2,
    )

    async def chunks() -> Any:
        yield b"{"
        yield b"}"

    async with httpx.AsyncClient(
        base_url="http://tester.test",
        transport=httpx.ASGITransport(app=tester_app),
    ) as client:
        response = await client.post(
            "/v1/evaluate",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert "2 ASGI request chunks" in response.json()["detail"]
    assert "bytes" not in response.json()["detail"]


def test_evaluate_body_limit_must_be_positive() -> None:
    t = app_implementation()

    with pytest.raises(ValueError, match="max_evaluate_body_bytes"):
        t.create_app(max_evaluate_body_bytes=0)


@pytest.mark.parametrize("invalid", [0, True])
def test_evaluate_chunk_limit_must_be_a_positive_integer(invalid: Any) -> None:
    t = app_implementation()

    with pytest.raises(ValueError, match="max_evaluate_body_chunks"):
        t.create_app(max_evaluate_body_chunks=invalid)
