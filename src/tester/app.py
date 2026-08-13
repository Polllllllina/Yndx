"""FastAPI entry point for the red-team tester service."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from fastapi import FastAPI, HTTPException

from common import TestSuite
from tester.body_limit import EvaluateBodyLimitMiddleware
from tester.client import GuardrailClient, GuardrailUnavailable
from tester.models import EvaluationReport, RunStatus
from tester.scoring import score_run


RUN_TIMEOUT_SECONDS = 60.0
MAX_EVALUATE_BODY_BYTES = 64 * 1024 * 1024
MAX_EVALUATE_BODY_CHUNKS = 8192
ClientFactory = Callable[[], GuardrailClient]


def create_app(
    client_factory: ClientFactory | None = None,
    *,
    run_timeout: float = RUN_TIMEOUT_SECONDS,
    max_evaluate_body_bytes: int = MAX_EVALUATE_BODY_BYTES,
    max_evaluate_body_chunks: int = MAX_EVALUATE_BODY_CHUNKS,
) -> FastAPI:
    if run_timeout <= 0:
        raise ValueError("run_timeout must be positive")
    if (
        isinstance(max_evaluate_body_bytes, bool)
        or not isinstance(max_evaluate_body_bytes, int)
        or max_evaluate_body_bytes <= 0
    ):
        raise ValueError("max_evaluate_body_bytes must be a positive integer")
    if (
        isinstance(max_evaluate_body_chunks, bool)
        or not isinstance(max_evaluate_body_chunks, int)
        or max_evaluate_body_chunks <= 0
    ):
        raise ValueError("max_evaluate_body_chunks must be a positive integer")
    make_client = client_factory or GuardrailClient
    application = FastAPI(title="Trust & Safety Red-Team Tester")
    application.add_middleware(
        EvaluateBodyLimitMiddleware,
        max_bytes=max_evaluate_body_bytes,
        max_chunks=max_evaluate_body_chunks,
    )

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "red-team-tester"}

    @application.post("/v1/evaluate", response_model=EvaluationReport)
    async def evaluate(suite: TestSuite) -> EvaluationReport:
        try:
            return await asyncio.wait_for(
                _run_evaluation(suite, make_client), timeout=run_timeout
            )
        except GuardrailUnavailable as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=504,
                detail=f"evaluation exceeded {run_timeout:g} seconds",
            ) from exc

    return application


async def _run_evaluation(
    suite: TestSuite,
    client_factory: ClientFactory,
) -> EvaluationReport:
    async with client_factory() as client:
        await client.preflight()
        outcomes = await client.evaluate(suite)

    status = (
        RunStatus.COMPLETED_WITH_ERRORS
        if any(item.error_code is not None for item in outcomes)
        else RunStatus.COMPLETED
    )
    return EvaluationReport(
        suite_id=suite.suite_id,
        policy_version=suite.policy_version,
        status=status,
        metrics=score_run(suite, outcomes),
        cases=outcomes,
    )


app = create_app()
