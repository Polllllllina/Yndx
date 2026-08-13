"""Concurrent HTTP client for evaluating suites against a guardrail."""

from __future__ import annotations

import asyncio
import os
from time import perf_counter
from types import TracebackType

import httpx
from pydantic import ValidationError

from common import (
    GuardrailDecision,
    GuardrailHealth,
    GuardrailRequest,
    TestCase,
    TestSuite,
)
from tester.models import CaseErrorCode, CaseOutcome


DEFAULT_GUARDRAIL_URL = "http://guardrail:8080"
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_CONCURRENCY = 8


class GuardrailUnavailable(RuntimeError):
    """Raised when the target fails readiness/protocol preflight."""


CANONICAL_SAFE_REQUEST = GuardrailRequest.model_validate(
    {
        "message": "Please help me with an ordinary account question.",
        "evidence": [],
        "context": {
            "route": "general",
            "actor_role": "end_user",
            "target_relation": "self",
            "requested_operation": "none",
            "allowed_operations": ["none"],
        },
    }
)


class GuardrailClient:
    """Own an HTTPX client and bound concurrent guardrail requests."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        concurrency: int = DEFAULT_CONCURRENCY,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")
        self.timeout_seconds = timeout
        self.concurrency = concurrency
        self._semaphore = asyncio.BoundedSemaphore(concurrency)
        self._client = httpx.AsyncClient(
            base_url=os.getenv("GUARDRAIL_URL", DEFAULT_GUARDRAIL_URL),
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> GuardrailClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def preflight(self) -> None:
        """Require a healthy endpoint and one strictly valid safe decision."""

        try:
            health = await self._client.get("/healthz")
            health.raise_for_status()
            GuardrailHealth.model_validate(health.json())
            response = await self._client.post(
                "/v1/check",
                json=CANONICAL_SAFE_REQUEST.model_dump(mode="json"),
            )
            response.raise_for_status()
            GuardrailDecision.model_validate(response.json())
        except (httpx.HTTPError, ValidationError, ValueError) as exc:
            raise GuardrailUnavailable(f"guardrail preflight failed: {exc}") from exc

    async def evaluate(self, suite: TestSuite) -> list[CaseOutcome]:
        """Evaluate every case concurrently while retaining suite order."""

        tasks = [
            asyncio.create_task(self._evaluate_case(case))
            for case in suite.cases
        ]
        try:
            return list(await asyncio.gather(*tasks))
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    async def _evaluate_case(self, case: TestCase) -> CaseOutcome:
        async with self._semaphore:
            started = perf_counter()
            try:
                response = await self._client.post(
                    "/v1/check",
                    json=case.input.model_dump(mode="json"),
                )
                response.raise_for_status()
                decision = GuardrailDecision.model_validate(response.json())
            except httpx.TimeoutException as exc:
                return self._error_outcome(
                    case, started, CaseErrorCode.TIMEOUT, exc
                )
            except httpx.HTTPStatusError as exc:
                return self._error_outcome(
                    case, started, CaseErrorCode.HTTP_ERROR, exc
                )
            except httpx.RequestError as exc:
                return self._error_outcome(
                    case, started, CaseErrorCode.CONNECTION_ERROR, exc
                )
            except (ValidationError, ValueError) as exc:
                return self._error_outcome(
                    case, started, CaseErrorCode.INVALID_RESPONSE, exc
                )

            return CaseOutcome.from_case(
                case,
                actual=decision,
                latency_ms=self._elapsed_ms(started),
            )

    def _error_outcome(
        self,
        case: TestCase,
        started: float,
        code: CaseErrorCode,
        error: Exception,
    ) -> CaseOutcome:
        return CaseOutcome.from_case(
            case,
            actual=None,
            latency_ms=self._elapsed_ms(started),
            error_code=code,
            error_detail=str(error),
        )

    @staticmethod
    def _elapsed_ms(started: float) -> float:
        return max(0.0, (perf_counter() - started) * 1000)
