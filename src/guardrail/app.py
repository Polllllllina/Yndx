"""FastAPI entry point for the starter guardrail service."""

from __future__ import annotations

from fastapi import FastAPI

from common import GuardrailDecision, GuardrailHealth, GuardrailRequest
from guardrail.engine import StarterGuardrail
from guardrail.policy import POLICY_VERSION


def create_app(guardrail: StarterGuardrail | None = None) -> FastAPI:
    service = guardrail or StarterGuardrail()
    application = FastAPI(title="Trust & Safety Starter Guardrail")

    @application.get("/healthz", response_model=GuardrailHealth)
    def healthz() -> GuardrailHealth:
        return GuardrailHealth(
            status="ok",
            service="guardrail",
            policy_version=POLICY_VERSION,
        )

    @application.post("/v1/check", response_model=GuardrailDecision)
    def check(request: GuardrailRequest) -> GuardrailDecision:
        return service.check(request)

    return application


app = create_app()
