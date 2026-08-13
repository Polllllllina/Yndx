"""Strict models emitted by the red-team tester."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from common.base import ContractModel
from common.enums import Dimension, Family
from common.guardrail import GuardrailDecision
from common.suite import ExpectedDecision, TestCase
from common.types import NonEmptyString, PolicyVersion


class CaseErrorCode(StrEnum):
    TIMEOUT = "TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"


class RunStatus(StrEnum):
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"


class CaseOutcome(ContractModel):
    case_id: NonEmptyString
    expected: ExpectedDecision
    actual: GuardrailDecision | None = None
    action_correct: StrictBool
    reason_correct: StrictBool
    latency_ms: float = Field(ge=0)
    error_code: CaseErrorCode | None = None
    error_detail: StrictStr | None = None

    @classmethod
    def from_case(
        cls,
        case: TestCase,
        *,
        actual: GuardrailDecision | None,
        latency_ms: float,
        error_code: CaseErrorCode | str | None = None,
        error_detail: str | None = None,
    ) -> Self:
        action_correct = (
            actual is not None and actual.action is case.expected.action
        )
        reason_correct = (
            action_correct
            and actual is not None
            and actual.reason_code is case.expected.reason_code
        )
        return cls(
            case_id=case.case_id,
            expected=case.expected,
            actual=actual,
            action_correct=action_correct,
            reason_correct=reason_correct,
            latency_ms=latency_ms,
            error_code=error_code,
            error_detail=error_detail,
        )

    @model_validator(mode="after")
    def validate_outcome_consistency(self) -> Self:
        expected_action_correct = (
            self.actual is not None
            and self.actual.action is self.expected.action
        )
        expected_reason_correct = (
            expected_action_correct
            and self.actual is not None
            and self.actual.reason_code is self.expected.reason_code
        )
        if self.action_correct is not expected_action_correct:
            raise ValueError("action_correct must match expected and actual actions")
        if self.reason_correct is not expected_reason_correct:
            raise ValueError(
                "reason_correct requires an exactly correct action/reason pair"
            )
        if self.actual is not None and self.error_code is not None:
            raise ValueError("a case outcome cannot contain both a decision and an error")
        if self.actual is None and self.error_code is None:
            raise ValueError("a case outcome requires either a decision or an error")
        if self.error_detail is not None and self.error_code is None:
            raise ValueError("error_detail requires error_code")
        return self


class FamilyMetric(ContractModel):
    family: Family
    dimension: Dimension
    correct_cases: int = Field(ge=0)
    total_cases: int = Field(gt=0)
    action_accuracy: float = Field(ge=0, le=1)


class Metrics(ContractModel):
    security: float = Field(ge=0, le=1)
    utility: float = Field(ge=0, le=1)
    balance: float = Field(ge=0, le=1)
    cluster_robustness: float = Field(ge=0, le=1)
    reason_accuracy: float = Field(ge=0, le=1)
    score: float = Field(ge=0, le=100)
    family_metrics: list[FamilyMetric] = Field(strict=True)

    @property
    def S(self) -> float:  # noqa: N802 - mirrors the published formula
        return self.security

    @property
    def U(self) -> float:  # noqa: N802 - mirrors the published formula
        return self.utility

    @property
    def B(self) -> float:  # noqa: N802 - mirrors the published formula
        return self.balance

    @property
    def M(self) -> float:  # noqa: N802 - mirrors the published formula
        return self.cluster_robustness

    @property
    def R(self) -> float:  # noqa: N802 - mirrors the published formula
        return self.reason_accuracy


class EvaluationReport(ContractModel):
    suite_id: NonEmptyString
    policy_version: PolicyVersion
    status: RunStatus
    metrics: Metrics
    cases: list[CaseOutcome] = Field(strict=True)
