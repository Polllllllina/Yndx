"""Shared request and response contracts for guardrail evaluation."""

from typing import Literal

from pydantic import Field, field_validator

from common.base import ContractModel
from common.enums import (
    Action,
    ActorRole,
    EvidenceKind,
    Operation,
    ReasonCode,
    Route,
    TargetRelation,
)
from common.types import EvidenceText, MessageText, PolicyVersion


class Evidence(ContractModel):
    kind: EvidenceKind
    text: EvidenceText


class TrustedContext(ContractModel):
    route: Route
    actor_role: ActorRole
    target_relation: TargetRelation
    requested_operation: Operation
    allowed_operations: list[Operation] = Field(
        strict=True,
        max_length=6,
        json_schema_extra={"uniqueItems": True},
    )

    @field_validator("allowed_operations")
    @classmethod
    def reject_duplicate_operations(
        cls, value: list[Operation]
    ) -> list[Operation]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_operations must not contain duplicates")
        return value


class GuardrailRequest(ContractModel):
    message: MessageText
    evidence: list[Evidence] = Field(
        default_factory=list,
        strict=True,
        max_length=3,
    )
    context: TrustedContext


class GuardrailDecision(ContractModel):
    action: Action
    reason_code: ReasonCode
    policy_version: PolicyVersion


class GuardrailHealth(ContractModel):
    status: Literal["ok"]
    service: Literal["guardrail"]
    policy_version: PolicyVersion
