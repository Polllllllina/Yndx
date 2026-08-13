"""Shared conformance-suite contracts and cross-record invariants."""

from collections import Counter
from typing import Self

from pydantic import Field, StrictBool, model_validator

from common.base import ContractModel
from common.enums import Action, Dimension, Family, ReasonCode
from common.guardrail import GuardrailRequest
from common.taxonomy import FAMILY_RULES
from common.types import NonEmptyString, PolicyVersion


class ExpectedDecision(ContractModel):
    action: Action
    reason_code: ReasonCode


class TestCase(ContractModel):
    case_id: NonEmptyString
    family: Family
    dimension: Dimension
    cluster_id: NonEmptyString
    is_anchor: StrictBool
    input: GuardrailRequest
    expected: ExpectedDecision

    @model_validator(mode="after")
    def validate_taxonomy(self) -> Self:
        if self.family.value != self.expected.reason_code.value:
            raise ValueError("family must equal expected.reason_code")

        expected_dimension, expected_action = FAMILY_RULES[self.family]
        if self.dimension is not expected_dimension:
            raise ValueError(
                f"family {self.family.value} belongs to dimension "
                f"{expected_dimension.value}"
            )
        if self.expected.action is not expected_action:
            raise ValueError(
                f"family {self.family.value} requires action {expected_action.value}"
            )
        return self


class TestSuite(ContractModel):
    suite_id: NonEmptyString
    policy_version: PolicyVersion
    cases: list[TestCase] = Field(
        strict=True,
        min_length=1,
        max_length=500,
    )

    @model_validator(mode="after")
    def validate_suite_invariants(self) -> Self:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("case IDs must be unique")

        dimensions = {case.dimension for case in self.cases}
        missing_dimensions = {Dimension.UTILITY, Dimension.SECURITY} - dimensions
        if missing_dimensions:
            missing = ", ".join(sorted(item.value for item in missing_dimensions))
            raise ValueError(f"suite is missing required dimension(s): {missing}")

        anchor_counts = Counter(
            case.cluster_id for case in self.cases if case.is_anchor
        )
        cluster_ids = {case.cluster_id for case in self.cases}
        invalid_clusters = sorted(
            cluster_id
            for cluster_id in cluster_ids
            if anchor_counts[cluster_id] != 1
        )
        if invalid_clusters:
            joined = ", ".join(invalid_clusters)
            raise ValueError(f"each cluster must have exactly one anchor: {joined}")

        return self
