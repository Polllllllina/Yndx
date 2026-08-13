"""Behavioral tests for the shared Trust & Safety wire contracts."""

from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError


def contracts() -> SimpleNamespace:
    """Load the intended public contract modules inside each test.

    Keeping imports inside the test body lets the initial scaffold test fail as a
    normal test failure while the greenfield package is still absent.
    """

    enums = import_module("common.enums")
    guardrail = import_module("common.guardrail")
    suite = import_module("common.suite")
    return SimpleNamespace(
        **{
            name: getattr(enums, name)
            for name in (
                "Action",
                "ActorRole",
                "Dimension",
                "EvidenceKind",
                "Family",
                "Operation",
                "ReasonCode",
                "Route",
                "TargetRelation",
            )
        },
        **{
            name: getattr(guardrail, name)
            for name in (
                "Evidence",
                "GuardrailDecision",
                "GuardrailHealth",
                "GuardrailRequest",
                "TrustedContext",
            )
        },
        **{
            name: getattr(suite, name)
            for name in ("ExpectedDecision", "TestCase", "TestSuite")
        },
    )


def context_data() -> dict[str, Any]:
    return {
        "route": "general",
        "actor_role": "end_user",
        "target_relation": "self",
        "requested_operation": "none",
        "allowed_operations": ["none"],
    }


def request_data() -> dict[str, Any]:
    return {"message": "Please help with my account.", "context": context_data()}


def case_data(
    *,
    case_id: str = "utility-1",
    family: str = "ORDINARY_SUPPORT",
    dimension: str = "utility",
    cluster_id: str = "support-cluster",
    is_anchor: bool = True,
    action: str = "ALLOW",
    reason_code: str | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "family": family,
        "dimension": dimension,
        "cluster_id": cluster_id,
        "is_anchor": is_anchor,
        "input": request_data(),
        "expected": {
            "action": action,
            "reason_code": reason_code or family,
        },
    }


def suite_data() -> dict[str, Any]:
    return {
        "suite_id": "smoke-suite",
        "policy_version": "2026-07-15",
        "cases": [
            case_data(),
            case_data(
                case_id="security-1",
                family="GENERATE_ABUSE",
                dimension="security",
                cluster_id="abuse-cluster",
                action="BLOCK",
            ),
        ],
    }


def error_types(exc_info: pytest.ExceptionInfo[ValidationError]) -> set[str]:
    return {error["type"] for error in exc_info.value.errors()}


def test_valid_suite_json_round_trip() -> None:
    c = contracts()
    suite = c.TestSuite.model_validate(suite_data())

    restored = c.TestSuite.model_validate_json(suite.model_dump_json())

    assert restored == suite
    assert restored.cases[0].input.evidence == []
    assert restored.cases[1].expected.action is c.Action.BLOCK


def test_enums_have_exact_wire_values() -> None:
    c = contracts()
    expected = {
        c.Action: ["ALLOW", "ALLOW_AS_DATA", "BLOCK", "ESCALATE"],
        c.ReasonCode: [
            "ORDINARY_SUPPORT",
            "POLICY_QUESTION",
            "APPEAL_DECISION",
            "ACCOUNT_SAFETY",
            "QUOTED_ABUSE",
            "QUOTED_SCAM",
            "QUOTED_INJECTION",
            "GENERATE_ABUSE",
            "MODERATION_EVASION",
            "PROMPT_OVERRIDE",
            "PRIVATE_DATA_REQUEST",
            "UNAUTHORIZED_ACTION",
            "IMMINENT_SAFETY_RISK",
        ],
        c.Family: [
            "ORDINARY_SUPPORT",
            "POLICY_QUESTION",
            "APPEAL_DECISION",
            "ACCOUNT_SAFETY",
            "QUOTED_ABUSE",
            "QUOTED_SCAM",
            "QUOTED_INJECTION",
            "GENERATE_ABUSE",
            "MODERATION_EVASION",
            "PROMPT_OVERRIDE",
            "PRIVATE_DATA_REQUEST",
            "UNAUTHORIZED_ACTION",
            "IMMINENT_SAFETY_RISK",
        ],
        c.Dimension: ["utility", "security"],
        c.EvidenceKind: [
            "quoted_message",
            "profile_text",
            "attachment_text",
        ],
        c.Route: ["general", "report", "appeal", "account_safety"],
        c.ActorRole: ["end_user", "moderator", "support_agent"],
        c.TargetRelation: ["self", "other", "none"],
        c.Operation: [
            "none",
            "submit_report",
            "view_own_case",
            "appeal_own_sanction",
            "view_reporter_identity",
            "change_sanction",
        ],
    }

    for enum_type, wire_values in expected.items():
        assert [member.value for member in enum_type] == wire_values


@pytest.mark.parametrize(
    ("model_name", "payload"),
    [
        ("Evidence", {"kind": "quoted_message", "text": "quoted"}),
        ("TrustedContext", context_data()),
        ("GuardrailRequest", request_data()),
        (
            "GuardrailDecision",
            {
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "v1",
            },
        ),
        (
            "ExpectedDecision",
            {"action": "ALLOW", "reason_code": "ORDINARY_SUPPORT"},
        ),
        ("TestCase", case_data()),
        ("TestSuite", suite_data()),
    ],
)
def test_every_model_forbids_extra_fields(
    model_name: str, payload: dict[str, Any]
) -> None:
    c = contracts()
    invalid = deepcopy(payload)
    invalid["unexpected"] = True

    with pytest.raises(ValidationError) as exc_info:
        getattr(c, model_name).model_validate(invalid)

    assert "extra_forbidden" in error_types(exc_info)


def test_unknown_enum_value_fails_validation() -> None:
    c = contracts()
    invalid = {
        "action": "REVIEW",
        "reason_code": "ORDINARY_SUPPORT",
        "policy_version": "v1",
    }

    with pytest.raises(ValidationError) as exc_info:
        c.GuardrailDecision.model_validate(invalid)

    assert "enum" in error_types(exc_info)


def test_valid_json_enum_strings_remain_accepted() -> None:
    c = contracts()

    decision = c.GuardrailDecision.model_validate_json(
        '{"action":"ALLOW","reason_code":"ORDINARY_SUPPORT",'
        '"policy_version":"v1"}'
    )

    assert decision.action is c.Action.ALLOW
    assert decision.reason_code is c.ReasonCode.ORDINARY_SUPPORT


@pytest.mark.parametrize(
    ("model_name", "payload", "field"),
    [
        ("Evidence", {"kind": "quoted_message", "text": "quoted"}, "text"),
        ("GuardrailRequest", request_data(), "message"),
        (
            "GuardrailDecision",
            {
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "v1",
            },
            "policy_version",
        ),
        ("TestCase", case_data(), "case_id"),
        ("TestCase", case_data(), "cluster_id"),
        ("TestSuite", suite_data(), "suite_id"),
    ],
)
def test_wire_string_fields_reject_bytes(
    model_name: str, payload: dict[str, Any], field: str
) -> None:
    c = contracts()
    invalid = deepcopy(payload)
    invalid[field] = b"not-a-json-string"

    with pytest.raises(ValidationError) as exc_info:
        getattr(c, model_name).model_validate(invalid)

    assert "string_type" in error_types(exc_info)


def test_is_anchor_rejects_string_boolean_coercion() -> None:
    c = contracts()
    invalid = case_data()
    invalid["is_anchor"] = "no"

    with pytest.raises(ValidationError) as exc_info:
        c.TestCase.model_validate(invalid)

    assert "bool_type" in error_types(exc_info)


@pytest.mark.parametrize(
    ("model_name", "payload", "field"),
    [
        ("TrustedContext", context_data(), "allowed_operations"),
        ("GuardrailRequest", request_data(), "evidence"),
        ("TestSuite", suite_data(), "cases"),
    ],
)
def test_wire_array_fields_reject_tuples(
    model_name: str, payload: dict[str, Any], field: str
) -> None:
    c = contracts()
    invalid = deepcopy(payload)
    invalid[field] = tuple(invalid.get(field, []))

    with pytest.raises(ValidationError) as exc_info:
        getattr(c, model_name).model_validate(invalid)

    assert "list_type" in error_types(exc_info)


@pytest.mark.parametrize(
    ("model_name", "payload", "field"),
    [
        ("Evidence", {"kind": "quoted_message", "text": "quoted"}, "text"),
        ("GuardrailRequest", request_data(), "message"),
        (
            "GuardrailDecision",
            {
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "v1",
            },
            "policy_version",
        ),
        ("TestCase", case_data(), "case_id"),
        ("TestCase", case_data(), "cluster_id"),
        ("TestSuite", suite_data(), "suite_id"),
        ("TestSuite", suite_data(), "policy_version"),
    ],
)
def test_empty_required_strings_fail_validation(
    model_name: str, payload: dict[str, Any], field: str
) -> None:
    c = contracts()
    invalid = deepcopy(payload)
    invalid[field] = ""

    with pytest.raises(ValidationError) as exc_info:
        getattr(c, model_name).model_validate(invalid)

    assert "string_too_short" in error_types(exc_info)


@pytest.mark.parametrize(
    ("model_name", "payload", "field", "size"),
    [
        ("Evidence", {"kind": "quoted_message", "text": "quoted"}, "text", 8193),
        ("GuardrailRequest", request_data(), "message", 4097),
        (
            "GuardrailDecision",
            {
                "action": "ALLOW",
                "reason_code": "ORDINARY_SUPPORT",
                "policy_version": "v1",
            },
            "policy_version",
            65,
        ),
        ("TestSuite", suite_data(), "policy_version", 65),
        ("TestCase", case_data(), "case_id", 129),
        ("TestCase", case_data(), "cluster_id", 129),
        ("TestSuite", suite_data(), "suite_id", 129),
    ],
)
def test_oversize_strings_fail_validation(
    model_name: str, payload: dict[str, Any], field: str, size: int
) -> None:
    c = contracts()
    invalid = deepcopy(payload)
    invalid[field] = "x" * size

    with pytest.raises(ValidationError) as exc_info:
        getattr(c, model_name).model_validate(invalid)

    assert "string_too_long" in error_types(exc_info)


def test_four_evidence_items_fail_validation() -> None:
    c = contracts()
    invalid = request_data()
    invalid["evidence"] = [
        {"kind": "quoted_message", "text": f"quote {index}"}
        for index in range(4)
    ]

    with pytest.raises(ValidationError) as exc_info:
        c.GuardrailRequest.model_validate(invalid)

    assert "too_long" in error_types(exc_info)


def test_allowed_operations_reject_duplicates() -> None:
    c = contracts()
    invalid = context_data()
    invalid["allowed_operations"] = ["none", "none"]

    with pytest.raises(ValidationError) as exc_info:
        c.TrustedContext.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


def test_allowed_operations_schema_declares_unique_items() -> None:
    c = contracts()
    schema = c.TrustedContext.model_json_schema()

    assert schema["properties"]["allowed_operations"]["uniqueItems"] is True


def test_more_than_six_allowed_operations_fail_validation() -> None:
    c = contracts()
    invalid = context_data()
    invalid["allowed_operations"] = ["none"] * 7

    with pytest.raises(ValidationError) as exc_info:
        c.TrustedContext.model_validate(invalid)

    assert "too_long" in error_types(exc_info)


def test_suite_requires_between_one_and_five_hundred_cases() -> None:
    c = contracts()
    empty = suite_data()
    empty["cases"] = []

    with pytest.raises(ValidationError) as empty_exc:
        c.TestSuite.model_validate(empty)

    assert "too_short" in error_types(empty_exc)

    oversized = suite_data()
    oversized["cases"] = [
        case_data(
            case_id=f"utility-{index}",
            cluster_id=f"cluster-{index}",
        )
        for index in range(501)
    ]

    with pytest.raises(ValidationError) as oversized_exc:
        c.TestSuite.model_validate(oversized)

    assert "too_long" in error_types(oversized_exc)


def test_suite_rejects_duplicate_case_ids() -> None:
    c = contracts()
    invalid = suite_data()
    invalid["cases"][1]["case_id"] = invalid["cases"][0]["case_id"]

    with pytest.raises(ValidationError) as exc_info:
        c.TestSuite.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


def test_suite_requires_a_security_dimension() -> None:
    c = contracts()
    invalid = suite_data()
    invalid["cases"] = [case_data()]

    with pytest.raises(ValidationError) as exc_info:
        c.TestSuite.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


@pytest.mark.parametrize("anchor_count", [0, 2])
def test_each_cluster_requires_exactly_one_anchor(anchor_count: int) -> None:
    c = contracts()
    invalid = suite_data()
    invalid["cases"] = [
        case_data(
            case_id="utility-1",
            is_anchor=anchor_count >= 1,
        ),
        case_data(
            case_id="utility-2",
            is_anchor=anchor_count == 2,
        ),
        case_data(
            case_id="security-1",
            family="GENERATE_ABUSE",
            dimension="security",
            cluster_id="abuse-cluster",
            action="BLOCK",
        ),
    ]

    with pytest.raises(ValidationError) as exc_info:
        c.TestSuite.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


def test_case_rejects_mismatched_family_and_reason_code() -> None:
    c = contracts()
    invalid = case_data(reason_code="POLICY_QUESTION")

    with pytest.raises(ValidationError) as exc_info:
        c.TestCase.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


@pytest.mark.parametrize(
    ("family", "dimension", "action"),
    [
        ("ORDINARY_SUPPORT", "utility", "ALLOW"),
        ("POLICY_QUESTION", "utility", "ALLOW"),
        ("APPEAL_DECISION", "utility", "ALLOW"),
        ("ACCOUNT_SAFETY", "utility", "ALLOW"),
        ("QUOTED_ABUSE", "utility", "ALLOW_AS_DATA"),
        ("QUOTED_SCAM", "utility", "ALLOW_AS_DATA"),
        ("QUOTED_INJECTION", "utility", "ALLOW_AS_DATA"),
        ("GENERATE_ABUSE", "security", "BLOCK"),
        ("MODERATION_EVASION", "security", "BLOCK"),
        ("PROMPT_OVERRIDE", "security", "BLOCK"),
        ("PRIVATE_DATA_REQUEST", "security", "BLOCK"),
        ("UNAUTHORIZED_ACTION", "security", "BLOCK"),
        ("IMMINENT_SAFETY_RISK", "security", "ESCALATE"),
    ],
)
def test_each_family_accepts_its_exact_dimension_and_action(
    family: str, dimension: str, action: str
) -> None:
    c = contracts()

    parsed = c.TestCase.model_validate(
        case_data(family=family, dimension=dimension, action=action)
    )

    assert parsed.family.value == family
    assert parsed.expected.action.value == action


@pytest.mark.parametrize(
    ("family", "dimension", "wrong_action"),
    [
        ("ORDINARY_SUPPORT", "utility", "ALLOW_AS_DATA"),
        ("QUOTED_INJECTION", "utility", "ALLOW"),
        ("GENERATE_ABUSE", "security", "ESCALATE"),
        ("IMMINENT_SAFETY_RISK", "security", "BLOCK"),
    ],
)
def test_case_rejects_action_that_does_not_match_family(
    family: str, dimension: str, wrong_action: str
) -> None:
    c = contracts()
    invalid = case_data(
        family=family,
        dimension=dimension,
        action=wrong_action,
    )

    with pytest.raises(ValidationError) as exc_info:
        c.TestCase.model_validate(invalid)

    assert "value_error" in error_types(exc_info)


def test_case_rejects_family_in_the_wrong_dimension() -> None:
    c = contracts()
    invalid = case_data(dimension="security")

    with pytest.raises(ValidationError) as exc_info:
        c.TestCase.model_validate(invalid)

    assert "value_error" in error_types(exc_info)
