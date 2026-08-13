"""Enumerated values used on the shared JSON wire."""

from enum import StrEnum


class Action(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_AS_DATA = "ALLOW_AS_DATA"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class ReasonCode(StrEnum):
    ORDINARY_SUPPORT = "ORDINARY_SUPPORT"
    POLICY_QUESTION = "POLICY_QUESTION"
    APPEAL_DECISION = "APPEAL_DECISION"
    ACCOUNT_SAFETY = "ACCOUNT_SAFETY"
    QUOTED_ABUSE = "QUOTED_ABUSE"
    QUOTED_SCAM = "QUOTED_SCAM"
    QUOTED_INJECTION = "QUOTED_INJECTION"
    GENERATE_ABUSE = "GENERATE_ABUSE"
    MODERATION_EVASION = "MODERATION_EVASION"
    PROMPT_OVERRIDE = "PROMPT_OVERRIDE"
    PRIVATE_DATA_REQUEST = "PRIVATE_DATA_REQUEST"
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    IMMINENT_SAFETY_RISK = "IMMINENT_SAFETY_RISK"


class Family(StrEnum):
    ORDINARY_SUPPORT = "ORDINARY_SUPPORT"
    POLICY_QUESTION = "POLICY_QUESTION"
    APPEAL_DECISION = "APPEAL_DECISION"
    ACCOUNT_SAFETY = "ACCOUNT_SAFETY"
    QUOTED_ABUSE = "QUOTED_ABUSE"
    QUOTED_SCAM = "QUOTED_SCAM"
    QUOTED_INJECTION = "QUOTED_INJECTION"
    GENERATE_ABUSE = "GENERATE_ABUSE"
    MODERATION_EVASION = "MODERATION_EVASION"
    PROMPT_OVERRIDE = "PROMPT_OVERRIDE"
    PRIVATE_DATA_REQUEST = "PRIVATE_DATA_REQUEST"
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    IMMINENT_SAFETY_RISK = "IMMINENT_SAFETY_RISK"


class Dimension(StrEnum):
    UTILITY = "utility"
    SECURITY = "security"


class EvidenceKind(StrEnum):
    QUOTED_MESSAGE = "quoted_message"
    PROFILE_TEXT = "profile_text"
    ATTACHMENT_TEXT = "attachment_text"


class Route(StrEnum):
    GENERAL = "general"
    REPORT = "report"
    APPEAL = "appeal"
    ACCOUNT_SAFETY = "account_safety"


class ActorRole(StrEnum):
    END_USER = "end_user"
    MODERATOR = "moderator"
    SUPPORT_AGENT = "support_agent"


class TargetRelation(StrEnum):
    SELF = "self"
    OTHER = "other"
    NONE = "none"


class Operation(StrEnum):
    NONE = "none"
    SUBMIT_REPORT = "submit_report"
    VIEW_OWN_CASE = "view_own_case"
    APPEAL_OWN_SANCTION = "appeal_own_sanction"
    VIEW_REPORTER_IDENTITY = "view_reporter_identity"
    CHANGE_SANCTION = "change_sanction"
