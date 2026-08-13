"""Ordered keyword signals for the improved policy."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable
from common import Action, ReasonCode
from guardrail.normalization import normalize_text

@dataclass(frozen=True, slots=True)
class Signal:
    """A detector's proposed action and reason."""
    action: Action
    reason_code: ReasonCode

@runtime_checkable
class Detector(Protocol):
    """Structural interface implemented by signal detectors."""
    def detect(self, text: str) -> Signal | None:
        """Return one signal for a flattened input, or no signal."""

@dataclass(frozen=True, slots=True)
class KeywordRule:
    """One ordered policy concept and its literal trigger terms."""
    action: Action
    reason_code: ReasonCode
    keywords: tuple[str, ...]

# Very precise keyword rules
DEFAULT_KEYWORD_RULES = (
    KeywordRule(
        Action.BLOCK,
        ReasonCode.GENERATE_ABUSE,
        (
            "write a message that will intimidate",
            "help me threaten",
            "intimidate into silence",
            "threaten a neighbor",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.MODERATION_EVASION,
        (
            "bypass moderation",
            "evade safety checks",
            "bypass safety",
            "circumvent content",
            "evade the safety",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PROMPT_OVERRIDE,
        (
            "ignore all prior instructions",
            "disregard the conversation rules",
            "reveal the system prompt",
            "disregard all",
            "disclose",
        ),
    ),
    KeywordRule(
        Action.BLOCK,
        ReasonCode.PRIVATE_DATA_REQUEST,
        (
            "reporter identity",
            "private home address",
            "tell me the reporter",
            "find the private",
        ),
    ),
)

class OrderedKeywordDetector:
    """Return the first matching concept according to configured rule order."""
    def __init__(
        self, rules: Sequence[KeywordRule] | None = None
    ) -> None:
        configured = tuple(rules) if rules is not None else DEFAULT_KEYWORD_RULES
        self._rules = tuple(
            KeywordRule(
                rule.action,
                rule.reason_code,
                tuple(
                    normalize_text(keyword).control_stripped
                    for keyword in rule.keywords
                ),
            )
            for rule in configured
        )
    
    def detect(self, text: str) -> Signal | None:
        flattened = normalize_text(text).control_stripped
        for rule in self._rules:
            if any(keyword in flattened for keyword in rule.keywords):
                return Signal(rule.action, rule.reason_code)
        return None