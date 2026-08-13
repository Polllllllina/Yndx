"""Deterministic signal fusion for the improved guardrail."""
from __future__ import annotations
from collections.abc import Iterable
from typing import Final
from common import Action, GuardrailDecision, ReasonCode, Route
from guardrail.detectors import Signal

POLICY_VERSION = "starter-v1"

ROUTE_ALLOW_REASONS = {
    Route.APPEAL: ReasonCode.APPEAL_DECISION,
    Route.ACCOUNT_SAFETY: ReasonCode.ACCOUNT_SAFETY,
    Route.REPORT: ReasonCode.POLICY_QUESTION,
    Route.GENERAL: ReasonCode.ORDINARY_SUPPORT,
}

ACTION_PRIORITY = {
    Action.ESCALATE: 4,
    Action.BLOCK: 3,
    Action.ALLOW_AS_DATA: 2,
    Action.ALLOW: 1,
}

class StarterPolicy:
    """Choose the highest priority signal, otherwise allow by route."""
    def __init__(self, policy_version: str = POLICY_VERSION) -> None:
        self.policy_version = policy_version
    
    def decide(
        self, signals: Iterable[Signal], route: Route
    ) -> GuardrailDecision:
        signal_list = list(signals)
        
        if not signal_list:
            return GuardrailDecision(
                action=Action.ALLOW,
                reason_code=ROUTE_ALLOW_REASONS[Route(route)],
                policy_version=self.policy_version,
            )
        
        if len(signal_list) == 1:
            best_signal = signal_list[0]
        else:
            best_signal = max(
                signal_list,
                key=lambda s: ACTION_PRIORITY.get(s.action, 0)
            )
            
            same_priority = [
                s for s in signal_list 
                if ACTION_PRIORITY.get(s.action, 0) == ACTION_PRIORITY.get(best_signal.action, 0)
            ]
            if len(same_priority) > 1:
                # Prefer more specific security reasons
                priority_order = [
                    ReasonCode.IMMINENT_SAFETY_RISK,
                    ReasonCode.UNAUTHORIZED_ACTION,
                    ReasonCode.PRIVATE_DATA_REQUEST,
                    ReasonCode.PROMPT_OVERRIDE,
                    ReasonCode.MODERATION_EVASION,
                    ReasonCode.GENERATE_ABUSE,
                ]
                for reason in priority_order:
                    for s in same_priority:
                        if s.reason_code == reason:
                            best_signal = s
                            break
                    else:
                        continue
                    break
        
        return GuardrailDecision(
            action=best_signal.action,
            reason_code=best_signal.reason_code,
            policy_version=self.policy_version,
        )

def fuse_signals(
    signals: Iterable[Signal],
    route: Route,
    *,
    policy_version: str = POLICY_VERSION,
) -> GuardrailDecision:
    """Functional entry point for deterministic policy fusion."""
    return StarterPolicy(policy_version).decide(signals, route)
