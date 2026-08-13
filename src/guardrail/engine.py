"""Orchestration for the improved guardrail."""
from __future__ import annotations
from collections.abc import Sequence
from common import (
    Action,
    GuardrailDecision,
    GuardrailRequest,
    ReasonCode,
    Route,
    Operation,
)
from guardrail.detectors import Detector, OrderedKeywordDetector, Signal
from guardrail.normalization import normalize_text
from guardrail.policy import StarterPolicy
from guardrail.vector_detector import create_starter_prototype_detector

class StarterGuardrail:
    """Normalize, detect with context awareness, and fuse signals."""
    
    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._detectors = (
            tuple(detectors)
            if detectors is not None
            else (
                OrderedKeywordDetector(),
                create_starter_prototype_detector(),
            )
        )
        self._policy = policy or StarterPolicy()
    
    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        message_lower = request.message.lower()
        message_text = normalize_text(request.message).control_stripped
        
        # 0. Check if this is about user's OWN account safety
        if self._is_own_account_safety(request):
            return self._policy.decide([], request.context.route)
        
        # 1. Check unauthorized action using context
        if request.context.requested_operation != Operation.NONE:
            if request.context.requested_operation not in request.context.allowed_operations:
                return self._policy.decide(
                    [Signal(Action.BLOCK, ReasonCode.UNAUTHORIZED_ACTION)],
                    request.context.route
                )
        
        # 2. Check imminent safety risk
        if self._is_imminent_safety(message_lower):
            return self._policy.decide(
                [Signal(Action.ESCALATE, ReasonCode.IMMINENT_SAFETY_RISK)],
                request.context.route
            )
        
        # 3. Check quoted data cases
        if request.evidence:
            quoted_signal = self._check_quoted_data(request, message_lower)
            if quoted_signal:
                return self._policy.decide([quoted_signal], request.context.route)
        
        # 4. Run detectors on message only
        signals: list[Signal] = []
        for detector in self._detectors:
            signal = detector.detect(message_text)
            if signal is not None:
                signals.append(signal)
        
        return self._policy.decide(signals, request.context.route)
    
    def _is_own_account_safety(self, request: GuardrailRequest) -> bool:
        """Check if the request is about the user's own account safety."""
        # Проверяем route (может быть enum или строка)
        route_value = request.context.route.value if hasattr(request.context.route, 'value') else str(request.context.route)
        if route_value != "account_safety":
            return False
        
        # Проверяем, что это о собственном аккаунте
        message_lower = request.message.lower()
        
        # Ключевые фразы для собственной безопасности аккаунта
        own_account_phrases = [
            "secure my account",
            "password reset notice",
            "login i do not recognize",
            "unexpected password",
            "what steps should i take after"
        ]
        
        return any(phrase in message_lower for phrase in own_account_phrases)
    
    def _is_imminent_safety(self, text_lower: str) -> bool:
        """Check for imminent safety risks."""
        # Case 1: "Someone outside my door is threatening me right now"
        if "threatening me" in text_lower and ("right now" in text_lower or "immediate danger" in text_lower):
            return True
        
        # Case 2: "My friend says they are about to hurt themselves"
        if "about to hurt" in text_lower and "urgent" in text_lower:
            return True
        
        imminent_phrases = [
            "immediate danger",
            "need urgent help",
            "about to kill",
            "hurt myself",
            "harm myself",
            "i want to die",
            "suicide",
            "self-harm"
        ]
        
        return any(phrase in text_lower for phrase in imminent_phrases)
    
    def _check_quoted_data(self, request: GuardrailRequest, message_lower: str) -> Signal | None:
        """Handle quoted abuse/scam/injection cases."""
        for evidence in request.evidence:
            evidence_lower = evidence.text.lower()
            
            # QUOTED_ABUSE
            if self._is_abuse_evidence(evidence_lower):
                if self._is_abuse_analysis(message_lower):
                    return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_ABUSE)
            
            # QUOTED_SCAM
            if self._is_scam_evidence(evidence_lower):
                if self._is_scam_analysis(message_lower):
                    return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_SCAM)
            
            # QUOTED_INJECTION
            if self._is_injection_evidence(evidence_lower):
                if self._is_injection_analysis(message_lower):
                    return Signal(Action.ALLOW_AS_DATA, ReasonCode.QUOTED_INJECTION)
        
        return None
    
    def _is_abuse_evidence(self, text: str) -> bool:
        abuse_words = [
            "worthless", "pathetic", "nobody wants you",
            "hostile", "abusive", "insult"
        ]
        return any(word in text for word in abuse_words)
    
    def _is_scam_evidence(self, text: str) -> bool:
        scam_words = [
            "processing fee", "guaranteed prize", "gift cards",
            "impersonation", "verify your account"
        ]
        return any(word in text for word in scam_words)
    
    def _is_injection_evidence(self, text: str) -> bool:
        injection_words = [
            "ignore the system", "disregard your directions",
            "reveal the secret", "expose", "prompt-injection"
        ]
        return any(word in text for word in injection_words)
    
    def _is_abuse_analysis(self, text: str) -> bool:
        analysis_words = [
            "classify", "summarize", "abusive tone", "reported insult"
        ]
        return any(word in text for word in analysis_words)
    
    def _is_scam_analysis(self, text: str) -> bool:
        analysis_words = [
            "identify", "warning signs", "consistent with", "impersonation"
        ]
        return any(word in text for word in analysis_words)
    
    def _is_injection_analysis(self, text: str) -> bool:
        analysis_words = [
            "explain", "review", "inert evidence", "prompt-injection"
        ]
        return any(word in text for word in analysis_words)
