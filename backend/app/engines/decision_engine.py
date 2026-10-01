from typing import List, Dict, Any, Optional
from backend.app.config import settings
from backend.app.engines.adaptive_risk_engine import RiskCalculationResult

class DecisionResult:
    def __init__(
        self,
        decision: str,  # ALLOW, WARN, BLOCK, REVIEW
        risk_score: float,
        confidence: float,
        threat_type: str,
        reasons: List[str],
        can_bypass: bool = False
    ):
        self.decision = decision
        self.risk_score = risk_score
        self.confidence = confidence
        self.threat_type = threat_type
        self.reasons = reasons
        self.can_bypass = can_bypass

class DecisionEngine:
    @staticmethod
    def evaluate(risk_calc: RiskCalculationResult, security_mode: str = "NORMAL") -> DecisionResult:
        # Handle hard override rules directly
        if risk_calc.is_hard_override and risk_calc.hard_verdict:
            verdict = risk_calc.hard_verdict
            can_bypass = False
            return DecisionResult(
                decision=verdict,
                risk_score=risk_calc.risk_score,
                confidence=risk_calc.confidence,
                threat_type=risk_calc.threat_type,
                reasons=risk_calc.reasons,
                can_bypass=can_bypass
            )

        # Dynamic decision thresholding based on risk + confidence
        risk = risk_calc.risk_score
        confidence = risk_calc.confidence

        # Determine thresholds based on mode
        block_risk_thresh = settings.BLOCK_RISK_THRESHOLD
        warn_risk_thresh = settings.WARN_RISK_THRESHOLD

        if security_mode == "STRICT":
            block_risk_thresh -= 10
            warn_risk_thresh -= 10
        elif security_mode == "MAXIMUM":
            block_risk_thresh -= 20
            warn_risk_thresh -= 20

        # Decision Matrix
        if risk >= block_risk_thresh and confidence >= settings.CONFIDENCE_THRESHOLD_BLOCK:
            decision = "BLOCK"
            can_bypass = False
        elif risk >= warn_risk_thresh and confidence >= settings.CONFIDENCE_THRESHOLD_WARN:
            decision = "WARN"
            can_bypass = True  # User can proceed at own risk for uncertain warnings
        elif risk >= warn_risk_thresh and confidence < settings.CONFIDENCE_THRESHOLD_WARN:
            # High risk but low confidence -> Review / silent analysis
            decision = "REVIEW" if security_mode == "MAXIMUM" else "ALLOW"
            can_bypass = True
        else:
            decision = "ALLOW"
            can_bypass = True

        return DecisionResult(
            decision=decision,
            risk_score=risk,
            confidence=confidence,
            threat_type=risk_calc.threat_type if decision != "ALLOW" else "NONE",
            reasons=risk_calc.reasons,
            can_bypass=can_bypass
        )
