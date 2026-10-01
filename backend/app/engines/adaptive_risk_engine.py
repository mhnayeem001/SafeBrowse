from typing import List, Optional, Tuple, Dict, Any
from backend.app.engines.url_normalizer import NormalizedURLResult
from backend.app.engines.domain_intel import DomainAnalysisResult
from backend.app.engines.typosquatting import TyposquattingResult
from backend.app.engines.phishing_engine import PhishingAnalysisResult
from backend.app.services.threat_intel import ThreatIntelResult

class RiskCalculationResult:
    def __init__(
        self,
        risk_score: float,
        confidence: float,
        threat_type: str,
        reasons: List[str],
        is_hard_override: bool = False,
        hard_verdict: Optional[str] = None
    ):
        self.risk_score = risk_score
        self.confidence = confidence
        self.threat_type = threat_type
        self.reasons = reasons
        self.is_hard_override = is_hard_override
        self.hard_verdict = hard_verdict

class AdaptiveRiskEngine:
    @staticmethod
    def calculate_risk(
        url_res: NormalizedURLResult,
        domain_res: DomainAnalysisResult,
        typo_res: TyposquattingResult,
        phish_res: Optional[PhishingAnalysisResult] = None,
        intel_res: Optional[ThreatIntelResult] = None,
        is_whitelisted: bool = False,
        is_blacklisted: bool = False,
        security_mode: str = "NORMAL"
    ) -> RiskCalculationResult:
        reasons: List[str] = []

        # 1. HARD RULE: Whitelist Check
        if is_whitelisted:
            return RiskCalculationResult(
                risk_score=0.0,
                confidence=99.0,
                threat_type="NONE",
                reasons=["Domain or URL is in verified whitelist"],
                is_hard_override=True,
                hard_verdict="ALLOW"
            )

        # 2. HARD RULE: Blacklist Check
        if is_blacklisted:
            return RiskCalculationResult(
                risk_score=100.0,
                confidence=100.0,
                threat_type="BLACKLISTED",
                reasons=["Domain or URL is listed on security blacklist"],
                is_hard_override=True,
                hard_verdict="BLOCK"
            )

        # 3. HARD RULE: Confirmed Threat Intel Hit
        if intel_res and intel_res.is_malicious:
            return RiskCalculationResult(
                risk_score=98.0,
                confidence=intel_res.confidence or 95.0,
                threat_type=intel_res.threat_type or "MALICIOUS",
                reasons=[intel_res.details or "Flagged by threat intelligence feed"],
                is_hard_override=True,
                hard_verdict="BLOCK"
            )

        # 4. Aggregated Signals Calculation
        cumulative_score = 0.0
        confidence_points = 50.0
        primary_threat = "NONE"

        # Signal A: URL structure modifier
        if url_res.risk_modifier > 0:
            cumulative_score += url_res.risk_modifier * 0.4
            reasons.extend(url_res.suspicious_signals)

        # Signal B: Domain structural analysis
        if domain_res.risk_score > 0:
            cumulative_score += domain_res.risk_score * 0.5
            reasons.extend(domain_res.reasons)

        # Signal C: Typosquatting / Brand Spoofing
        if typo_res.is_spoofed:
            cumulative_score += typo_res.similarity_score * 0.8
            confidence_points = max(confidence_points, typo_res.confidence)
            primary_threat = "BRAND_SPOOF"
            reasons.extend(typo_res.reasons)

        # Signal D: Phishing page analysis (if content scan provided)
        if phish_res:
            if phish_res.is_phishing:
                cumulative_score += phish_res.risk_score * 0.9
                confidence_points = max(confidence_points, phish_res.confidence)
                primary_threat = "PHISHING"
                reasons.extend(phish_res.reasons)
            elif phish_res.risk_score > 20.0:
                cumulative_score += phish_res.risk_score * 0.5
                reasons.extend(phish_res.reasons)

        # Adjust for security mode sensitivity
        if security_mode == "STRICT":
            cumulative_score *= 1.2
            confidence_points = min(100.0, confidence_points + 10.0)
        elif security_mode == "MAXIMUM":
            cumulative_score *= 1.4
            confidence_points = min(100.0, confidence_points + 20.0)

        # Deduplicate reasons while preserving order
        unique_reasons = []
        seen = set()
        for r in reasons:
            if r not in seen:
                seen.add(r)
                unique_reasons.append(r)

        final_risk = max(0.0, min(cumulative_score, 100.0))
        final_confidence = max(10.0, min(confidence_points, 100.0))

        if final_risk < 20.0 and not unique_reasons:
            unique_reasons.append("No suspicious threat indicators found")

        return RiskCalculationResult(
            risk_score=round(final_risk, 1),
            confidence=round(final_confidence, 1),
            threat_type=primary_threat,
            reasons=unique_reasons,
            is_hard_override=False,
            hard_verdict=None
        )
