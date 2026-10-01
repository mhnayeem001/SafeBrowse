from typing import List, Optional, Dict, Any
from backend.app.schemas import FormMetadata, PageScanRequest

PHISHING_TITLE_PATTERNS = [
    "verify your account", "account suspended", "security alert", "confirm identity",
    "unusual activity", "login to continue", "sign in to your account", "verify identity",
    "wallet connect", "restore access", "billing error", "card confirmation",
    "identity verification", "2fa verification", "unlock account", "security center"
]

class PhishingAnalysisResult:
    def __init__(
        self,
        is_phishing: bool,
        risk_score: float,
        confidence: float,
        threat_type: str,
        reasons: List[str],
        recommended_action: str, # ALLOW, WARN, BLOCK
    ):
        self.is_phishing = is_phishing
        self.risk_score = risk_score
        self.confidence = confidence
        self.threat_type = threat_type
        self.reasons = reasons
        self.recommended_action = recommended_action

class PhishingEngine:
    @staticmethod
    def analyze_page_context(
        page_data: PageScanRequest,
        domain_risk: float,
        is_brand_spoof: bool,
        matched_brand: Optional[str] = None
    ) -> PhishingAnalysisResult:
        reasons = []
        score = domain_risk * 0.4  # Start with fraction of domain baseline risk
        confidence = 60.0

        has_password_form = False
        has_credit_card_form = False
        has_otp_form = False
        has_cross_origin_form = False

        if page_data.forms:
            for form in page_data.forms:
                if form.has_password:
                    has_password_form = True
                if form.has_credit_card:
                    has_credit_card_form = True
                if form.has_otp_or_token:
                    has_otp_form = True
                if form.is_cross_origin:
                    has_cross_origin_form = True

        # Signal 1: Credential Form on Untrusted / Spoofed Domain
        if is_brand_spoof and (has_password_form or has_otp_form or has_credit_card_form):
            score = 95.0
            confidence = 98.0
            reasons.append(f"Credential harvesting form detected on spoofed brand domain ({matched_brand or 'known brand'})")
        elif domain_risk >= 50.0 and (has_password_form or has_credit_card_form):
            score += 45.0
            confidence = max(confidence, 85.0)
            reasons.append("Sensitive login/credit card form on untrusted or suspicious domain")
        elif has_password_form and domain_risk > 30.0:
            score += 25.0
            reasons.append("Password input field detected on domain with elevated risk")

        # Signal 2: Cross-Origin Credential Form Submission
        if has_cross_origin_form and has_password_form:
            score += 35.0
            confidence = max(confidence, 88.0)
            reasons.append("Form submits credentials to an external cross-origin domain")

        # Signal 3: Urgency / Phishing Lure in Page Title
        if page_data.title:
            lower_title = page_data.title.lower()
            for pattern in PHISHING_TITLE_PATTERNS:
                if pattern in lower_title:
                    score += 20.0
                    confidence = max(confidence, 75.0)
                    reasons.append(f"Page title contains social-engineering lure phrasing: '{pattern}'")
                    break

        # Signal 4: Notification Permission Abuse
        if page_data.notification_prompt_count >= 2 or page_data.has_suspicious_prompts:
            score += 25.0
            reasons.append(f"Aggressive or deceptive notification permission abuse detected ({page_data.notification_prompt_count} prompts)")

        # Signal 5: Hidden or suspicious iframes
        if page_data.iframes and len(page_data.iframes) >= 2:
            score += 15.0
            reasons.append(f"Multiple embedded iframes detected on page ({len(page_data.iframes)})")

        final_score = max(0.0, min(score, 100.0))
        
        # Decide verdict
        if final_score >= 80.0 and confidence >= 70.0:
            return PhishingAnalysisResult(
                is_phishing=True,
                risk_score=final_score,
                confidence=confidence,
                threat_type="PHISHING",
                reasons=reasons,
                recommended_action="BLOCK"
            )
        elif final_score >= 45.0:
            return PhishingAnalysisResult(
                is_phishing=False,
                risk_score=final_score,
                confidence=confidence,
                threat_type="SUSPICIOUS_CONTENT" if reasons else "NONE",
                reasons=reasons,
                recommended_action="WARN"
            )
        else:
            return PhishingAnalysisResult(
                is_phishing=False,
                risk_score=final_score,
                confidence=confidence,
                threat_type="NONE",
                reasons=reasons,
                recommended_action="ALLOW"
            )
