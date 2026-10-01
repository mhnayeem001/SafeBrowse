import math
import re
import socket
from typing import Dict, Any, List, Optional
import tldextract

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "fit", "surf", "buzz", 
    "work", "click", "rest", "icu", "cam", "kim", "stream", "live", "club",
    "vip", "monster", "casa", "country", "review", "download"
}

TRUSTED_TLDS = {
    "gov", "edu", "mil", "gov.uk", "edu.au", "ac.uk"
}

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "security", "update",
    "banking", "wallet", "support", "portal", "confirm", "auth", "authenticate",
    "recover", "recovery", "password", "secure", "billing", "invoice", "payment",
    "checkpoint", "secure-login", "webscr", "myaccount", "id-verify"
]

class DomainAnalysisResult:
    def __init__(
        self,
        domain_name: str,
        subdomain: str,
        root_domain: str,
        suffix: str,
        entropy: float,
        is_high_risk_tld: bool,
        is_trusted_tld: bool,
        hyphen_count: int,
        digit_count: int,
        detected_keywords: List[str],
        risk_score: float,
        reasons: List[str],
    ):
        self.domain_name = domain_name
        self.subdomain = subdomain
        self.root_domain = root_domain
        self.suffix = suffix
        self.entropy = entropy
        self.is_high_risk_tld = is_high_risk_tld
        self.is_trusted_tld = is_trusted_tld
        self.hyphen_count = hyphen_count
        self.digit_count = digit_count
        self.detected_keywords = detected_keywords
        self.risk_score = risk_score
        self.reasons = reasons

class DomainIntelEngine:
    def __init__(self):
        self.extractor = tldextract.TLDExtract(cache_dir=None)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy for DGA/randomness detection."""
        if not text:
            return 0.0
        prob_dict = {}
        for char in text:
            prob_dict[char] = prob_dict.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in prob_dict.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def analyze_domain(self, domain_str: str) -> DomainAnalysisResult:
        clean_domain = domain_str.strip().lower().rstrip(".")
        extracted = self.extractor(clean_domain)
        
        subdomain = extracted.subdomain
        root = extracted.domain
        suffix = extracted.suffix
        root_domain = f"{root}.{suffix}" if suffix else root
        
        reasons: List[str] = []
        score = 0.0

        # Check TLD
        is_high_risk_tld = suffix in HIGH_RISK_TLDS
        is_trusted_tld = suffix in TRUSTED_TLDS

        if is_high_risk_tld:
            score += 25.0
            reasons.append(f"Domain uses high-abuse/risk TLD: '.{suffix}'")
        elif is_trusted_tld:
            score -= 20.0
            reasons.append(f"Domain uses highly vetted TLD: '.{suffix}'")

        # Check Entropy on the core domain name
        entropy = self.calculate_entropy(root)
        if len(root) > 10 and entropy > 3.8:
            score += 25.0
            reasons.append(f"High domain character entropy ({entropy:.2f}), possible DGA/random generated domain")

        # Hyphens and structure
        hyphen_count = clean_domain.count("-")
        if hyphen_count >= 3:
            score += 20.0
            reasons.append(f"Multiple hyphens in domain ({hyphen_count} hyphens)")
        elif hyphen_count == 2:
            score += 10.0

        # Digit count in root
        digit_count = sum(1 for c in root if c.isdigit())
        if digit_count >= 4 and len(root) > 0 and (digit_count / len(root)) > 0.4:
            score += 20.0
            reasons.append(f"High numeric character density in domain ({digit_count} digits)")

        # Keyword matching
        detected_keywords = []
        full_text = f"{subdomain}.{root}".lower()
        for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if kw in full_text:
                detected_keywords.append(kw)

        if detected_keywords:
            kw_penalty = min(len(detected_keywords) * 15.0, 45.0)
            score += kw_penalty
            reasons.append(f"Security/credential lure keywords found in domain: {', '.join(detected_keywords)}")

        # Check Subdomain abuse (e.g., paypal.com.evil-server.xyz)
        if subdomain:
            sub_parts = subdomain.split(".")
            for part in sub_parts:
                if part in ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "chase", "bankofamerica"]:
                    score += 40.0
                    reasons.append(f"Target brand name '{part}' placed inside subdomain misleadingly")

        final_score = max(0.0, min(score, 100.0))
        return DomainAnalysisResult(
            domain_name=clean_domain,
            subdomain=subdomain,
            root_domain=root_domain,
            suffix=suffix,
            entropy=entropy,
            is_high_risk_tld=is_high_risk_tld,
            is_trusted_tld=is_trusted_tld,
            hyphen_count=hyphen_count,
            digit_count=digit_count,
            detected_keywords=detected_keywords,
            risk_score=final_score,
            reasons=reasons
        )
