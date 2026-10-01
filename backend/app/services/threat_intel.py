from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

class ThreatIntelResult(BaseModel):
    is_malicious: bool
    threat_type: Optional[str] = None  # PHISHING, MALWARE, EXPLOIT, SCAM, COMMAND_AND_CONTROL
    confidence: float = 0.0
    provider_name: str
    details: Optional[str] = None

class ThreatIntelProvider(ABC):
    @abstractmethod
    async def check_url(self, url: str) -> Optional[ThreatIntelResult]:
        pass

    @abstractmethod
    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        pass

# Built-in curated threat feeds for deterministic fast decisions
KNOWN_MALICIOUS_DOMAINS = {
    "malware-traffic-analysis.net": "MALWARE",
    "evil-phishing-test.com": "PHISHING",
    "secure-login-apple-support-verify.com": "PHISHING",
    "paypal-security-alert-center.top": "PHISHING",
    "free-crypto-giveaway-claim.xyz": "SCAM",
    "metamask-wallet-restore-auth.tk": "PHISHING",
    "g00gle-security-alert.click": "BRAND_SPOOF",
    "update-chrome-browser-critical.com": "MALWARE",
    "test-malicious-domain.safebrowse.internal": "PHISHING",
    "test-ransomware-payload.safebrowse.internal": "MALWARE",
}

KNOWN_SAFE_DOMAINS = {
    "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com", "amazon.com", "www.amazon.com",
    "github.com", "gitlab.com", "wikipedia.org", "en.wikipedia.org",
    "stackoverflow.com", "cloudflare.com", "mozilla.org", "w3.org",
    "python.org", "pypi.org", "npmjs.com", "reddit.com", "youtube.com",
    "netflix.com", "linkedin.com", "twitter.com", "x.com"
}

class LocalThreatIntelProvider(ThreatIntelProvider):
    def __init__(self):
        self.malicious_domains = KNOWN_MALICIOUS_DOMAINS
        self.safe_domains = KNOWN_SAFE_DOMAINS

    async def check_url(self, url: str) -> Optional[ThreatIntelResult]:
        # Fast check against known feed
        for mal_dom, threat in self.malicious_domains.items():
            if mal_dom in url.lower():
                return ThreatIntelResult(
                    is_malicious=True,
                    threat_type=threat,
                    confidence=100.0,
                    provider_name="SafeBrowse Local Intel Feed",
                    details=f"Listed in SafeBrowse threat signature intelligence as {threat}"
                )
        return None

    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        clean = domain.lower().strip()
        if clean in self.malicious_domains:
            threat = self.malicious_domains[clean]
            return ThreatIntelResult(
                is_malicious=True,
                threat_type=threat,
                confidence=100.0,
                provider_name="SafeBrowse Local Intel Feed",
                details=f"Domain is a confirmed {threat} indicator"
            )
        return None

class ThreatIntelAggregator:
    def __init__(self):
        self.providers: List[ThreatIntelProvider] = [
            LocalThreatIntelProvider()
        ]

    def register_provider(self, provider: ThreatIntelProvider):
        self.providers.append(provider)

    async def query_all(self, url: str, domain: str) -> Optional[ThreatIntelResult]:
        # Check domain first
        for p in self.providers:
            res = await p.check_domain(domain)
            if res and res.is_malicious:
                return res

        # Check full URL
        for p in self.providers:
            res = await p.check_url(url)
            if res and res.is_malicious:
                return res

        return None

threat_intel_service = ThreatIntelAggregator()
