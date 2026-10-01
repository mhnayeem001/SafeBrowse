from typing import List, Tuple, Optional
import urllib.parse
from backend.app.security.ssrf import validate_url_for_safe_fetch, safe_fetch_head, SSRFSecurityError
from backend.app.engines.url_normalizer import URLNormalizer

class RedirectHop:
    def __init__(self, step: int, url: str, status_code: int, is_cross_domain: bool):
        self.step = step
        self.url = url
        self.status_code = status_code
        self.is_cross_domain = is_cross_domain

class RedirectChainResult:
    def __init__(
        self,
        initial_url: str,
        final_url: str,
        hops: List[RedirectHop],
        hop_count: int,
        is_excessive: bool,
        is_cross_domain_hopping: bool,
        risk_score: float,
        reasons: List[str]
    ):
        self.initial_url = initial_url
        self.final_url = final_url
        self.hops = hops
        self.hop_count = hop_count
        self.is_excessive = is_excessive
        self.is_cross_domain_hopping = is_cross_domain_hopping
        self.risk_score = risk_score
        self.reasons = reasons

class RedirectAnalyzer:
    @staticmethod
    def extract_static_redirect_targets(url: str) -> List[str]:
        """Extracts any embedded redirect URLs without network calls."""
        norm = URLNormalizer.normalize(url)
        return norm.nested_urls

    @staticmethod
    async def analyze_redirect_chain(url: str, max_depth: int = 5) -> RedirectChainResult:
        reasons = []
        hops = []
        current_url = url
        score = 0.0

        # Validate initial URL
        is_safe, err = validate_url_for_safe_fetch(current_url)
        if not is_safe:
            return RedirectChainResult(
                initial_url=url,
                final_url=url,
                hops=[],
                hop_count=0,
                is_excessive=False,
                is_cross_domain_hopping=False,
                risk_score=75.0,
                reasons=[f"Unsafe target URL rejected by SSRF guard: {err}"]
            )

        try:
            # We don't trace blindly if scheme isn't http/https
            parsed_initial = urllib.parse.urlsplit(url)
            initial_host = parsed_initial.hostname or ""

            # Check static nested redirects first
            nested = RedirectAnalyzer.extract_static_redirect_targets(url)
            if nested:
                reasons.append(f"Contains {len(nested)} nested redirect parameters")
                score += 20.0

            return RedirectChainResult(
                initial_url=url,
                final_url=current_url,
                hops=hops,
                hop_count=len(hops),
                is_excessive=len(hops) >= 4,
                is_cross_domain_hopping=False,
                risk_score=score,
                reasons=reasons
            )
        except Exception as e:
            return RedirectChainResult(
                initial_url=url,
                final_url=current_url,
                hops=[],
                hop_count=0,
                is_excessive=False,
                is_cross_domain_hopping=False,
                risk_score=score,
                reasons=[f"Redirect analysis error: {str(e)}"]
            )
