import unicodedata
from typing import Dict, List, Optional, Tuple, Set

# Comprehensive Map of major global brands to their legitimate registered domains
PROTECTED_BRANDS = {
    "google": [
        "google.com", "google.co.uk", "google.ca", "google.com.bd", "google.de", 
        "google.fr", "google.com.au", "googleapis.com", "gstatic.com", 
        "googleusercontent.com", "youtube.com", "gmail.com", "googlevideo.com"
    ],
    "microsoft": [
        "microsoft.com", "microsoftonline.com", "live.com", "office.com", 
        "office365.com", "outlook.com", "msn.com", "azure.com", "windows.net", 
        "visualstudio.com", "bing.com", "microsoftedge.com", "partner.microsoft.com",
        "sharepoint.com", "microsoft365.com", "skype.com", "xbox.com"
    ],
    "apple": [
        "apple.com", "icloud.com", "apple-dns.net", "mzstatic.com", "appleid.apple.com"
    ],
    "amazon": [
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.in", 
        "aws.amazon.com", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com"
    ],
    "paypal": [
        "paypal.com", "paypal.me", "paypal-communication.com", "paypalobjects.com"
    ],
    "netflix": [
        "netflix.com", "nflxvideo.net", "nflxext.com", "nflximg.net"
    ],
    "meta": [
        "facebook.com", "instagram.com", "whatsapp.com", "meta.com", 
        "fbcdn.net", "messenger.com", "threads.net", "facebook.net"
    ],
    "chase": ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "binance": ["binance.com", "binance.org", "binance.me", "bnapp.org"],
    "coinbase": ["coinbase.com", "pro.coinbase.com"],
    "twitter": ["twitter.com", "x.com", "twimg.com", "t.co"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "dropbox": ["dropbox.com", "dropboxstatic.com", "dropboxusercontent.com"],
    "adobe": ["adobe.com", "adobe.io", "behance.net"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "github": ["github.com", "githubusercontent.com", "github.io", "github.dev"],
    "gitlab": ["gitlab.com"],
}

HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '@': 'a',
    '!': 'i',
    '|': 'l',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', # Cyrillic
    'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ν': 'v',                     # Greek
    'vv': 'w', 'rn': 'm', 'cl': 'd', 'cj': 'g', 'nn': 'm',
}

class TyposquattingResult:
    def __init__(
        self,
        is_spoofed: bool,
        matched_brand: Optional[str],
        similarity_score: float, # 0 to 100
        confidence: float,        # 0 to 100
        technique: Optional[str],
        reasons: List[str],
    ):
        self.is_spoofed = is_spoofed
        self.matched_brand = matched_brand
        self.similarity_score = similarity_score
        self.confidence = confidence
        self.technique = technique
        self.reasons = reasons

class TyposquattingEngine:
    @staticmethod
    def normalize_confusables(text: str) -> str:
        """Replace confusables and unicode homoglyphs with standard ASCII letters."""
        normalized = unicodedata.normalize('NFKD', text)
        result = []
        i = 0
        while i < len(normalized):
            two_char = normalized[i:i+2]
            if two_char in HOMOGLYPH_MAP:
                result.append(HOMOGLYPH_MAP[two_char])
                i += 2
                continue
            char = normalized[i]
            if char in HOMOGLYPH_MAP:
                result.append(HOMOGLYPH_MAP[char])
            else:
                result.append(char)
            i += 1
        return "".join(result)

    @staticmethod
    def damerau_levenshtein_distance(s1: str, s2: str) -> int:
        d = {}
        len1 = len(s1)
        len2 = len(s2)
        for i in range(-1, len1 + 1):
            d[(i, -1)] = i + 1
        for j in range(-1, len2 + 1):
            d[(-1, j)] = j + 1

        for i in range(len1):
            for j in range(len2):
                cost = 0 if s1[i] == s2[j] else 1
                d[(i, j)] = min(
                    d[(i - 1, j)] + 1,       # deletion
                    d[(i, j - 1)] + 1,       # insertion
                    d[(i - 1, j - 1)] + cost  # substitution
                )
                if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

        return d[(len1 - 1, len2 - 1)]

    def analyze_domain(self, domain_label: str, full_domain: str) -> TyposquattingResult:
        clean_label = domain_label.lower().strip()
        clean_full = full_domain.lower().strip()

        # Check if legitimate official domain or subdomain of official domain
        for brand, legits in PROTECTED_BRANDS.items():
            for legit in legits:
                if clean_full == legit or clean_full.endswith("." + legit) or clean_label == brand:
                    return TyposquattingResult(
                        is_spoofed=False,
                        matched_brand=brand,
                        similarity_score=100.0,
                        confidence=95.0,
                        technique="LEGITIMATE_DOMAIN",
                        reasons=[f"Recognized official domain for '{brand}'"]
                    )

        normalized_label = self.normalize_confusables(clean_label)
        reasons = []
        best_match_brand = None
        highest_sim = 0.0
        best_technique = None

        for brand in PROTECTED_BRANDS.keys():
            brand_len = len(brand)
            label_len = len(clean_label)

            # Check 1: Brand or normalized homoglyph brand in compound
            if brand in normalized_label:
                if normalized_label == brand:
                    highest_sim = 95.0
                    best_match_brand = brand
                    best_technique = "HOMOGLYPH_SUBSTITUTION"
                    reasons.append(f"Visual homoglyph / char substitution impersonating '{brand}' ('{clean_label}' -> '{brand}')")
                    break
                else:
                    highest_sim = 90.0
                    best_match_brand = brand
                    best_technique = "BRAND_NAME_COMPOUND"
                    reasons.append(f"Domain embeds protected brand name or homoglyph '{brand}' in an unauthorized compound domain")
                    break

            # Check 2: Edit distance on original label
            dist = self.damerau_levenshtein_distance(clean_label, brand)
            max_len = max(brand_len, label_len)
            sim_score = max(0.0, (1.0 - (dist / max_len)) * 100.0)

            if dist == 1 and brand_len >= 4:
                similarity = 90.0
                if similarity > highest_sim:
                    highest_sim = similarity
                    best_match_brand = brand
                    best_technique = "TYPO_EDIT_DISTANCE_1"
                    reasons = [f"Direct typosquatting variation of '{brand}' (edit distance 1)"]
            elif dist == 2 and brand_len >= 7 and sim_score > 70.0:
                similarity = 75.0
                if similarity > highest_sim:
                    highest_sim = similarity
                    best_match_brand = brand
                    best_technique = "TYPO_EDIT_DISTANCE_2"
                    reasons = [f"Possible brand spoofing of '{brand}' (edit distance 2)"]

        if best_match_brand and highest_sim >= 70.0:
            return TyposquattingResult(
                is_spoofed=True,
                matched_brand=best_match_brand,
                similarity_score=highest_sim,
                confidence=min(95.0, highest_sim),
                technique=best_technique,
                reasons=reasons
            )

        return TyposquattingResult(
            is_spoofed=False,
            matched_brand=None,
            similarity_score=0.0,
            confidence=50.0,
            technique=None,
            reasons=[]
        )
