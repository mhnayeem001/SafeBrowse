import re
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", 
    "goo.gl", "tiny.cc", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"
}

SUSPICIOUS_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_to", "next", "dest", "destination", 
    "target", "return", "return_to", "r", "u", "link", "goto", "out"
}

DANGEROUS_SCHEMES = {
    "javascript", "data", "blob", "vbscript", "file"
}

class NormalizedURLResult:
    def __init__(
        self,
        original_url: str,
        normalized_url: str,
        scheme: str,
        hostname: str,
        registered_domain: str,
        subdomains: List[str],
        port: Optional[int],
        path: str,
        query: str,
        is_ip_host: bool,
        is_punycode: bool,
        is_shortener: bool,
        nested_urls: List[str],
        suspicious_signals: List[str],
        risk_modifier: float,
    ):
        self.original_url = original_url
        self.normalized_url = normalized_url
        self.scheme = scheme
        self.hostname = hostname
        self.registered_domain = registered_domain
        self.subdomains = subdomains
        self.port = port
        self.path = path
        self.query = query
        self.is_ip_host = is_ip_host
        self.is_punycode = is_punycode
        self.is_shortener = is_shortener
        self.nested_urls = nested_urls
        self.suspicious_signals = suspicious_signals
        self.risk_modifier = risk_modifier

class URLNormalizer:
    @staticmethod
    def normalize(raw_url: str) -> NormalizedURLResult:
        original = raw_url.strip()
        signals: List[str] = []
        nested_urls: List[str] = []
        risk_mod = 0.0

        # Handle schemes
        if "://" not in original:
            if original.startswith("//"):
                working_url = "http:" + original
            elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", original):
                working_url = "http://" + original
            else:
                working_url = "http://" + original
        else:
            working_url = original

        parsed = urllib.parse.urlsplit(working_url)
        scheme = parsed.scheme.lower()

        if scheme in DANGEROUS_SCHEMES:
            signals.append(f"Dangerous URI scheme detected: '{scheme}:'")
            risk_mod += 60.0

        # Check for userinfo / credentials in authority (e.g. http://google.com@evil.com)
        netloc = parsed.netloc
        if "@" in netloc:
            signals.append("URL contains credentials/misleading authority with '@' symbol")
            risk_mod += 35.0
            # Split off userinfo
            userinfo, _, host_port = netloc.rpartition("@")
            netloc = host_port

        # Split host and port
        hostname = ""
        port = None
        if ":" in netloc and not netloc.endswith("]"):
            h, _, p = netloc.rpartition(":")
            hostname = h.strip("[]")
            try:
                port = int(p)
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    port = None
            except ValueError:
                signals.append(f"Malformed port '{p}'")
                risk_mod += 15.0
        else:
            hostname = netloc.strip("[]")

        # Host normalization
        hostname = hostname.lower().rstrip(".")

        # Check IP address host
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            signals.append(f"Host is a raw IP address ({hostname})")
            risk_mod += 25.0
        except ValueError:
            # Check integer or hex obfuscated IP
            if hostname.isdigit():
                try:
                    resolved_ip = str(ipaddress.IPv4Address(int(hostname)))
                    signals.append(f"Integer-obfuscated IP address: {hostname} -> {resolved_ip}")
                    hostname = resolved_ip
                    is_ip = True
                    risk_mod += 40.0
                except Exception:
                    pass
            elif hostname.startswith("0x"):
                try:
                    resolved_ip = str(ipaddress.IPv4Address(int(hostname, 16)))
                    signals.append(f"Hex-obfuscated IP address: {hostname} -> {resolved_ip}")
                    hostname = resolved_ip
                    is_ip = True
                    risk_mod += 40.0
                except Exception:
                    pass

        # Punycode check
        is_punycode = False
        if "xn--" in hostname:
            is_punycode = True
            try:
                decoded_host = hostname.encode("utf-8").decode("idna")
                signals.append(f"Punycode/IDN hostname: '{hostname}' decoded to '{decoded_host}'")
                risk_mod += 20.0
            except Exception:
                signals.append(f"Malformed punycode hostname: {hostname}")
                risk_mod += 30.0

        # Subdomains and registered domain extraction
        parts = hostname.split(".")
        if is_ip or len(parts) <= 1:
            registered_domain = hostname
            subdomains = []
        elif len(parts) == 2:
            registered_domain = hostname
            subdomains = []
        else:
            # Common 2-level TLD heuristic fallback (co.uk, com.au, org.uk, etc.)
            two_part_tlds = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.in"}
            last_two = ".".join(parts[-2:])
            if last_two in two_part_tlds and len(parts) >= 3:
                registered_domain = ".".join(parts[-3:])
                subdomains = parts[:-3]
            else:
                registered_domain = ".".join(parts[-2:])
                subdomains = parts[:-2]

        if len(subdomains) >= 3:
            signals.append(f"Excessive subdomain depth ({len(subdomains)} levels)")
            risk_mod += 15.0

        # Check for URL shorteners
        is_shortener = registered_domain in KNOWN_URL_SHORTENERS
        if is_shortener:
            signals.append(f"URL uses known shortening service: {registered_domain}")
            risk_mod += 10.0

        # Non-standard ports
        if port and port not in (80, 443, 8080, 8443, 3000, 5000, 5173, 8000):
            signals.append(f"Suspicious non-standard port: {port}")
            risk_mod += 20.0

        # Parse query params for nested redirect targets
        query_dict = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        clean_query_pairs = []
        for k, vals in sorted(query_dict.items()):
            for v in vals:
                clean_query_pairs.append((k, v))
                if k.lower() in SUSPICIOUS_REDIRECT_PARAMS:
                    # Check if value looks like a URL
                    if "http://" in v or "https://" in v or "//" in v or (len(v) > 4 and "." in v and "/" in v):
                        nested_urls.append(v)
                        signals.append(f"Nested redirect parameter '{k}' detected")
                        risk_mod += 15.0

        sorted_query = urllib.parse.urlencode(clean_query_pairs)
        path = parsed.path or "/"
        if "//" in path:
            path = re.sub(r"/+", "/", path)

        # Reconstructed normalized URL
        netloc_part = hostname
        if port:
            netloc_part = f"{hostname}:{port}"

        normalized_url = urllib.parse.urlunsplit((
            scheme,
            netloc_part,
            path,
            sorted_query,
            ""  # Exclude fragment for normalization
        ))

        return NormalizedURLResult(
            original_url=original,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            registered_domain=registered_domain,
            subdomains=subdomains,
            port=port,
            path=path,
            query=sorted_query,
            is_ip_host=is_ip,
            is_punycode=is_punycode,
            is_shortener=is_shortener,
            nested_urls=nested_urls,
            suspicious_signals=signals,
            risk_modifier=min(risk_mod, 100.0)
        )
