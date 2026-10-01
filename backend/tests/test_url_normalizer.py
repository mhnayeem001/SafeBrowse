import pytest
from backend.app.engines.url_normalizer import URLNormalizer

def test_url_normalizer_basic():
    res = URLNormalizer.normalize("HTTP://EXAMPLE.COM:80/path/to/page?b=2&a=1#fragment")
    assert res.scheme == "http"
    assert res.hostname == "example.com"
    assert res.port is None  # standard port stripped
    assert res.query == "a=1&b=2"  # sorted query params
    assert res.normalized_url == "http://example.com/path/to/page?a=1&b=2"

def test_url_normalizer_userinfo_detection():
    res = URLNormalizer.normalize("http://google.com:secret@evil-domain.com/login")
    assert res.hostname == "evil-domain.com"
    assert any("credentials" in s.lower() or "@" in s for s in res.suspicious_signals)
    assert res.risk_modifier > 0

def test_url_normalizer_punycode():
    res = URLNormalizer.normalize("http://xn--e1afmkfd.xn--p1ai")
    assert res.is_punycode is True
    assert res.risk_modifier > 0

def test_url_normalizer_nested_redirect():
    res = URLNormalizer.normalize("https://tracking.example/click?dest=https%3A%2F%2Ftarget.org%2Faccount")
    assert len(res.nested_urls) >= 1
    assert any("redirect" in s.lower() for s in res.suspicious_signals)

def test_url_normalizer_shortener():
    res = URLNormalizer.normalize("https://bit.ly/3xY9zQ")
    assert res.is_shortener is True
    assert res.registered_domain == "bit.ly"
