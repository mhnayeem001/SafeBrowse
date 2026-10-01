import pytest
from backend.app.engines.typosquatting import TyposquattingEngine

def test_legitimate_domains_not_flagged():
    engine = TyposquattingEngine()
    res = engine.analyze_domain("google", "google.com")
    assert res.is_spoofed is False
    assert res.matched_brand == "google"

    res_paypal = engine.analyze_domain("paypal", "paypal.com")
    assert res_paypal.is_spoofed is False

def test_homoglyph_spoof_detection():
    engine = TyposquattingEngine()
    # paypa1 with digit '1' replacing 'l'
    res = engine.analyze_domain("paypa1", "paypa1.com")
    assert res.is_spoofed is True
    assert res.matched_brand == "paypal"
    assert res.similarity_score >= 90.0

    # g00gle with zeros replacing 'o'
    res_google = engine.analyze_domain("g00gle", "g00gle.com")
    assert res_google.is_spoofed is True
    assert res_google.matched_brand == "google"

def test_edit_distance_typosquatting():
    engine = TyposquattingEngine()
    # googlr with edit distance 1
    res = engine.analyze_domain("googlr", "googlr.com")
    assert res.is_spoofed is True
    assert res.matched_brand == "google"

    # microsft with omitted 'o'
    res_ms = engine.analyze_domain("microsft", "microsft.com")
    assert res_ms.is_spoofed is True
    assert res_ms.matched_brand == "microsoft"

def test_brand_compound_spoof():
    engine = TyposquattingEngine()
    res = engine.analyze_domain("paypal-security-update", "paypal-security-update.com")
    assert res.is_spoofed is True
    assert res.matched_brand == "paypal"
