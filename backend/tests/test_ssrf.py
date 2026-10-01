import pytest
from backend.app.security.ssrf import is_ip_blocked, resolve_and_validate_hostname, validate_url_for_safe_fetch

def test_blocked_private_ips():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("10.0.0.5") is True
    assert is_ip_blocked("172.16.1.1") is True
    assert is_ip_blocked("192.168.1.100") is True
    assert is_ip_blocked("169.254.169.254") is True  # AWS/GCP metadata
    assert is_ip_blocked("0.0.0.0") is True
    assert is_ip_blocked("255.255.255.255") is True

def test_blocked_ipv6():
    assert is_ip_blocked("::1") is True
    assert is_ip_blocked("fe80::1") is True
    assert is_ip_blocked("fc00::1") is True

def test_allowed_public_ips():
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False
    assert is_ip_blocked("93.184.216.34") is False

def test_blocked_hostnames():
    is_safe, reason, _ = resolve_and_validate_hostname("localhost")
    assert is_safe is False
    assert "forbidden" in reason.lower()

    is_safe, reason, _ = resolve_and_validate_hostname("metadata.google.internal")
    assert is_safe is False

def test_validate_url_schemes():
    is_safe, reason = validate_url_for_safe_fetch("file:///etc/passwd")
    assert is_safe is False
    assert "scheme" in reason.lower()

    is_safe, reason = validate_url_for_safe_fetch("gopher://127.0.0.1:70")
    assert is_safe is False

    is_safe, reason = validate_url_for_safe_fetch("http://127.0.0.1:8000/api")
    assert is_safe is False

    is_safe, reason = validate_url_for_safe_fetch("http://169.254.169.254/latest/meta-data")
    assert is_safe is False
