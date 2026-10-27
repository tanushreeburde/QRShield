import pytest
from app.analysis.url_analyzer import url_analyzer


def test_url_analyzer_clean_url():
    findings = url_analyzer.analyze("https://example.com/safe/path")
    assert len(findings) == 0


def test_url_analyzer_http_scheme():
    findings = url_analyzer.analyze("http://example.com/page")
    codes = [f.code for f in findings]
    assert "INSECURE_SCHEME_HTTP" in codes


def test_url_analyzer_ip_literal():
    findings = url_analyzer.analyze("http://198.51.100.25/login")
    codes = [f.code for f in findings]
    assert "IP_LITERAL_HOST" in codes


def test_url_analyzer_shortener():
    findings = url_analyzer.analyze("https://bit.ly/3xYqz")
    codes = [f.code for f in findings]
    assert "URL_SHORTENER_DETECTED" in codes


def test_url_analyzer_userinfo_at():
    findings = url_analyzer.analyze("https://google.com@phishing-server.com/login")
    codes = [f.code for f in findings]
    assert "SUSPICIOUS_USERINFO_AT_SYMBOL" in codes


def test_url_analyzer_excessive_length():
    long_url = "https://example.com/" + ("a" * 300)
    findings = url_analyzer.analyze(long_url)
    codes = [f.code for f in findings]
    assert "EXCESSIVE_URL_LENGTH" in codes


def test_url_analyzer_percent_encoding():
    obfuscated_url = "https://example.com/%25%32%30%2f%2e%2e"
    findings = url_analyzer.analyze(obfuscated_url)
    codes = [f.code for f in findings]
    assert "URL_OBFUSCATION_PERCENT_ENCODING" in codes


def test_url_analyzer_malformed():
    findings = url_analyzer.analyze("not_a_valid_url")
    codes = [f.code for f in findings]
    assert "MALFORMED_URL" in codes
