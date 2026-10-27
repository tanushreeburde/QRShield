import pytest
from app.analysis.lookalike_detector import lookalike_detector


def test_lookalike_detects_typosquatting_paypal():
    findings = lookalike_detector.analyze("paypa1.com")
    codes = [f.code for f in findings]
    assert "LOOKALIKE_DOMAIN_SUSPECTED" in codes
    lookalike_finding = next(f for f in findings if f.code == "LOOKALIKE_DOMAIN_SUSPECTED")
    assert lookalike_finding.details["matched_brand"] == "PayPal"


def test_lookalike_does_not_flag_genuine_brand():
    findings = lookalike_detector.analyze("paypal.com")
    codes = [f.code for f in findings]
    assert "LOOKALIKE_DOMAIN_SUSPECTED" not in codes


def test_lookalike_does_not_flag_unrelated_domain():
    findings = lookalike_detector.analyze("wikipedia.org")
    codes = [f.code for f in findings]
    assert "LOOKALIKE_DOMAIN_SUSPECTED" not in codes


def test_lookalike_detects_homoglyph():
    # Cyrillic small letter 'а' (U+0430) in place of Latin 'a'
    homoglyph_domain = "p\u0430ypal.com"
    findings = lookalike_detector.analyze(homoglyph_domain)
    codes = [f.code for f in findings]
    assert "HOMOGLYPH_DOMAIN_DETECTED" in codes
