import pytest
from app.analysis.risk_engine import risk_engine
from app.schemas.common import Finding, VerdictEnum


def test_risk_engine_low_risk():
    findings = [
        Finding(code="EXCESSIVE_URL_LENGTH", severity="low", description="Long URL", critical=False)
    ]
    verdict, score, evidence, disclaimers = risk_engine.evaluate(findings, [])
    assert verdict == VerdictEnum.LOW_RISK
    assert score < 30
    assert any("does not guarantee" in d for d in disclaimers)


def test_risk_engine_suspicious():
    findings = [
        Finding(code="INSECURE_SCHEME_HTTP", severity="medium", description="HTTP", critical=False),
        Finding(code="URL_SHORTENER_DETECTED", severity="medium", description="Shortener", critical=False)
    ]
    verdict, score, evidence, disclaimers = risk_engine.evaluate(findings, [])
    assert verdict == VerdictEnum.SUSPICIOUS
    assert score >= 30


def test_risk_engine_high_risk_compound():
    # Lookalike + Login form combo escalates to HIGH_RISK
    findings = [
        Finding(code="LOOKALIKE_DOMAIN_SUSPECTED", severity="high", description="Lookalike", critical=False),
        Finding(code="LOGIN_FORM_DETECTED", severity="medium", description="Login form", critical=False)
    ]
    verdict, score, evidence, disclaimers = risk_engine.evaluate(findings, [])
    assert verdict == VerdictEnum.HIGH_RISK


def test_risk_engine_unavailable_checks_disclaimer():
    findings = []
    unavailable = ["domain_age", "reputation"]
    verdict, score, evidence, disclaimers = risk_engine.evaluate(findings, unavailable)
    assert verdict == VerdictEnum.LOW_RISK
    assert score == 0
    # Must explicitly disclaim missing data
    assert any("Limited analysis coverage" in d for d in disclaimers)
    evidence_codes = [e.code for e in evidence]
    assert "LIMITED_ANALYSIS_COVERAGE" in evidence_codes
