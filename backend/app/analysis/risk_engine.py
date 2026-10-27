import os
from pathlib import Path
from typing import List, Tuple, Dict, Any, Set
import yaml
from app.schemas.common import Finding, VerdictEnum


class RiskEngine:
    def __init__(self, config_path: str = None):
        if not config_path:
            base_dir = Path(__file__).resolve().parent.parent
            config_path = os.path.join(base_dir, "config", "risk_weights.yaml")

        self.thresholds = {"suspicious_min_score": 30, "high_risk_min_score": 70}
        self.finding_weights: Dict[str, Dict[str, Any]] = {}

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8-sig") as f:
                    cfg = yaml.safe_load(f) or {}
                    self.thresholds = cfg.get("thresholds", self.thresholds)
                    self.finding_weights = cfg.get("findings", {})
            except Exception:
                pass

    def evaluate(
        self,
        findings: List[Finding],
        unavailable_checks: List[str]
    ) -> Tuple[VerdictEnum, int, List[Finding], List[str]]:
        # Deduplicate findings by code while preserving order and details
        unique_findings: List[Finding] = []
        seen_codes: Set[str] = set()

        for f in findings:
            if f.code not in seen_codes:
                seen_codes.add(f.code)
                unique_findings.append(f)

        total_score = 0
        has_critical = False

        for f in unique_findings:
            cfg_item = self.finding_weights.get(f.code, {})
            weight = cfg_item.get("weight", 0)
            is_critical = cfg_item.get("critical", False) or f.critical
            severity = cfg_item.get("severity", f.severity)

            f.severity = severity
            f.critical = is_critical

            total_score += weight
            if is_critical:
                has_critical = True

        # Contextual compound heuristics:
        # e.g., Lookalike domain + Login form = critical phishing combination
        if "LOOKALIKE_DOMAIN_SUSPECTED" in seen_codes and "LOGIN_FORM_DETECTED" in seen_codes:
            has_critical = True

        if "HOMOGLYPH_DOMAIN_DETECTED" in seen_codes and "LOGIN_FORM_DETECTED" in seen_codes:
            has_critical = True

        if "LOOKALIKE_DOMAIN_SUSPECTED" in seen_codes and "PAYMENT_FORM_DETECTED" in seen_codes:
            has_critical = True

        # Category determination
        high_threshold = self.thresholds.get("high_risk_min_score", 70)
        suspicious_threshold = self.thresholds.get("suspicious_min_score", 30)

        if has_critical or total_score >= high_threshold:
            verdict = VerdictEnum.HIGH_RISK
        elif total_score >= suspicious_threshold:
            verdict = VerdictEnum.SUSPICIOUS
        else:
            verdict = VerdictEnum.LOW_RISK

        # Disclaimers list
        disclaimers: List[str] = [
            "This result does not guarantee the destination is safe or unsafe. It reflects the checks that could be performed at this time."
        ]

        if unavailable_checks:
            checks_formatted = ", ".join(unavailable_checks)
            disclaimers.append(
                f"The following inspection checks were unavailable for this scan: {checks_formatted}."
            )

        if len(unavailable_checks) >= 2:
            disclaimers.append(
                "Limited analysis coverage: Multiple inspection modules were unavailable. Missing data is never treated as proof of safety."
            )
            # Add explicit limited coverage finding if not already present
            if "LIMITED_ANALYSIS_COVERAGE" not in seen_codes:
                cfg_item = self.finding_weights.get("LIMITED_ANALYSIS_COVERAGE", {})
                unique_findings.append(Finding(
                    code="LIMITED_ANALYSIS_COVERAGE",
                    severity="info",
                    description=cfg_item.get("description", "Multiple checks were unavailable; verdict is based on partial analysis coverage."),
                    critical=False
                ))

        return verdict, total_score, unique_findings, disclaimers


risk_engine = RiskEngine()
