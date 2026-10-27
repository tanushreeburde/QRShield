import json
import os
from pathlib import Path
from typing import List, Optional, Dict
import tldextract
from app.schemas.common import Finding


class BrandContextAnalyzer:
    def __init__(self, brand_list_path: Optional[str] = None):
        if not brand_list_path:
            base_dir = Path(__file__).resolve().parent.parent
            brand_list_path = os.path.join(base_dir, "data", "brand_list.json")
        self.brands: List[Dict[str, str]] = []
        if os.path.exists(brand_list_path):
            try:
                with open(brand_list_path, "r", encoding="utf-8-sig") as f:
                    self.brands = json.load(f)
            except Exception:
                self.brands = []

    def analyze(self, claimed_brand_text: Optional[str], final_domain_or_host: str) -> List[Finding]:
        findings: List[Finding] = []
        if not claimed_brand_text or not claimed_brand_text.strip():
            return findings

        if not final_domain_or_host:
            return findings

        extracted = tldextract.extract(final_domain_or_host)
        reg_domain = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.domain and extracted.suffix else final_domain_or_host.lower()

        text_lower = claimed_brand_text.lower()

        for item in self.brands:
            brand_name = item.get("brand", "")
            brand_domain = item.get("domain", "").lower()

            if not brand_name or not brand_domain:
                continue

            brand_name_lower = brand_name.lower()
            if brand_name_lower in text_lower:
                if reg_domain != brand_domain:
                    findings.append(Finding(
                        code="BRAND_CONTEXT_MISMATCH",
                        severity="high",
                        description=f"Context references '{brand_name}', but the destination domain is '{reg_domain}' instead of legitimate '{brand_domain}'. (Heuristic, based on visible text - not a verified brand identity check).",
                        critical=False,
                        details={
                            "claimed_brand": brand_name,
                            "expected_domain": brand_domain,
                            "actual_domain": reg_domain
                        }
                    ))
                    break

        return findings


brand_context_analyzer = BrandContextAnalyzer()
