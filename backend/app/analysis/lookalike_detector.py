import json
import os
from pathlib import Path
from typing import List, Dict, Optional
import tldextract
from rapidfuzz.distance import Levenshtein
from confusable_homoglyphs import confusables
from app.schemas.common import Finding


class LookalikeDetector:
    def __init__(self, brand_list_path: Optional[str] = None):
        if not brand_list_path:
            base_dir = Path(__file__).resolve().parent.parent
            brand_list_path = os.path.join(base_dir, "data", "brand_list.json")
        self.brands: List[Dict[str, str]] = []
        if os.path.exists(brand_list_path):
            try:
                with open(brand_list_path, "r", encoding="utf-8-sig") as f:
                    self.brands = json.load(f)
            except Exception as e:
                self.brands = []

    def analyze(self, domain_or_host: str) -> List[Finding]:
        findings: List[Finding] = []
        if not domain_or_host:
            return findings

        extracted = tldextract.extract(domain_or_host)
        registrable = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.domain and extracted.suffix else domain_or_host.lower()
        core_domain = extracted.domain.lower() if extracted.domain else domain_or_host.lower()

        # 1. Homoglyph / Confusable detection
        try:
            is_confusable = confusables.is_confusable(registrable, preferred_aliases=["latin"])
            if is_confusable:
                findings.append(Finding(
                    code="HOMOGLYPH_DOMAIN_DETECTED",
                    severity="high",
                    description=f"Domain '{registrable}' contains Unicode homoglyphs or confusable script characters designed to visually mimic Latin letters.",
                    critical=False,
                    details={"homoglyph_matches": [str(x) for x in is_confusable[:3]]}
                ))
        except Exception:
            pass

        # 2. Typosquatting / Edit-distance comparison against brand list
        for item in self.brands:
            brand_name = item.get("brand", "")
            brand_domain = item.get("domain", "").lower()

            if not brand_domain:
                continue

            brand_extracted = tldextract.extract(brand_domain)
            brand_core = brand_extracted.domain.lower()

            # If it's the genuine brand domain, do NOT flag
            if registrable == brand_domain:
                continue

            # Check core domain similarity (e.g. 'paypa1' vs 'paypal')
            if len(core_domain) >= 4 and len(brand_core) >= 4:
                dist = Levenshtein.distance(core_domain, brand_core)
                max_len = max(len(core_domain), len(brand_core))
                similarity = 1.0 - (dist / max_len)

                # Flag if edit distance is 1 or 2 with >= 75% similarity, or substring imitation
                is_typosquat = (dist in (1, 2) and similarity >= 0.75) or (
                    brand_core in core_domain and core_domain != brand_core and (len(core_domain) - len(brand_core) <= 4)
                )

                if is_typosquat:
                    findings.append(Finding(
                        code="LOOKALIKE_DOMAIN_SUSPECTED",
                        severity="high",
                        description=f"Domain '{registrable}' exhibits close typographic similarity to legitimate brand '{brand_name}' ({brand_domain}) (similarity: {similarity:.0%}). Note: Heuristic indicator, not a legal trademark determination.",
                        critical=False,
                        details={
                            "matched_brand": brand_name,
                            "legitimate_domain": brand_domain,
                            "edit_distance": dist,
                            "similarity": round(similarity, 2)
                        }
                    ))
                    # Only report the strongest matching brand to prevent noisy duplicates
                    break

        return findings


lookalike_detector = LookalikeDetector()
