import asyncio
import datetime
import ipaddress
from typing import List, Tuple, Optional
import tldextract
import whois
from app.config import settings
from app.schemas.common import Finding

HIGH_ABUSE_TLDS = {
    "top", "xyz", "click", "loan", "work", "country", "gq", "cf", "tk",
    "ml", "ga", "fit", "surf", "buzz", "racing", "kim", "icu", "cam", "rest"
}


class DomainAnalyzer:
    def __init__(self, whois_enabled: bool = settings.WHOIS_LOOKUP_ENABLED, whois_timeout: float = settings.WHOIS_TIMEOUT_SECONDS):
        self.whois_enabled = whois_enabled
        self.whois_timeout = whois_timeout

    def _sync_whois(self, domain: str):
        try:
            return whois.whois(domain)
        except Exception:
            return None

    async def analyze(self, hostname: str) -> Tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        unavailable_checks: List[str] = []

        if not hostname:
            return findings, unavailable_checks

        # Check if hostname is an IP address
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            findings.append(Finding(
                code="IP_LITERAL_HOST",
                severity="high",
                description=f"Destination domain is a raw IP literal ({hostname}).",
                critical=False
            ))
            unavailable_checks.append("domain_age")
            return findings, unavailable_checks
        except ValueError:
            pass

        extracted = tldextract.extract(hostname)
        tld = (extracted.suffix or "").lower()
        reg_domain = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.domain and extracted.suffix else hostname.lower()

        # Check uncommon / high-abuse TLD
        last_tld = tld.split(".")[-1] if tld else ""
        if last_tld in HIGH_ABUSE_TLDS:
            findings.append(Finding(
                code="UNCOMMON_TLD",
                severity="medium",
                description=f"Destination uses '.{last_tld}', a top-level domain frequently associated with elevated spam and phishing abuse.",
                critical=False,
                details={"tld": last_tld}
            ))

        # Best-effort WHOIS lookup
        if not self.whois_enabled or not reg_domain:
            findings.append(Finding(
                code="DOMAIN_AGE_UNAVAILABLE",
                severity="info",
                description="WHOIS domain age lookup is disabled or not configured; check not evaluated.",
                critical=False
            ))
            unavailable_checks.append("domain_age")
            return findings, unavailable_checks

        try:
            # Run whois in thread with timeout
            loop = asyncio.get_running_loop()
            w_info = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_whois, reg_domain),
                timeout=self.whois_timeout
            )

            if not w_info or not w_info.creation_date:
                findings.append(Finding(
                    code="DOMAIN_AGE_UNAVAILABLE",
                    severity="info",
                    description=f"Registration age for '{reg_domain}' could not be determined via WHOIS.",
                    critical=False
                ))
                unavailable_checks.append("domain_age")
                return findings, unavailable_checks

            creation_date = w_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime.datetime):
                now = datetime.datetime.now(datetime.timezone.utc if creation_date.tzinfo else None)
                age_days = (now - creation_date).days
                if age_days < 30:
                    findings.append(Finding(
                        code="RECENTLY_REGISTERED_DOMAIN",
                        severity="high",
                        description=f"Domain was registered only {age_days} days ago ({creation_date.strftime('%Y-%m-%d')}). Newly created domains carry elevated risk.",
                        critical=False,
                        details={"age_days": age_days, "creation_date": str(creation_date)}
                    ))
            else:
                findings.append(Finding(
                    code="DOMAIN_AGE_UNAVAILABLE",
                    severity="info",
                    description="Could not parse WHOIS registration timestamp into a valid date.",
                    critical=False
                ))
                unavailable_checks.append("domain_age")

        except asyncio.TimeoutError:
            findings.append(Finding(
                code="DOMAIN_AGE_UNAVAILABLE",
                severity="info",
                description=f"WHOIS lookup for '{reg_domain}' timed out after {self.whois_timeout}s.",
                critical=False
            ))
            unavailable_checks.append("domain_age")
        except Exception as e:
            findings.append(Finding(
                code="DOMAIN_AGE_UNAVAILABLE",
                severity="info",
                description=f"WHOIS query failed: {e}",
                critical=False
            ))
            unavailable_checks.append("domain_age")

        return findings, unavailable_checks


domain_analyzer = DomainAnalyzer()
