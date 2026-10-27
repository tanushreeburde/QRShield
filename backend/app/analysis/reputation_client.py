import logging
from typing import List, Tuple, Optional
import httpx
from app.config import settings
from app.schemas.common import Finding

logger = logging.getLogger(__name__)


class ReputationClient:
    def __init__(self, api_key: Optional[str] = settings.SAFE_BROWSING_API_KEY):
        self.api_key = api_key

    async def check_url(self, url: str) -> Tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        unavailable_checks: List[str] = []

        if not self.api_key:
            findings.append(Finding(
                code="REPUTATION_UNAVAILABLE",
                severity="info",
                description="Google Safe Browsing threat reputation API key is not configured; check not evaluated.",
                critical=False
            ))
            unavailable_checks.append("reputation")
            return findings, unavailable_checks

        api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "qrshield-security-analyzer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(api_endpoint, json=payload)
                if resp.status_code != 200:
                    logger.warning(f"Safe Browsing API returned status {resp.status_code}")
                    findings.append(Finding(
                        code="REPUTATION_UNAVAILABLE",
                        severity="info",
                        description=f"Safe Browsing threat intelligence returned status {resp.status_code}; check not evaluated.",
                        critical=False
                    ))
                    unavailable_checks.append("reputation")
                    return findings, unavailable_checks

                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
                    findings.append(Finding(
                        code="REPUTATION_MATCH_FOUND",
                        severity="high",
                        description=f"Google Safe Browsing flagged destination as malicious ({', '.join(threat_types)}).",
                        critical=True,
                        details={"matches": matches}
                    ))
                # If matches is empty, it means no known threat was returned by the database.
                # Note: per specification, we do not add a 'reputation_clean' finding that gives false security.

        except Exception as e:
            logger.warning(f"Safe Browsing lookup failed: {e}")
            findings.append(Finding(
                code="REPUTATION_UNAVAILABLE",
                severity="info",
                description="Failed to contact external reputation service; check not evaluated.",
                critical=False
            ))
            unavailable_checks.append("reputation")

        return findings, unavailable_checks


reputation_client = ReputationClient()
