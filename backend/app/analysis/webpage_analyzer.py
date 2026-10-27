import urllib.parse
from typing import List, Tuple
import httpx
from bs4 import BeautifulSoup
import tldextract
from app.config import settings
from app.schemas.common import Finding
from app.security.ssrf_guard import validate_url_for_ssrf, SSRFBlockedException

PAYMENT_KEYWORDS = {
    "card", "cardnumber", "card_number", "cc-number", "cvv", "cvc",
    "securitycode", "security_code", "exp-date", "expiry", "cardholder"
}

LOGIN_KEYWORDS = {
    "password", "passwd", "pwd", "user_password", "pass"
}


class WebpageAnalyzer:
    def __init__(
        self,
        max_bytes: int = settings.MAX_RESPONSE_BYTES,
        connect_timeout: float = settings.CONNECT_TIMEOUT_SECONDS,
        total_timeout: float = settings.REQUEST_TIMEOUT_SECONDS
    ):
        self.max_bytes = max_bytes
        self.connect_timeout = connect_timeout
        self.total_timeout = total_timeout

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            ext = tldextract.extract(parsed.hostname or "")
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    async def analyze(self, final_url: str) -> List[Finding]:
        findings: List[Finding] = []

        if not final_url:
            return findings

        # SSRF check before controlled fetch
        try:
            validate_url_for_ssrf(final_url)
        except SSRFBlockedException as ssrf_err:
            findings.append(Finding(
                code="SSRF_BLOCKED_HOP",
                severity="high",
                description=f"Destination page fetch aborted by SSRF guard: {ssrf_err.message}",
                critical=True
            ))
            return findings

        headers = {
            "User-Agent": "QRShield-Analyzer/1.0 (Security Risk Analysis; +https://qrshield.local)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        timeout = httpx.Timeout(self.total_timeout, connect=self.connect_timeout)

        html_content = ""
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False) as client:
                async with client.stream("GET", final_url, headers=headers) as response:
                    content_type = response.headers.get("content-type", "").lower()
                    if response.status_code >= 400:
                        findings.append(Finding(
                            code="PAGE_UNREACHABLE_FOR_ANALYSIS",
                            severity="medium",
                            description=f"Destination page returned HTTP status {response.status_code}.",
                            critical=False
                        ))
                        return findings

                    # Only inspect HTML-like content
                    if "text/html" not in content_type and "application/xhtml" not in content_type:
                        return findings

                    chunks = []
                    total_bytes = 0
                    async for chunk in response.aiter_bytes():
                        chunks.append(chunk)
                        total_bytes += len(chunk)
                        if total_bytes >= self.max_bytes:
                            break

                    html_content = b"".join(chunks).decode("utf-8", errors="replace")

        except httpx.ConnectTimeout:
            findings.append(Finding(
                code="PAGE_UNREACHABLE_FOR_ANALYSIS",
                severity="medium",
                description="Timed out while attempting to retrieve webpage for static content analysis.",
                critical=False
            ))
            return findings
        except (httpx.ConnectError, httpx.NetworkError, Exception) as fetch_err:
            findings.append(Finding(
                code="PAGE_UNREACHABLE_FOR_ANALYSIS",
                severity="medium",
                description=f"Could not retrieve webpage HTML: {fetch_err}",
                critical=False
            ))
            return findings

        if not html_content.strip():
            findings.append(Finding(
                code="PAGE_UNREACHABLE_FOR_ANALYSIS",
                severity="medium",
                description="Destination server returned an empty response body.",
                critical=False
            ))
            return findings

        # Parse static HTML
        page_domain = self._extract_domain(final_url)
        soup = BeautifulSoup(html_content, "html.parser")

        # Check for SPA/client-rendered shell with minimal HTML
        body = soup.find("body")
        body_text = body.get_text(strip=True) if body else ""
        forms = soup.find_all("form")

        if len(body_text) < 150 and not forms:
            root_div = soup.find(id=["root", "app", "__next"])
            if root_div or "javascript" in html_content.lower():
                findings.append(Finding(
                    code="JS_HEAVY_PAGE_LIMITED_ANALYSIS",
                    severity="info",
                    description="The destination is a client-side JavaScript Single Page Application (SPA). Dynamic components were not executed in static analysis.",
                    critical=False
                ))

        has_password_field = False
        has_payment_field = False
        has_cross_domain_submission = False

        for form in forms:
            action = form.get("action", "")
            if action:
                action_full_url = urllib.parse.urljoin(final_url, action)
                action_domain = self._extract_domain(action_full_url)
                if action_domain and page_domain and action_domain != page_domain:
                    has_cross_domain_submission = True

            # Inspect inputs
            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                inp_type = (inp.get("type") or "text").lower()
                inp_name = (inp.get("name") or "").lower()
                inp_id = (inp.get("id") or "").lower()
                inp_placeholder = (inp.get("placeholder") or "").lower()
                inp_autocomplete = (inp.get("autocomplete") or "").lower()

                field_identifiers = f"{inp_name} {inp_id} {inp_placeholder} {inp_autocomplete}"

                # Password / Login detection
                if inp_type == "password" or any(k in field_identifiers for k in LOGIN_KEYWORDS):
                    has_password_field = True

                # Payment / Credit Card detection
                if any(k in field_identifiers for k in PAYMENT_KEYWORDS) or inp_autocomplete in ("cc-number", "cc-csc", "cc-exp"):
                    has_payment_field = True

        if has_password_field:
            findings.append(Finding(
                code="LOGIN_FORM_DETECTED",
                severity="medium",
                description="The destination page presents an authentication login or password collection form.",
                critical=False
            ))

        if has_payment_field:
            findings.append(Finding(
                code="PAYMENT_FORM_DETECTED",
                severity="high",
                description="The destination page includes payment credential inputs (e.g. credit card number, CVV, expiration date).",
                critical=False
            ))

        if has_cross_domain_submission:
            findings.append(Finding(
                code="FORM_SUBMITS_TO_DIFFERENT_DOMAIN",
                severity="high",
                description="Form action submits data to a third-party external domain differing from the page domain.",
                critical=False
            ))

        return findings


webpage_analyzer = WebpageAnalyzer()
