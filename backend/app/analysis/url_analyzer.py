import re
import urllib.parse
import ipaddress
from typing import List, Tuple
import tldextract
from app.schemas.common import Finding

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "rb.gy", "tiny.cc", "cutt.ly", "shorturl.at", "bl.ink",
    "qr.ae", "v.gd", "clck.ru", "tr.ee", "linktr.ee"
}

SCHEME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class URLAnalyzer:
    def __init__(self, max_length_threshold: int = 256):
        self.max_length_threshold = max_length_threshold

    def analyze(self, raw_url: str) -> List[Finding]:
        findings: List[Finding] = []

        if not raw_url or not isinstance(raw_url, str):
            findings.append(Finding(
                code="MALFORMED_URL",
                severity="high",
                description="Submitted URL is empty or not a valid string.",
                critical=False
            ))
            return findings

        try:
            parsed = urllib.parse.urlparse(raw_url)
        except Exception as e:
            findings.append(Finding(
                code="MALFORMED_URL",
                severity="high",
                description=f"Failed to parse URL: {e}",
                critical=False
            ))
            return findings

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            findings.append(Finding(
                code="MALFORMED_URL",
                severity="high",
                description=f"Unsupported or malformed protocol scheme: '{scheme}'",
                critical=False
            ))
            return findings

        # Scheme check
        if scheme == "http":
            findings.append(Finding(
                code="INSECURE_SCHEME_HTTP",
                severity="medium",
                description="The destination uses unencrypted plain HTTP instead of HTTPS.",
                critical=False
            ))

        hostname = parsed.hostname or ""
        if not hostname:
            findings.append(Finding(
                code="MALFORMED_URL",
                severity="high",
                description="URL lacks a valid hostname or host specification.",
                critical=False
            ))
            return findings

        # Check for literal IP host (IPv4 or IPv6)
        is_ip = False
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            findings.append(Finding(
                code="IP_LITERAL_HOST",
                severity="high",
                description=f"The URL connects directly to an IP literal ({hostname}) rather than a registered domain name.",
                critical=False,
                details={"host": hostname}
            ))

        # Check URL length
        if len(raw_url) > self.max_length_threshold:
            findings.append(Finding(
                code="EXCESSIVE_URL_LENGTH",
                severity="low",
                description=f"URL is unusually long ({len(raw_url)} characters > {self.max_length_threshold}), which can obscure destination parameters.",
                critical=False,
                details={"length": len(raw_url)}
            ))

        # Check for excessive percent-encoding or hex obfuscation
        percent_encodings = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
        if len(percent_encodings) >= 4 or "%" in (parsed.netloc or ""):
            findings.append(Finding(
                code="URL_OBFUSCATION_PERCENT_ENCODING",
                severity="medium",
                description=f"Excessive percent-encoding ({len(percent_encodings)} instances) detected, potentially masking the true destination.",
                critical=False
            ))

        # Check for '@' symbol in netloc/authority (userinfo trick)
        if "@" in parsed.netloc:
            findings.append(Finding(
                code="SUSPICIOUS_USERINFO_AT_SYMBOL",
                severity="high",
                description="The URL authority contains an '@' symbol, which can mislead users about the actual destination server.",
                critical=False
            ))

        # Check for multiple embedded protocol schemes in path or query
        url_without_scheme = raw_url[len(scheme) + 3:]
        embedded_schemes = re.findall(r"(?:https?|ftp|file)://", url_without_scheme, re.IGNORECASE)
        if len(embedded_schemes) > 0:
            findings.append(Finding(
                code="MULTIPLE_EMBEDDED_SCHEMES",
                severity="medium",
                description="URL contains nested or embedded protocol schemes (e.g. redirector parameters or open proxy patterns).",
                critical=False
            ))

        # Known shortener detection
        extracted = tldextract.extract(hostname)
        reg_domain = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.domain and extracted.suffix else hostname.lower()

        if reg_domain in KNOWN_SHORTENERS or hostname.lower() in KNOWN_SHORTENERS:
            findings.append(Finding(
                code="URL_SHORTENER_DETECTED",
                severity="medium",
                description=f"The URL uses a known shortening service ({reg_domain}), hiding the final destination.",
                critical=False,
                details={"shortener_domain": reg_domain}
            ))

        return findings


url_analyzer = URLAnalyzer()
