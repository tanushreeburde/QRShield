import urllib.parse
from typing import List, Tuple, Set, Optional
import httpx
import tldextract
from app.config import settings
from app.schemas.common import Finding, RedirectHop
from app.security.ssrf_guard import validate_url_for_ssrf, SSRFBlockedException


class RedirectTracker:
    def __init__(
        self,
        max_hops: int = settings.MAX_REDIRECT_HOPS,
        connect_timeout: float = settings.CONNECT_TIMEOUT_SECONDS,
        total_timeout: float = settings.REQUEST_TIMEOUT_SECONDS
    ):
        self.max_hops = max_hops
        self.connect_timeout = connect_timeout
        self.total_timeout = total_timeout

    def _get_domain(self, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            extracted = tldextract.extract(host)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
            return host.lower()
        except Exception:
            return ""

    async def track(self, start_url: str) -> Tuple[str, List[RedirectHop], List[Finding]]:
        hops: List[RedirectHop] = []
        findings: List[Finding] = []
        current_url = start_url
        seen_domains: Set[str] = set()
        seen_urls: Set[str] = set()
        saw_https = False

        headers = {
            "User-Agent": "QRShield-Analyzer/1.0 (Security Risk Analysis; +https://qrshield.local)"
        }
        timeout = httpx.Timeout(self.total_timeout, connect=self.connect_timeout)

        async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False) as client:
            for hop_idx in range(self.max_hops + 1):
                parsed = urllib.parse.urlparse(current_url)
                current_scheme = (parsed.scheme or "").lower()
                current_domain = self._get_domain(current_url)

                if current_scheme == "https":
                    saw_https = True
                elif saw_https and current_scheme == "http":
                    findings.append(Finding(
                        code="INSECURE_REDIRECT_HOP",
                        severity="medium",
                        description=f"Redirect chain downgraded from HTTPS to unencrypted HTTP at hop {hop_idx}.",
                        critical=False
                    ))

                if current_domain:
                    seen_domains.add(current_domain)

                # SSRF validation on EVERY hop
                try:
                    validate_url_for_ssrf(current_url)
                except SSRFBlockedException as ssrf_err:
                    hops.append(RedirectHop(
                        hop=hop_idx,
                        url=current_url,
                        status_code=None,
                        domain=current_domain
                    ))
                    findings.append(Finding(
                        code="SSRF_BLOCKED_HOP",
                        severity="high",
                        description=f"Outbound request blocked by SSRF guard at hop {hop_idx}: {ssrf_err.message}",
                        critical=True
                    ))
                    return current_url, hops, findings

                # Check redirect loop
                if current_url in seen_urls:
                    hops.append(RedirectHop(
                        hop=hop_idx,
                        url=current_url,
                        status_code=None,
                        domain=current_domain
                    ))
                    findings.append(Finding(
                        code="MAX_REDIRECTS_EXCEEDED",
                        severity="high",
                        description="Circular redirect loop detected.",
                        critical=False
                    ))
                    return current_url, hops, findings

                seen_urls.add(current_url)

                if hop_idx >= self.max_hops:
                    hops.append(RedirectHop(
                        hop=hop_idx,
                        url=current_url,
                        status_code=None,
                        domain=current_domain
                    ))
                    findings.append(Finding(
                        code="MAX_REDIRECTS_EXCEEDED",
                        severity="high",
                        description=f"Exceeded maximum allowed redirect hops ({self.max_hops}).",
                        critical=False
                    ))
                    return current_url, hops, findings

                # Perform manual HTTP GET or HEAD to inspect status code and Location header
                try:
                    response = await client.get(current_url, headers=headers)
                except httpx.ConnectTimeout:
                    hops.append(RedirectHop(hop=hop_idx, url=current_url, status_code=None, domain=current_domain))
                    findings.append(Finding(
                        code="DESTINATION_UNREACHABLE",
                        severity="medium",
                        description=f"Connection timed out reaching {current_url}.",
                        critical=False
                    ))
                    return current_url, hops, findings
                except (httpx.ConnectError, httpx.NetworkError) as conn_err:
                    hops.append(RedirectHop(hop=hop_idx, url=current_url, status_code=None, domain=current_domain))
                    findings.append(Finding(
                        code="DESTINATION_UNREACHABLE",
                        severity="medium",
                        description=f"Network connection failed: {conn_err}",
                        critical=False
                    ))
                    return current_url, hops, findings
                except httpx.InvalidURL as inv_err:
                    hops.append(RedirectHop(hop=hop_idx, url=current_url, status_code=None, domain=current_domain))
                    findings.append(Finding(
                        code="MALFORMED_URL",
                        severity="high",
                        description=f"Invalid redirect target URL: {inv_err}",
                        critical=False
                    ))
                    return current_url, hops, findings
                except Exception as tls_err:
                    hops.append(RedirectHop(hop=hop_idx, url=current_url, status_code=None, domain=current_domain))
                    err_str = str(tls_err)
                    if "certificate" in err_str.lower() or "ssl" in err_str.lower() or "tls" in err_str.lower():
                        findings.append(Finding(
                            code="TLS_ERROR",
                            severity="high",
                            description=f"TLS/SSL validation failed at hop {hop_idx}: {err_str}",
                            critical=False
                        ))
                    else:
                        findings.append(Finding(
                            code="DESTINATION_UNREACHABLE",
                            severity="medium",
                            description=f"Failed request to {current_url}: {err_str}",
                            critical=False
                        ))
                    return current_url, hops, findings

                hops.append(RedirectHop(
                    hop=hop_idx,
                    url=current_url,
                    status_code=response.status_code,
                    domain=current_domain
                ))

                # Check if response is a redirect (3xx)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = urllib.parse.urljoin(current_url, location)
                    current_url = next_url
                else:
                    # Terminal response reached
                    break

        if len(hops) > 3:
            findings.append(Finding(
                code="MULTIPLE_REDIRECTS",
                severity="low",
                description=f"The link traversed {len(hops) - 1} redirects before landing at destination.",
                critical=False,
                details={"hop_count": len(hops) - 1}
            ))

        if len(seen_domains) > 1:
            findings.append(Finding(
                code="REDIRECT_DOMAIN_CHANGE",
                severity="medium",
                description=f"The redirect path traversed multiple distinct domains ({', '.join(seen_domains)}).",
                critical=False,
                details={"domains": list(seen_domains)}
            ))

        return current_url, hops, findings


redirect_tracker = RedirectTracker()
