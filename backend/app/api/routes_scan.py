import uuid
from datetime import datetime, timezone
import urllib.parse
from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from app.data.db import get_db
from app.data.models import ScanRecord, FindingRecord, RedirectHopRecord
from app.schemas.scan import ScanRequest, ScanResponse, ImageDecodeResponse
from app.security.rate_limiter import rate_limiter
from app.analysis.url_analyzer import url_analyzer
from app.analysis.redirect_tracker import redirect_tracker
from app.analysis.domain_analyzer import domain_analyzer
from app.analysis.lookalike_detector import lookalike_detector
from app.analysis.webpage_analyzer import webpage_analyzer
from app.analysis.brand_context import brand_context_analyzer
from app.analysis.reputation_client import reputation_client
from app.analysis.risk_engine import risk_engine
from app.analysis.qr_decoder import qr_decoder

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_url(
    scan_req: ScanRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    # 1. Rate limiting by client IP
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Please retry after {retry_after} seconds."
        )

    url_str = scan_req.url.strip()
    all_findings = []
    all_unavailable = []

    # 2. Local URL Analyzer
    url_findings = url_analyzer.analyze(url_str)
    all_findings.extend(url_findings)

    # 3. Redirect Tracker (hop-by-hop with SSRF validation on every step)
    final_url, redirect_hops, redirect_findings = await redirect_tracker.track(url_str)
    all_findings.extend(redirect_findings)

    # Check if SSRF or network failure aborted tracking
    is_blocked_ssrf = any(f.code == "SSRF_BLOCKED_HOP" for f in redirect_findings)
    is_unreachable = any(f.code == "DESTINATION_UNREACHABLE" for f in redirect_findings)

    submitted_parsed = urllib.parse.urlparse(url_str)
    submitted_hostname = submitted_parsed.hostname or ""

    final_parsed = urllib.parse.urlparse(final_url)
    final_hostname = final_parsed.hostname or ""

    # 4. Domain Analyzer & Best-effort WHOIS
    domain_findings, domain_unav = await domain_analyzer.analyze(final_hostname)
    all_findings.extend(domain_findings)
    all_unavailable.extend(domain_unav)

    # 5. Lookalike & Homoglyph Detector (check both submitted and final host)
    hostnames_to_check = {final_hostname}
    if submitted_hostname:
        hostnames_to_check.add(submitted_hostname)

    for h in hostnames_to_check:
        lookalike_findings = lookalike_detector.analyze(h)
        all_findings.extend(lookalike_findings)

    # 6. Webpage Analyzer (only if destination is reachable and not SSRF blocked)
    if not is_blocked_ssrf and not is_unreachable:
        webpage_findings = await webpage_analyzer.analyze(final_url)
        all_findings.extend(webpage_findings)
    else:
        all_unavailable.append("webpage_content")

    # 7. Brand / Context Analyzer
    brand_findings = brand_context_analyzer.analyze(scan_req.claimed_brand_text, final_hostname)
    all_findings.extend(brand_findings)

    # 8. Reputation Client (optional, key-gated)
    rep_findings, rep_unav = await reputation_client.check_url(final_url)
    all_findings.extend(rep_findings)
    all_unavailable.extend(rep_unav)

    # 9. Risk Engine evaluation
    verdict, score, evidence, disclaimers = risk_engine.evaluate(
        findings=all_findings,
        unavailable_checks=all_unavailable
    )

    # 10. Persistence (SQLite via SQLAlchemy, metadata only)
    scan_id = str(uuid.uuid4())
    analyzed_at = datetime.now(timezone.utc)

    scan_record = ScanRecord(
        id=scan_id,
        submitted_url=url_str,
        final_url=final_url,
        verdict=verdict.value,
        score=score,
        client_platform=scan_req.client_platform,
        created_at=analyzed_at
    )
    db.add(scan_record)

    # Add findings records
    for ev in evidence:
        finding_rec = FindingRecord(
            scan_id=scan_id,
            code=ev.code,
            severity=ev.severity,
            description=ev.description
        )
        db.add(finding_rec)

    # Add redirect hops records
    for hop in redirect_hops:
        hop_rec = RedirectHopRecord(
            scan_id=scan_id,
            hop_index=hop.hop,
            url=hop.url,
            status_code=hop.status_code,
            domain=hop.domain
        )
        db.add(hop_rec)

    await db.commit()

    return ScanResponse(
        scan_id=scan_id,
        submitted_url=url_str,
        final_url=final_url,
        verdict=verdict,
        score=score,
        redirect_chain=redirect_hops,
        evidence=evidence,
        unavailable_checks=all_unavailable,
        disclaimers=disclaimers,
        analyzed_at=analyzed_at
    )


@router.post("/scan/decode-image", response_model=ImageDecodeResponse)
async def decode_qr_image(
    file: UploadFile = File(...),
):
    if not file:
        raise HTTPException(status_code=400, detail="No image file provided.")

    contents = await file.read()
    if not contents or len(contents) == 0:
        return ImageDecodeResponse(
            success=False,
            decoded_text=None,
            is_url=False,
            normalized_url=None,
            error="Uploaded file is empty."
        )

    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image exceeds maximum 10MB limit.")

    decoded_text, error = qr_decoder.decode_bytes(contents)
    if error or not decoded_text:
        return ImageDecodeResponse(
            success=False,
            decoded_text=None,
            is_url=False,
            normalized_url=None,
            error=error or "No readable QR code found in this image."
        )

    text = decoded_text.strip()
    is_url = False
    norm_url = None
    lower = text.lower()

    if lower.startswith("http://") or lower.startswith("https://"):
        is_url = True
        norm_url = text
    elif "." in text and " " not in text and "\n" not in text:
        is_url = True
        norm_url = "https://" + text

    return ImageDecodeResponse(
        success=True,
        decoded_text=text,
        is_url=is_url,
        normalized_url=norm_url,
        error=None
    )

