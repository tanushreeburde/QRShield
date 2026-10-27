from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from app.schemas.common import Finding, RedirectHop, VerdictEnum


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="The URL extracted from the QR code")
    claimed_brand_text: Optional[str] = Field(None, max_length=500, description="Optional brand context text")
    client_platform: Optional[str] = Field(None, max_length=64, description="Client platform e.g. windows, android")

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        lower = v.lower()
        if "://" in lower and not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("Unsupported scheme: only http:// and https:// URLs are supported")
        if not (lower.startswith("http://") or lower.startswith("https://")):
            v = "https://" + v
        return v



class ScanResponse(BaseModel):
    scan_id: str
    submitted_url: str
    final_url: Optional[str] = None
    verdict: VerdictEnum
    score: int
    redirect_chain: List[RedirectHop] = []
    evidence: List[Finding] = []
    unavailable_checks: List[str] = []
    disclaimers: List[str] = []
    analyzed_at: datetime


class ScanHistoryItem(BaseModel):
    id: str
    submitted_url: str
    final_url: Optional[str] = None
    verdict: VerdictEnum
    score: int
    client_platform: Optional[str] = None
    created_at: datetime
    evidence_count: int = 0
    redirect_count: int = 0


class HistoryResponse(BaseModel):
    total: int
    items: List[ScanHistoryItem]
    limit: int
    offset: int


class HealthResponse(BaseModel):
    status: str
    version: str
    app_env: str
    configured_services: dict


class ImageDecodeResponse(BaseModel):
    success: bool
    decoded_text: Optional[str] = None
    is_url: bool = False
    normalized_url: Optional[str] = None
    error: Optional[str] = None

