from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class VerdictEnum(str, Enum):
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


class SeverityEnum(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    code: str
    severity: str
    description: str
    critical: bool = False
    details: Optional[dict] = None


class RedirectHop(BaseModel):
    hop: int
    url: str
    status_code: Optional[int] = None
    domain: Optional[str] = None
