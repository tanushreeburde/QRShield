from fastapi import APIRouter
from app.config import settings
from app.schemas.scan import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        version="1.0.0",
        app_env=settings.APP_ENV,
        configured_services={
            "safe_browsing_api": bool(settings.SAFE_BROWSING_API_KEY),
            "whois_lookup": settings.WHOIS_LOOKUP_ENABLED,
            "ocr_brand_detection": settings.OCR_ENABLED,
            "ssrf_guard": True,
            "rate_limiter": True,
            "sqlite_persistence": True
        }
    )
