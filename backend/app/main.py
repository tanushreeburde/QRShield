from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder

from app.config import settings
from app.logging_config import setup_logging
from app.data.db import init_db
from app.api.routes_scan import router as scan_router
from app.api.routes_history import router as history_router
from app.api.routes_health import router as health_router

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    await init_db()
    yield
    # Shutdown logic if any


app = FastAPI(
    title="QRShield Security Analyzer",
    description="Multi-layered explainable risk analysis pipeline for QR codes and URLs.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for cross-origin or local client communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error_code": "VALIDATION_ERROR", "detail": jsonable_encoder(exc.errors())}
    )


# Mount API routes first
app.include_router(scan_router, prefix="/api/v1", tags=["Scan"])
app.include_router(history_router, prefix="/api/v1", tags=["History"])
app.include_router(health_router, prefix="/api/v1", tags=["Health"])

# Locate and mount frontend website directory
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"

if frontend_dir.exists() and (frontend_dir / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
else:
    @app.get("/")
    async def root():
        return {
            "service": "QRShield Security Risk Analyzer",
            "version": "1.0.0",
            "documentation": "/docs",
            "health": "/api/v1/health"
        }
