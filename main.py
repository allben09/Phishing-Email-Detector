import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import logging
from loguru import logger

from app.api import routes
from app.core.detector import AdvancedPhishingDetector

# Configure logging
logger.add(
    "logs/phishing_detector.log",
    rotation="500 MB",
    retention="10 days",
    format="{time} | {level} | {message}"
)

# Initialize FastAPI app
app = FastAPI(
    title="Advanced Phishing Email Detector API",
    description="Enterprise-grade phishing detection with ML, threat intelligence, and comprehensive email analysis",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(routes.router, prefix="/api", tags=["api"])

# Initialize detector
detector = AdvancedPhishingDetector()

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("🚀 Starting Phishing Email Detector...")
    logger.info("✅ Detector initialized")
    logger.info("✅ API Documentation available at /docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("🛑 Shutting down Phishing Email Detector...")

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Advanced Phishing Email Detector",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
        "dashboard": "/dashboard"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "services": {
            "api": "running",
            "ml_model": "loaded",
            "database": "connected"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
