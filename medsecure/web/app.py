"""FastAPI web dashboard for MedSecure security automation.

Provides a browser-based UI to explore vulnerability identification,
mitigation, remediation phases and manage finding lifecycle.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from medsecure.web.api import router as api_router

logger = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).parent
_TEMPLATES_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"

app = FastAPI(
    title="MedSecure Security Dashboard",
    description="Vulnerability remediation tracking and Devin session management",
    version="0.1.0",
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Include API routes
app.include_router(api_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Serve the main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request) -> HTMLResponse:
    """Serve the findings portal page."""
    return templates.TemplateResponse("findings.html", {"request": request})


@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request) -> HTMLResponse:
    """Serve the sessions page."""
    return templates.TemplateResponse("sessions.html", {"request": request})


@app.get("/pipeline", response_class=HTMLResponse)
async def pipeline_page(request: Request) -> HTMLResponse:
    """Serve the pipeline view page."""
    return templates.TemplateResponse("pipeline.html", {"request": request})
