"""FastAPI web dashboard for MedSecure security automation.

Provides an interactive UI for the full remediation workflow:
  CodeQL scan -> Triage -> Fix -> PR Review -> Merge -> Rescan
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
    description="Interactive vulnerability remediation with Devin AI",
    version="0.2.0",
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Include API routes
app.include_router(api_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Main dashboard with metrics and workflow overview."""
    return templates.TemplateResponse(request=request, name="dashboard.html")


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request) -> HTMLResponse:
    """CodeQL findings with triage and fix actions."""
    return templates.TemplateResponse(request=request, name="findings.html")


@app.get("/review", response_class=HTMLResponse)
async def review_page(request: Request) -> HTMLResponse:
    """PRs ready for review with comment and merge actions."""
    return templates.TemplateResponse(request=request, name="review.html")


@app.get("/activity", response_class=HTMLResponse)
async def activity_page(request: Request) -> HTMLResponse:
    """Activity log and notification center."""
    return templates.TemplateResponse(request=request, name="activity.html")
