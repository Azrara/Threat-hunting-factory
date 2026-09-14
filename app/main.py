"""Application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from . import hypotheses as hypothesis_service
from .ai.collector import schedule as collector_schedule
from .ai.config import ai_settings
from .attack import version as attack_version
from .database import SessionLocal, init_db
from .engine import catalog as catalog_registry
from .engine.catalog import validate_catalogue
from .engine.rules import statistics as rule_statistics
from .routers import admin, ai, auth, catalog, cti, hunts, reports, stats
from .seed import seed_demo

logger = logging.getLogger("thf")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    init_db()
    problems = validate_catalogue()
    if problems:
        logger.warning("Hypothesis catalogue problems: %s", problems)
    db = SessionLocal()
    try:
        # Published hypotheses live in the database. Loading them here means the
        # catalogue is complete before the first request rather than after it.
        hypothesis_service.refresh(db, force=True)
        if settings.seed_demo_data:
            seed_demo(db)
    finally:
        db.close()
    logger.info("Detection library loaded: %s", rule_statistics())
    if collector_schedule.start():
        logger.info(
            "Collector scheduled for weekday %s at %02d:00 UTC",
            ai_settings.collector_weekday, ai_settings.collector_hour,
        )
    yield
    collector_schedule.stop()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Hypothesis driven threat hunting automation, from evidence intake to reporting.",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(catalog.router)
app.include_router(hunts.router)
app.include_router(reports.router)
app.include_router(stats.router)
app.include_router(admin.router)
app.include_router(ai.router)
app.include_router(cti.router)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = exc.errors()
    cleaned = []
    for error in errors[:8]:
        field = ".".join(str(part) for part in error.get("loc", [])[1:]) or "request"
        cleaned.append({"field": field, "message": str(error.get("msg", "invalid value")),
                        "type": str(error.get("type", ""))})
    message = "The request could not be processed"
    if cleaned:
        first = cleaned[0]
        message = first["message"] if first["field"] == "request" else f"{first['field']}: {first['message']}"
    return JSONResponse(status_code=422, content={"detail": message, "errors": cleaned})


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "application": settings.app_name,
        "version": settings.app_version,
        "engine": rule_statistics(),
        "hypotheses": len(catalog_registry.all_hypotheses()),
        "attack_version": attack_version(),
    }


if settings.web_dir.exists():
    for mount in ("assets", "css", "js"):
        directory = settings.web_dir / mount
        # Git does not track empty directories, so a fresh clone can be missing
        # one. Creating it here means a missing optional directory cannot stop
        # the application from starting at all.
        directory.mkdir(parents=True, exist_ok=True)
        app.mount(f"/{mount}", StaticFiles(directory=directory), name=mount)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(settings.web_dir / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        """Serve the single page application for any unmatched route.

        API paths are excluded so that an unknown endpoint returns a proper
        404 rather than the HTML shell.
        """
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Unknown endpoint")
        candidate = settings.web_dir / path
        if path and candidate.is_file() and candidate.resolve().is_relative_to(settings.web_dir.resolve()):
            return FileResponse(candidate)
        return FileResponse(settings.web_dir / "index.html")
