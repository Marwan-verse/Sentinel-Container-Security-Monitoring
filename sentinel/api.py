from contextlib import asynccontextmanager
import hmac
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .collectors import CollectorManager
from .config import DB_PATH, MODE, POLL_SECONDS
from .store import Store, utcnow
from . import explain as ai
from .runtime import FalcoEvent, ingest
from .scanning import ImageScanner


def create_app(store=None, start_collectors=True):
    database = store or Store(DB_PATH)
    scanner = ImageScanner(database)
    manager = CollectorManager(database, MODE, POLL_SECONDS, scanner=scanner)

    @asynccontextmanager
    async def lifespan(app):
        if start_collectors:
            manager.start()
        try:
            yield
        finally:
            if start_collectors:
                manager.close()
            scanner.close()

    app = FastAPI(title="Sentinel Container Monitor", version="0.2.0", lifespan=lifespan)
    app.state.store = database
    app.state.collectors = manager
    app.state.scanner = scanner

    @app.get("/api/health")
    def health():
        return {"status": "ok", "collectors": manager.health, "mode": manager.mode,
                "ai_enabled": ai.enabled(), "time": utcnow(),
                "runtime_enabled": bool(os.getenv("SENTINEL_FALCO_TOKEN")), "scanner_available": scanner.available()}

    @app.post("/api/runtime/falco")
    async def falco_event(request: Request):
        token = os.getenv("SENTINEL_FALCO_TOKEN", "")
        if not token:
            raise HTTPException(503, "Falco ingestion is disabled; configure SENTINEL_FALCO_TOKEN")
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(), f"Bearer {token}".encode()):
            raise HTTPException(401, "Invalid Falco bearer token")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 256 * 1024:
                raise HTTPException(413, "Falco event exceeds 256 KiB")
        try:
            event = FalcoEvent.model_validate(json.loads(body))
            return ingest(database, event)
        except (ValidationError, ValueError) as exc:
            # Validation errors can contain original input, including secrets.
            message = "Invalid Falco event" if isinstance(exc, ValidationError) else str(exc)
            if isinstance(exc, json.JSONDecodeError):
                message = "Invalid JSON"
            raise HTTPException(422, message) from exc

    @app.get("/api/history/{key:path}")
    def history(key: str, limit: int = Query(50, ge=1, le=200), before: int | None = Query(None, ge=1)):
        if not database.container(key):
            raise HTTPException(404, "Container not found")
        return database.configuration_history(key, limit=limit, before=before)

    @app.get("/api/incidents")
    def incidents(status: str | None = Query(None, pattern="^(open|acknowledged|resolved)$"), key: str | None = None):
        return database.incidents(status=status, key=key)

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: int, limit: int = Query(200, ge=1, le=500), before: int | None = Query(None, ge=1)):
        result = database.incident(incident_id, limit=limit, before=before)
        if not result:
            raise HTTPException(404, "Incident not found")
        return result

    @app.post("/api/incidents/{incident_id}/status")
    def incident_status(incident_id: int, status: str = Query(pattern="^(open|acknowledged|resolved)$")):
        if not database.set_incident_status(incident_id, status):
            raise HTTPException(404, "Incident not found")
        return {"id": incident_id, "status": status}

    @app.post("/api/scans/{key:path}", status_code=202)
    def scan_images(key: str, force: bool = False):
        item = database.container(key)
        if not item:
            raise HTTPException(404, "Container not found")
        try:
            return scanner.request(item, force=force)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/summary")
    def summary():
        return database.summary()

    @app.get("/api/containers")
    def containers():
        return database.containers()

    @app.get("/api/containers/{key:path}")
    def container(key: str):
        item = database.container(key)
        if not item:
            raise HTTPException(404, "Container not found")
        return {**item, "alerts": database.alerts(key=key), "events": database.events(key=key),
                "samples": database.recent_samples(key, 60), "history": database.configuration_history(key),
                "incidents": database.incidents(key=key), "image_scans": scanner.results(item)}

    @app.get("/api/alerts")
    def alerts(status: str | None = Query(default=None, pattern="^(open|acknowledged|resolved)$")):
        return database.alerts(status=status)

    @app.post("/api/alerts/{alert_id}/status")
    def set_alert_status(alert_id: int, status: str = Query(pattern="^(open|acknowledged|resolved)$")):
        if not database.set_alert_status(alert_id, status):
            raise HTTPException(404, "Alert not found")
        return {"id": alert_id, "status": status}

    @app.post("/api/alerts/{alert_id}/explain")
    def explain_alert(alert_id: int):
        alert = database.alert_by_id(alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        if not ai.enabled():
            raise HTTPException(503, "AI explanations are disabled. Set OPENAI_API_KEY to enable them.")
        workload = database.container(alert["container_key"]) if alert["container_key"] else None
        events = database.events(10, alert["container_key"]) if alert["container_key"] else []
        try:
            explanation = ai.explain(alert, workload, events)
        except Exception as exc:
            raise HTTPException(502, f"Explanation service failed: {str(exc)[:150]}") from exc
        return {"alert_id": alert_id, "explanation": explanation}

    @app.get("/api/events")
    def events():
        return database.events()

    @app.get("/api/reports/incident", response_class=PlainTextResponse)
    def incident_report():
        alerts = database.alerts(limit=500, status="open")
        events = database.events(limit=50)
        lines = ["# Container security incident report", "", f"Generated: {utcnow()}", "",
                 f"Open alerts: {len(alerts)}", "", "## Findings", ""]
        if not alerts:
            lines.append("No open findings.")
        for alert in alerts:
            lines.extend([f"### {alert['severity'].upper()}: {alert['title']}", "",
                          f"Workload: {alert['container_key'] or 'unknown'}", "",
                          alert["description"], "", f"Action: {alert['recommendation']}", ""])
        lines.extend(["## Recent events", ""])
        for event in events:
            lines.append(f"- {event['occurred_at']} — {event['source']} — {event['message']}")
        return "\n".join(lines) + "\n"

    dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if (dist / "index.html").is_file() and (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            target = (dist / path).resolve()
            if path and target.is_relative_to(dist.resolve()) and target.is_file():
                return FileResponse(target)
            return FileResponse(dist / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        def frontend_missing():
            return PlainTextResponse("Dashboard not built. Run: cd frontend && npm install && npm run build. API docs: /docs")

    return app


app = create_app()
