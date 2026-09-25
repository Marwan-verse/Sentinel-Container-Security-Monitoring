from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .collectors import CollectorManager
from .config import DB_PATH, MODE, POLL_SECONDS
from .store import Store, utcnow
from . import explain as ai


def create_app(store=None, start_collectors=True):
    database = store or Store(DB_PATH)
    manager = CollectorManager(database, MODE, POLL_SECONDS)

    @asynccontextmanager
    async def lifespan(app):
        if start_collectors:
            manager.start()
        yield
        if start_collectors:
            manager.close()

    app = FastAPI(title="Sentinel Container Monitor", version="0.1.0", lifespan=lifespan)
    app.state.store = database
    app.state.collectors = manager

    @app.get("/api/health")
    def health():
        return {"status": "ok", "collectors": manager.health, "mode": manager.mode,
                "ai_enabled": ai.enabled(), "time": utcnow()}

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
                "samples": database.recent_samples(key, 60)}

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
