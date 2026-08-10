"""Dashboard — FastAPI backend + vanilla-JS SPA (P3).

Read-only views over the INTECTED state DB:
  GET /api/missions                       mission list
  GET /api/missions/{mid}                 mission bundle (tasks/facts/commands/audit/stats)
  GET /api/missions/{mid}/evidence/{fid}  raw evidence text + sha256 + verification
  GET /                                    SPA (static/)

Auth: bearer token via ?token= or X-INTECTED-Token header (constant-time compare),
plus an Origin allowlist for browser requests. Localhost-only by design.
"""

import json
import secrets
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from . import config, db
from .parsing import verify_evidence

STATIC_DIR = Path(__file__).parent / "static"
ALLOWED_ORIGINS = {
    "http://127.0.0.1:8765", "http://localhost:8765",
    "http://127.0.0.1:8000", "http://localhost:8000",
}


def load_or_create_token(state_dir: str = config.STATE_DIR) -> str:
    path = Path(state_dir) / "dashboard.token"
    if path.exists():
        token = path.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token)
    return token


def mission_bundle(conn, mission_id: int) -> dict:
    mission = db.get_mission(conn, mission_id)
    if mission is None:
        raise KeyError(mission_id)
    tasks = [dict(r) for r in db.get_tasks(conn, mission_id)]
    facts = [dict(r) for r in db.get_facts(conn, mission_id)]
    commands = [dict(r) for r in conn.execute(
        "SELECT * FROM commands WHERE mission_id=? ORDER BY id", (mission_id,)).fetchall()]
    audit = [dict(r) for r in db.get_audit(conn, limit=40)]
    task_counts = {}
    for t in tasks:
        task_counts[t["status"]] = task_counts.get(t["status"], 0) + 1
    fact_counts = {}
    for f in facts:
        fact_counts[f["fact_type"]] = fact_counts.get(f["fact_type"], 0) + 1
    cmd_counts = {}
    for c in commands:
        cmd_counts[c["state"]] = cmd_counts.get(c["state"], 0) + 1
    return {
        "mission": dict(mission),
        "tasks": tasks,
        "facts": facts,
        "commands": commands,
        "audit": audit,
        "stats": {"tasks": task_counts, "facts": fact_counts,
                  "commands": cmd_counts, "facts_total": len(facts)},
    }


def create_app(token: str | None = None,
               db_path: str = config.DB_PATH) -> FastAPI:
    app = FastAPI(title="INTECTED — PentestDROR co-pilot dashboard")
    app.state.token = token if token is not None else load_or_create_token()
    app.state.db_path = db_path

    def _open():
        conn = db.connect(app.state.db_path)
        db.init_db(conn)
        return conn

    def _authorized(token_value: str | None, origin: str | None) -> bool:
        if not token_value:
            return False
        if not secrets.compare_digest(token_value, app.state.token):
            return False
        if origin is not None and origin not in ALLOWED_ORIGINS:
            return False
        return True

    @app.get("/api/missions")
    def api_missions(token: str | None = Query(None),
                     x_intected_token: str | None = Header(None),
                     origin: str | None = Header(None)):
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        conn = _open()
        try:
            return [dict(r) for r in db.list_missions(conn)]
        finally:
            conn.close()

    @app.get("/api/missions/{mission_id}")
    def api_mission(mission_id: int,
                    token: str | None = Query(None),
                    x_intected_token: str | None = Header(None),
                    origin: str | None = Header(None)):
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        conn = _open()
        try:
            return mission_bundle(conn, mission_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="mission not found")
        finally:
            conn.close()

    @app.post("/api/missions/{mission_id}/targets")
    def api_add_target(mission_id: int, payload: dict,
                       token: str | None = Query(None),
                       x_intected_token: str | None = Header(None),
                       origin: str | None = Header(None)):
        """Add a validated target (IP / IP range / domain) to the mission scope."""
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        target = (payload.get("target") or "").strip()
        if not target:
            raise HTTPException(status_code=422, detail="target required")
        try:
            from .scope import validate_target
            normalized = validate_target(target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        conn = _open()
        try:
            hosts = db.add_mission_target(conn, mission_id, normalized)
        except KeyError:
            raise HTTPException(status_code=404, detail="mission not found")
        finally:
            conn.close()
        return {"mission_id": mission_id, "scope": hosts, "target": normalized}

    @app.delete("/api/missions/{mission_id}/targets")
    def api_remove_target(mission_id: int, target: str = Query(...),
                          token: str | None = Query(None),
                          x_intected_token: str | None = Header(None),
                          origin: str | None = Header(None)):
        """Remove a target from the mission scope."""
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        conn = _open()
        try:
            try:
                hosts = db.remove_mission_target(conn, mission_id, target.strip())
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            except KeyError:
                raise HTTPException(status_code=404, detail="mission not found")
        finally:
            conn.close()
        return {"mission_id": mission_id, "scope": hosts, "target": target.strip()}

    @app.post("/api/missions/{mission_id}/start")
    def api_start_test(mission_id: int,
                       token: str | None = Query(None),
                       x_intected_token: str | None = Header(None),
                       origin: str | None = Header(None)):
        """Start the test: create scan tasks for every scope target."""
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        conn = _open()
        try:
            try:
                targets, created, existing = db.start_mission_test(
                    conn, mission_id)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            except KeyError:
                raise HTTPException(status_code=404, detail="mission not found")
        finally:
            conn.close()
        return {"mission_id": mission_id, "targets": targets,
                "tasks_created": created, "tasks_existing": existing}

    @app.get("/api/missions/{mission_id}/evidence/{fact_id}")
    def api_evidence(mission_id: int, fact_id: int,
                     token: str | None = Query(None),
                     x_intected_token: str | None = Header(None),
                     origin: str | None = Header(None)):
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        conn = _open()
        try:
            fact = conn.execute(
                "SELECT * FROM facts WHERE id=? AND mission_id=?",
                (fact_id, mission_id)).fetchone()
            if fact is None or not fact["evidence_ref"]:
                raise HTTPException(status_code=404, detail="no evidence for fact")
            path = fact["evidence_ref"]
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                raise HTTPException(status_code=404, detail="evidence file missing")
            return JSONResponse({
                "fact_id": fact_id,
                "fact_type": fact["fact_type"],
                "value": json.loads(fact["value_json"]),
                "evidence_path": path,
                "sha256": fact["sha256"],
                "matches": bool(fact["sha256"] and
                                verify_evidence(path, fact["sha256"])),
                "content": content,
            })
        finally:
            conn.close()

    @app.get("/")
    def spa():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/app.js")
    def spa_js():
        return FileResponse(STATIC_DIR / "app.js", media_type="text/javascript")

    @app.get("/styles.css")
    def spa_css():
        return FileResponse(STATIC_DIR / "styles.css", media_type="text/css")

    return app
