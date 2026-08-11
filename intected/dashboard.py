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
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

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

    @app.post("/api/commands/{command_id}/run")
    def api_command_run(command_id: int,
                        token: str | None = Query(None),
                        x_intected_token: str | None = Header(None),
                        authorization: str | None = Header(None),
                        origin: str | None = Header(None)):
        """Run ONE queued command through the Supervisor gate. Evidence is
        persisted (raw output + parsed facts); state -> ran."""
        if not _authorized(x_intected_token or token, origin or authorization):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        conn = _open()
        try:
            row = conn.execute("SELECT * FROM commands WHERE id=?",
                               (command_id,)).fetchone()
            if row is None:
                return JSONResponse({"error": "no such command"}, status_code=404)
            if row["state"] not in ("proposed", "approved"):
                return JSONResponse(
                    {"error": f"state {row['state']} is not runnable"},
                    status_code=409)
            # safe-mode: dashboard NEVER runs exploitation tools
            _cmd_lower = (row["cmd"] or "").lower()
            _exploitation_indicators = [
                "sqlmap", "msfconsole", "msfvenom", "john", "hashcat",
                "hydra", "medusa", "ncrack", "beef", "searchsploit",
            ]
            if any(ind in _cmd_lower for ind in _exploitation_indicators):
                return JSONResponse(
                    {"error": "active exploitation blocked — "
                     "dashboard is locked to recon-only tools",
                     "state": "rejected"}, status_code=422)
            mission = db.get_mission(conn, row["mission_id"])
            hosts = json.loads(mission["allowed_hosts_json"] or "[]")
            # supervisor gate (Agent 1): scope + aggression
            try:
                from .scope import check_command
                check_command(row["cmd"], hosts)
            except Exception as exc:
                db.update_command_state(conn, command_id, "rejected", exc=exc)
                return JSONResponse(
                    {"error": f"supervisor rejected: {exc}",
                     "state": "rejected"}, status_code=422)
            # execute (operator-gated, bounded, real-time capture)
            from .tools import execute_raw
            result = execute_raw(row["cmd"], timeout=600)
            output = result.get("log", "")
            # persist evidence + facts
            from .cli import _persist_run
            facts_added, evidence_ref = _persist_run(
                conn, row["mission_id"], row["tool"] or "cli", "raw", output)
            db.update_command_state(conn, command_id, "ran",
                                    exit_code=result.get("exit"),
                                    output_ref=evidence_ref)
            db.log_audit(conn, "dashboard", "command.run",
                         f"cmd={command_id} exit={result.get('exit')} "
                         f"facts={facts_added} ref={evidence_ref}")
        finally:
            conn.close()
        return {
            "command_id": command_id,
            "state": "ran",
            "exit_code": result.get("exit"),
            "elapsed_s": result.get("elapsed_s"),
            "facts_added": facts_added,
            "evidence_ref": evidence_ref,
            "output_head": output[:1200],
        }

    @app.post("/api/missions/{mission_id}/commands/run-all")
    def api_commands_run_all(mission_id: int,
                             token: str | None = Query(None),
                             x_intected_token: str | None = Header(None),
                             authorization: str | None = Header(None),
                             origin: str | None = Header(None)):
        """Run ALL runnable queued commands for the mission (sequentially)."""
        if not _authorized(x_intected_token or token, origin or authorization):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        conn = _open()
        from .tools import execute_raw
        from .cli import _persist_run
        from .scope import check_command
        try:
            rows = conn.execute(
                "SELECT * FROM commands WHERE mission_id=? AND state IN "
                "('proposed','approved') ORDER BY id", (mission_id,)).fetchall()
            if not rows:
                return {"mission_id": mission_id, "ran": 0, "results": [],
                        "note": "no runnable commands in the queue"}
            mission = db.get_mission(conn, mission_id)
            hosts = json.loads(mission["allowed_hosts_json"] or "[]")
            results = []
            for row in rows:
                try:
                    check_command(row["cmd"], hosts)
                except Exception as exc:
                    db.update_command_state(conn, row["id"], "rejected", exc=exc)
                    results.append({"command_id": row["id"], "state": "rejected",
                                    "reason": str(exc)})
                    continue
                result = execute_raw(row["cmd"], timeout=600)
                facts_added, evidence_ref = _persist_run(
                    conn, mission_id, row["tool"] or "cli", "raw",
                    result.get("log", ""))
                db.update_command_state(conn, row["id"], "ran",
                                        exit_code=result.get("exit"),
                                        output_ref=evidence_ref)
                db.log_audit(conn, "dashboard", "command.run_all",
                             f"cmd={row['id']} exit={result.get('exit')} "
                             f"facts={facts_added}")
                results.append({"command_id": row["id"], "state": "ran",
                                "exit_code": result.get("exit"),
                                "elapsed_s": result.get("elapsed_s"),
                                "facts_added": facts_added,
                                "evidence_ref": evidence_ref,
                                "output_head": (result.get("log") or "")[:400]})
            return {"mission_id": mission_id, "ran": len(results),
                    "results": results}
        finally:
            conn.close()

    @app.get("/api/missions/{mission_id}/plan")
    def api_plan(mission_id: int,
                 token: str | None = Query(None),
                 x_intected_token: str | None = Header(None),
                 origin: str | None = Header(None)):
        """Evidence graph + ranked attack plan (methodology 11/12)."""
        if not _authorized(token or x_intected_token, origin):
            raise HTTPException(status_code=401, detail="unauthorized")
        from .evidence import _default_target
        from .planner import plan_for_mission
        conn = _open()
        try:
            target = _default_target(conn, mission_id)
            if target is None:
                raise HTTPException(status_code=404, detail="mission not found")
            return plan_for_mission(conn, mission_id, target)
        finally:
            conn.close()

    @app.post("/api/missions/{mission_id}/plan/{rank}/run")
    def api_plan_run(mission_id: int, rank: str,
                     token: str | None = Query(None),
                     x_intected_token: str | None = Header(None),
                     authorization: str | None = Header(None),
                     origin: str | None = Header(None)):
        """Run ONE plan item's first command through the Supervisor gate.
        Evidence (raw output) + parsed facts are persisted, audit logged.
        `rank` matches the plan item either as "P5" or "5"."""
        if not _authorized(x_intected_token or token, origin or authorization):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        from .evidence import _default_target
        from .planner import plan_for_mission
        conn = _open()
        try:
            target = _default_target(conn, mission_id)
            if target is None:
                return JSONResponse({"error": "mission not found"},
                                    status_code=404)
            plan = plan_for_mission(conn, mission_id, target)
            item = next(
                (it for it in plan["plan"]["plan"]
                 if str(it["rank"]) == rank
                 or f"P{it['rank']}" == rank.upper()),
                None)
            if item is None:
                return JSONResponse(
                    {"error": f"no plan item with rank {rank}"},
                    status_code=404)
            cmds = item.get("commands") or []
            if not cmds:
                return JSONResponse(
                    {"error": f"plan item {rank} has no command to run"},
                    status_code=422)
            cmd, area = cmds[0], item["area"]
            # safe-mode: dashboard NEVER runs exploitation tools
            from .tools import SAFE_TOOLS as _safe_tools
            _cmd_lower = cmd.lower()
            _exploitation_indicators = [
                "sqlmap", "msfconsole", "msfvenom", "john", "hashcat",
                "hydra", "medusa", "ncrack", "beef", "searchsploit",
            ]
            if any(ind in _cmd_lower for ind in _exploitation_indicators):
                return JSONResponse(
                    {"error": "active exploitation blocked — "
                     "dashboard is locked to recon-only tools"},
                    status_code=422)
            # supervisor gate (Agent 1): scope + aggression
            mission = db.get_mission(conn, mission_id)
            hosts = json.loads(mission["allowed_hosts_json"] or "[]")
            try:
                from .scope import check_command
                check_command(cmd, hosts)
            except Exception as exc:
                return JSONResponse(
                    {"error": f"supervisor rejected: {exc}"},
                    status_code=422)
            # execute (operator-gated, bounded, real-time capture)
            from .tools import execute_raw
            result = execute_raw(cmd, timeout=600)
            output = result.get("log", "")
            # persist evidence + facts
            from .cli import _persist_run
            facts_added, evidence_ref = _persist_run(
                conn, mission_id, "plan", "raw", output)
            db.log_audit(conn, "dashboard", "plan.run",
                         f"rank={rank} cmd={cmd!r} exit={result.get('exit')} "
                         f"facts={facts_added} ref={evidence_ref}")
        finally:
            conn.close()
        return {
            "rank": rank,
            "area": area,
            "command": cmd,
            "exit_code": result.get("exit"),
            "elapsed_s": result.get("elapsed_s"),
            "facts_added": facts_added,
            "evidence_ref": evidence_ref,
            "output_head": output[:800],
        }

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

    @app.get("/api/missions/{mission_id}/report")
    def api_report(mission_id: int,
                   token: str | None = Query(None),
                   x_intected_token: str | None = Header(None),
                   origin: str | None = Header(None)):
        """SMB report: letter grade, plain-English summary, fix-it checklist."""
        if not _authorized(x_intected_token or token, origin):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        conn = _open()
        try:
            from .evidence import _default_target
            from .grading import compute_grade, _load_facts
            from .summary import generate_summary
            from .checklist import generate_checklist
            import json as _json
            target = _default_target(conn, mission_id) or f"mission-{mission_id}"
            grade = compute_grade(conn, mission_id, target)
            facts = _load_facts(conn, mission_id, target)
            summary = generate_summary(grade, facts)
            checklist = generate_checklist(grade, facts)
            html = _render_report_html(target, grade, summary, checklist, facts)
            return HTMLResponse(html)
        finally:
            conn.close()

    @app.post("/api/scan")
    def api_scan(domain: str = Query(...),
                 email: str | None = Query(None),
                 token: str | None = Query(None),
                 x_intected_token: str | None = Header(None),
                 origin: str | None = Header(None)):
        """One-click 'Scan My Business': domain → auto-mission → safe recon.

        The SMB user enters ONLY their domain name. RedAegis:
        1. Creates a mission auto-scoped to that domain
        2. Runs SAFE recon only (no exploitation — safe mode enforced)
        3. Returns the mission ID + report URL

        No CLI. No scope definition. No approve-command. Just a domain.
        """
        if not _authorized(x_intected_token or token, origin):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        import json as _json, re, time as _time
        from .scope import validate_target
        from .recon import run_recon
        conn = _open()
        try:
            # 1. validate + normalize the domain
            domain = domain.strip().lower()
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain):
                return JSONResponse(
                    {"error": f"invalid domain: {domain} — enter a domain like 'example.com'"},
                    status_code=422)
            # 2. create a mission with this domain as the single scope target
            name = f"SCAN-{domain}-{_time.strftime('%Y%m%d-%H%M%S')}"
            mid = db.create_mission(conn, name, [domain],
                                    scope={"auto_scanned": True, "email": email or ""})
            db.log_audit(conn, "dashboard", "scan.create",
                         f"domain={domain} mission={mid} auto-scanned")
            # 3. run SAFE recon against the domain
            stages = []
            try:
                data = run_recon(conn, mid, domain, operator_approved=True)
                stages = data.get("stages", [])
            except Exception as exc:
                db.log_audit(conn, "dashboard", "scan.error",
                             f"domain={domain} mission={mid} error={exc}")
            # 4. return the mission handle + report URL
            facts_count = conn.execute(
                "SELECT COUNT(*) FROM facts WHERE mission_id=?", (mid,)).fetchone()[0]
            report_url = f"/api/missions/{mid}/report?token={token}"
            return {
                "mission_id": mid,
                "mission_name": name,
                "domain": domain,
                "facts_found": facts_count,
                "stages_completed": len([s for s in stages if s.get("gate") == "approved"]),
                "report_url": report_url,
                "message": f"Scan of {domain} complete. {facts_count} facts found. View your report at {report_url}",
            }
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


# ── report HTML renderer (inside create_app so it's importable here) ──────────

def _render_report_html(target: str, grade, summary: str, checklist: list,
                         facts: dict[str, list]) -> str:
    """Return a self-contained HTML page for the SMB security report."""
    gra = grade
    dl_rows = "\n".join(
        f'<tr><td class="dd">{d["points"]} pts</td><td>{d["reason"]}</td></tr>'
        for d in gra.deductions
    ) or '<tr><td colspan="2">No risk deductions — clean scan</td></tr>'

    ch_rows = "\n".join(
        f'<div class="ch-item">'
        f'<strong>{c["priority"].upper()}</strong> — {c["title"]}<br>'
        f'<pre>{c["steps"]}</pre></div>'
        for c in checklist
    ) or '<p>No remediation steps needed.</p>'

    summary_paras = "\n".join(
        f"<p>{p}</p>" for p in summary.split("\n\n") if p.strip()
    )

    grade_color = {"A": "#2d6", "B": "#8c3", "C": "#db0",
                   "D": "#e80", "F": "#d22"}.get(gra.letter, "#888")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RedAegis Security Report — {target}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 720px;
         margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }}
  h1 {{ font-size: 24px; margin: 0; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
  .grade-card {{ text-align: center; margin: 30px 0; }}
  .grade-letter {{ font-size: 96px; font-weight: 800; color: {grade_color};
                   line-height: 1; }}
  .grade-score {{ font-size: 18px; color: #888; }}
  section {{ margin: 28px 0; }}
  section h2 {{ font-size: 16px; text-transform: uppercase; letter-spacing: 1px;
                color: #555; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
  .dd {{ text-align: right; font-weight: 600; color: #d22; width: 60px; }}
  .ch-item {{ margin: 12px 0; padding: 10px; background: #f7f7f7;
              border-left: 3px solid {grade_color}; font-size: 14px; }}
  .ch-item pre {{ margin: 6px 0 0; white-space: pre-wrap; font-size: 13px;
                  background: #fff; padding: 6px 8px; border-radius: 4px; }}
  footer {{ margin-top: 40px; font-size: 12px; color: #aaa; text-align: center; }}
  @media print {{ body {{ margin: 0; padding: 0; }} }}
</style>
</head>
<body>
  <h1>&#x25C8; RedAegis Security Report</h1>
  <p class="meta">Target: {target} &middot; {gra.fact_count} evidence facts &middot;
     Generated @timestamp@</p>
  <div class="grade-card">
    <div class="grade-letter">{gra.letter}</div>
    <div class="grade-score">Security Score: {gra.score} / 100</div>
  </div>
  <section>
    <h2>Executive Summary</h2>
    {summary_paras}
  </section>
  <section>
    <h2>Risk Breakdown</h2>
    <table><tr><th>Deduction</th><th>Finding</th></tr>
    {dl_rows}</table>
  </section>
  <section>
    <h2>Checklist for Your IT Team</h2>
    {ch_rows}
  </section>
  <footer>
    RedAegis &mdash; AI Security Co-Pilot &middot; redaegis.io<br>
    This report is generated from automated scanning. For a full security
    assessment, consult a qualified security professional.
  </footer>
</body>
</html>"""
