"""INTECTED CLI skeleton (P0).

Usage:
  python -m intected.cli init   --name ENG-1 --targets 10.0.0.5,dvwa.local --auth-ref AUTH-2026-001
  python -m intected.cli status [--mission N]
  python -m intected.cli task   --mission N --add "Scan web on :8080" --category recon
  python -m intected.cli paste  --mission N --tool nmap --file out.xml   # P1: parsing
  python -m intected.cli next   --mission N                               # P2: reasoning
  python -m intected.cli router-check
  python -m intected.cli audit  [--limit N]
"""

import argparse
import sys

from . import __version__, config, db, scope

EXIT_OK = 0
EXIT_ERR = 1


def _open_db() -> db.sqlite3.Connection:
    conn = db.connect(config.DB_PATH)
    db.init_db(conn)
    return conn


def cmd_init(args) -> int:
    conn = _open_db()
    hosts = [h.strip() for h in args.targets.split(",") if h.strip()]
    authz = [a.strip().lower() for a in (args.authz or "").split(",") if a.strip()]
    mission_id = db.create_mission(conn, args.name, hosts, auth_ref=args.auth_ref,
                                   authorizations=authz)
    print(f"mission created: id={mission_id} name={args.name!r} "
          f"hosts={hosts} auth_ref={args.auth_ref!r} "
          f"authorizations={authz}")
    print(f"db: {config.DB_PATH}")
    return EXIT_OK


def cmd_status(args) -> int:
    conn = _open_db()
    missions = db.list_missions(conn)
    if args.mission is None:
        for m in missions:
            print(f"#{m['id']:>3}  {m['status']:<7} {m['name']:<24} "
                  f"created={m['created_at']} auth_ref={m['auth_ref']}")
        return EXIT_OK
    mission = db.get_mission(conn, args.mission)
    if mission is None:
        print(f"mission {args.mission} not found", file=sys.stderr)
        return EXIT_ERR
    print(f"mission #{mission['id']}: {mission['name']} [{mission['status']}] "
          f"auth_ref={mission['auth_ref']}")
    print(f"  allowed hosts: {mission['allowed_hosts_json']}")
    tasks = db.get_tasks(conn, args.mission)
    if not tasks:
        print("  (no tasks yet)")
    for t in tasks:
        indent = "  " if t["parent_id"] else ""
        print(f"  {indent}[{t['id']:>3}] {t['status']:<10} "
              f"{t['category']:<10} {t['title']}")
    facts = db.get_facts(conn, args.mission)
    if facts:
        print(f"  facts: {len(facts)}")
        for f in facts[-8:]:
            print(f"    - {f['tool']}/{f['fact_type']}: {f['value_json'][:90]}")
    return EXIT_OK


def cmd_task(args) -> int:
    conn = _open_db()
    if args.add:
        task_id = db.add_task(conn, args.mission, args.add, args.category)
        print(f"task created: id={task_id}")
        return EXIT_OK
    if args.status:
        db.set_task_status(conn, args.task, args.status)
        print(f"task {args.task} -> {args.status}")
        return EXIT_OK
    print("task: pass --add 'title' --category X  or  --task N --status <s>")
    return EXIT_ERR


def cmd_paste(args) -> int:
    """Store raw output as evidence, then parse it into DB facts (P1)."""
    import os
    conn = _open_db()
    if not os.path.exists(args.file):
        print(f"file not found: {args.file}", file=sys.stderr)
        return EXIT_ERR
    raw = open(args.file, "rb").read()
    from .parsing import parse_tool_output, store_evidence
    ev_path, sha = store_evidence(args.mission, args.tool, raw, config.EVIDENCE_DIR)
    print(f"evidence stored: {ev_path}")
    print(f"sha256: {sha}  bytes: {len(raw)}")
    try:
        res = parse_tool_output(conn, args.mission, args.tool, ev_path)
    except Exception as exc:  # ParseError etc.
        db.log_audit(conn, "cli", "evidence.parse_error", f"tool={args.tool} err={exc}")
        print(f"parse error: {exc}", file=sys.stderr)
        return EXIT_ERR
    db.log_audit(conn, "cli", "evidence.parse",
                 f"tool={args.tool} facts={len(res['facts'])} "
                 f"warnings={len(res['warnings'])} sha256={sha[:16]}…")
    print(f"parsed {len(res['facts'])} facts into mission {args.mission}")
    for w in res["warnings"][:5]:
        print(f"  ⚠ {w}")
    for fid in res["facts"][-8:]:
        row = conn.execute("SELECT tool, fact_type, value_json FROM facts WHERE id=?",
                           (fid,)).fetchone()
        print(f"  [{fid}] {row['fact_type']:<8} {row['value_json'][:100]}")
    return EXIT_OK


def cmd_next(args) -> int:
    """Next-step reasoning (P2): digest -> flash -> validated command."""
    import json as _json
    from .reasoning import ReasoningEngine
    conn = _open_db()
    if args.mission is None:
        missions = db.list_missions(conn)
        if not missions:
            print("no missions — create one with `intected init`", file=sys.stderr)
            return EXIT_ERR
        args.mission = missions[0]["id"]
    print(f"reasoning on mission {args.mission} (deepseek-v4-flash)…")
    res = ReasoningEngine().next_step(conn, args.mission, user_input=args.input or "")
    if not res.get("ok"):
        print(f"ERROR: {res.get('error')}", file=sys.stderr)
        if res.get("raw_reply"):
            print(f"raw reply: {res['raw_reply']}", file=sys.stderr)
        return EXIT_ERR
    print(f"objective: {res.get('objective')}")
    print(f"analysis : {res.get('analysis')}")
    for a in res.get("task_updates_applied", []):
        print(f"  ✔ {a}")
    cmd = res.get("command") or {}
    if cmd.get("state") == "approved":
        print(f"command APPROVED (id={cmd.get('command_id')}):")
        print(f"  {cmd['cmd']}")
        if cmd.get("rationale"):
            print(f"  why: {cmd['rationale']}")
    elif cmd.get("state") == "rejected":
        print(f"command REJECTED: {cmd.get('reason')}")
        print(f"  (was: {cmd.get('cmd')})")
    else:
        print("no command suggested this turn")
    for q in res.get("open_questions", []):
        print(f"  ? {q}")
    return EXIT_OK


def cmd_digest(args) -> int:
    from .reasoning import ReasoningEngine, build_digest
    conn = _open_db()
    if args.mission is None:
        missions = db.list_missions(conn)
        if not missions:
            print("no missions", file=sys.stderr)
            return EXIT_ERR
        args.mission = missions[0]["id"]
    try:
        print(build_digest(conn, args.mission))
    except Exception as exc:
        print(f"digest error: {exc}", file=sys.stderr)
        return EXIT_ERR
    return EXIT_OK


def cmd_arsenal(args) -> int:
    """Catalog listing + real availability probe (no green-flag assumptions)."""
    from . import arsenal
    probe = arsenal.probe_arsenal(force=args.check or args.tool is not None)
    if args.tool:
        entry = next((e for e in arsenal.ARSENAL if e["name"] == args.tool), None)
        if entry is None:
            print(f"arsenal: unknown tool {args.tool!r} "
                  f"(known: {', '.join(e['name'] for e in arsenal.ARSENAL)})",
                  file=sys.stderr)
            return EXIT_ERR
        st = probe.get(entry["name"], "?")
        print(f"tool:      {entry['name']} [{st}]")
        print(f"phase:     {entry['phase']}")
        print(f"purpose:   {entry['purpose']}")
        print(f"host:      {entry['host']}")
        print(f"template:  {entry['template'] or '(none)'}")
        if entry["guardrail"]:
            print(f"guardrail: {entry['guardrail']}")
        return EXIT_OK
    print("INTECTED arsenal — live availability (probed, not assumed):")
    print(arsenal.format_arsenal_table(probe))
    return EXIT_OK


def cmd_router_check(args) -> int:
    from .router import router_check
    rows = router_check()
    print(f"{'task class':<18}{'model':<22}{'ok':<6}{'latency':<10}detail")
    for r in rows:
        lat = f"{r['latency_s']}s" if r["latency_s"] is not None else "-"
        print(f"{r['task_class']:<18}{r['model']:<22}{str(r['ok']):<6}{lat:<10}{r['detail']}")
    bad = [r for r in rows if not r["ok"]]
    if bad:
        print(f"\n{len(bad)} route(s) FAILED — see detail. "
              "(fallback chain still protects production calls)")
        return EXIT_ERR
    print("\nall routes OK")
    return EXIT_OK


def cmd_audit(args) -> int:
    conn = _open_db()
    for a in db.get_audit(conn, limit=args.limit):
        print(f"{a['ts']}  {a['actor']:<6} {a['action']:<20} {a['detail']}")
    return EXIT_OK


def cmd_dashboard(args) -> int:
    """Start the FastAPI dashboard (P3)."""
    from .dashboard import create_app, load_or_create_token
    token = load_or_create_token()
    port = args.port or 8765
    import uvicorn
    app = create_app(token=token)
    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"INTECTED dashboard: {url}")
    print(f"token file: {config.STATE_DIR}/dashboard.token  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="intected",
                                     description="INTECTED — PentestDROR co-pilot")
    parser.add_argument("--version", action="version", version=f"intected {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a mission with scope + auth ref")
    p.add_argument("--name", required=True)
    p.add_argument("--targets", required=True, help="comma-separated hosts/CIDRs")
    p.add_argument("--auth-ref", help="written-authorization reference (required for real ops)")
    p.add_argument("--authz", help="comma-separated risk categories authorized: "
                                   "phishing,c2,evasion,credential "
                                   "(tools in other categories are REJECTED)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("status", help="show missions / mission state")
    p.add_argument("--mission", type=int)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("task", help="PTM ops")
    p.add_argument("--mission", type=int)
    p.add_argument("--add", help="task title")
    p.add_argument("--category", default="general")
    p.add_argument("--task", type=int)
    p.add_argument("--status", choices=db.TASK_STATUSES)
    p.set_defaults(fn=cmd_task)

    p = sub.add_parser("paste", help="store raw tool output as evidence (P1 parses)")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--tool", required=True, choices=["nmap", "ffuf", "gobuster", "burp",
                                                     "nuclei", "sqlmap", "nikto",
                                                     "masscan", "other"])
    p.add_argument("--file", required=True)
    p.set_defaults(fn=cmd_paste)

    p = sub.add_parser("next", help="next-step reasoning (P2)")
    p.add_argument("--mission", type=int)
    p.add_argument("--input", help="optional tester note for the model")
    p.set_defaults(fn=cmd_next)

    p = sub.add_parser("digest", help="show compact mission state fed to the LLM")
    p.add_argument("--mission", type=int)
    p.set_defaults(fn=cmd_digest)

    p = sub.add_parser("dashboard", help="start the FastAPI dashboard (P3)")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(fn=cmd_dashboard)

    p = sub.add_parser("router-check", help="live latency probe of all LLM routes")
    p.set_defaults(fn=cmd_router_check)

    p = sub.add_parser("arsenal", help="tool arsenal: catalog + LIVE availability check")
    p.add_argument("--check", action="store_true",
                   help="probe every tool on its real host (kali WSL2 / docker)")
    p.add_argument("--tool", help="show one arsenal entry + its live status")
    p.set_defaults(fn=cmd_arsenal)

    p = sub.add_parser("audit", help="show audit log")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(fn=cmd_audit)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except scope.ScopeViolation as exc:
        print(f"SCOPE VIOLATION: {exc}", file=sys.stderr)
        return EXIT_ERR


if __name__ == "__main__":
    sys.exit(main())
