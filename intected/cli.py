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
    conn = db.connect(config.db_path())
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
        # pentest-core integration state (P4) — probed, not assumed
        import os as _os
        from . import pentestcore
        pc_path = config.PENTEST_CORE_DB
        if _os.path.exists(pc_path):
            try:
                pc_conn = pentestcore.connect(pc_path)
                try:
                    s = pentestcore.stats(pc_conn)
                    sev = dict(sorted(s["by_severity"].items(),
                                      key=lambda kv: -kv[1]))
                    print(f"\npentest-core integration: OK ({pc_path})")
                    print(f"  runs={s['runs']} findings={s['findings']} "
                          f"severity={sev}")
                finally:
                    pc_conn.close()
            except Exception as exc:
                print(f"\npentest-core integration: ERROR ({exc})")
        else:
            print(f"\npentest-core integration: not configured "
                  f"(db not found at {pc_path}; set INTECTED_PENTEST_CORE_DB)")
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


def cmd_evidence(args) -> int:
    """Evidence graph for a mission (methodology 12) — structured per-target
    model: services, technologies, WAF indicators, attack surface."""
    import json as _json
    from .evidence import _default_target, build_evidence_graph
    conn = _open_db()
    try:
        target = args.target or _default_target(conn, args.mission) or f"mission-{args.mission}"
        graph = build_evidence_graph(conn, args.mission, target)
        print(_json.dumps(graph.to_dict(), indent=1, ensure_ascii=False))
        return EXIT_OK
    except Exception as exc:
        print(f"evidence error: {exc}", file=sys.stderr)
        return EXIT_ERR
    finally:
        conn.close()


def cmd_plan(args) -> int:
    """Attack plan for a mission (methodology 11) — evidence-based, ranked:
    every finding leads to a test hypothesis, every test is based on evidence."""
    from .evidence import _default_target
    from .planner import plan_for_mission
    conn = _open_db()
    try:
        target = args.target or _default_target(conn, args.mission) or f"mission-{args.mission}"
        data = plan_for_mission(conn, args.mission, target)
        graph, plan = data["graph"], data["plan"]
        print(f"TARGET : {plan['target']}")
        print(f"BRANCH : {plan['branch']}   (web_api | network)")
        print(f"STACK  : web={plan['stack']['web']} api={plan['stack']['api']} "
              f"graphql={plan['stack']['graphql']} jwt={plan['stack']['jwt']} "
              f"network={plan['stack']['network']}")
        print(f"SERVICES: " + ", ".join(
            f"{s['port']}/{s['protocol']}" + (f" {s['banner'][:28]}" if s['banner'] else "")
            for s in graph["services"]) or "none")
        print(f"TECH   : " + ", ".join(
            f"{t['name']} ({t['confidence']})" for t in graph["technologies"]) or "none")
        print(f"WAF    : {'detected' if graph['waf']['detected'] else 'no indicators'} "
              f"(conf {graph['waf']['confidence']}) {graph['waf']['evidence']}")
        print(f"SURFACE: " + ", ".join(graph["attack_surface"]) or "none")
        print()
        print("RANKED PLAN (every test is based on evidence):")
        for item in plan["plan"]:
            print(f"  P{item['rank']} {item['area']}")
            print(f"     why: {item['hypothesis']}")
            if item["commands"]:
                for c in item["commands"][:3]:
                    print(f"     cmd : {c}")
        return EXIT_OK
    except Exception as exc:
        print(f"plan error: {exc}", file=sys.stderr)
        return EXIT_ERR
    finally:
        conn.close()


def cmd_run(args) -> int:
    """Run a tool through the Supervisor gate (Agent 1): registry-only tools,
    scope-checked, rate-bounded, operator-approval required for full scans.
    The LLM/planner can never call this directly with raw bash."""
    import json as _json
    from .scope import ScopeViolation
    from .supervisor import validate_tool_call
    from .tools import ToolError, execute
    conn = _open_db()
    try:
        mission = db.get_mission(conn, args.mission)
        if mission is None:
            print(f"no such mission {args.mission}", file=sys.stderr)
            return EXIT_ERR
        import json as _j
        hosts = _j.loads(mission["allowed_hosts_json"] or "[]")
        params = {"target": args.target}
        if args.rate:
            params["rate"] = args.rate
        if args.ports:
            params["ports"] = args.ports
        try:
            validated = validate_tool_call(
                args.tool, params, hosts,
                operator_approved=args.operator_approved)
        except (ToolError, ScopeViolation, ValueError) as exc:
            print(f"SUPERVISOR BLOCKED: {exc}", file=sys.stderr)
            return EXIT_ERR
        print(f"supervisor: approved {validated['tool']} "
              f"params={validated['params']}")
        result = execute(args.tool, params)
        # persist raw output as evidence + parse into facts (durable results)
        facts_added, evidence_ref = _persist_run(conn, args.mission,
                                                 args.tool, args.target,
                                                 result.get("output", ""))
        result["facts_added"] = facts_added
        result["evidence_ref"] = evidence_ref
        if args.raw:
            print(result["output"])
        else:
            print(_json.dumps(
                {k: (v if k != "output" else v[:400] + ("…" if len(v) > 400 else ""))
                 for k, v in result.items()}, indent=1, ensure_ascii=False))
        return EXIT_OK
    finally:
        conn.close()


def _persist_run(conn, mission_id: int, tool: str, output: str,
                 *, target: str = "") -> tuple[int, str]:
    """Save raw output as evidence + parse into facts; returns (count, ref).
    Pass ``target=`` as keyword to scope facts to a specific host for
    per-target evidence filtering (v3 migration)."""
    import os as _os
    import tempfile as _tf
    from . import config
    from .parsing import EXTRACTORS, parse_tool_output
    if not output.strip():
        return 0, ""
    parser_tool = {"nmap_ports": "nmap", "nmap_services": "nmap"}.get(tool, tool)
    state = _os.path.join(config.state_dir(), "evidence", f"mission-{mission_id}")
    _os.makedirs(state, exist_ok=True)
    fd, raw_path = _tf.mkstemp(
        prefix=f"{tool}_{target.replace('/', '_')}_", suffix=".raw", dir=state)
    with _os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
        f.write(output)
    if parser_tool not in EXTRACTORS:
        return 0, _os.path.basename(raw_path)
    res = parse_tool_output(conn, mission_id, parser_tool, raw_path,
                            target=target)
    return len(res.get("facts", [])), _os.path.basename(raw_path)


def cmd_tools(args) -> int:
    """ToolConfigurator + ToolVersionValidator (addendum 7/8A):
    probe installed tool versions/flags (real, from THIS kali image) and
    show the enforced stealth safe-defaults."""
    from .tools import SAFE_DEFAULTS, probe_all_tools, probe_tool
    if args.action == "probe":
        tools = probe_all_tools() if not args.tool else {args.tool: probe_tool(args.tool)}
        for name, info in tools.items():
            print(f"== {name} ==")
            print(f"   {info}")
        return EXIT_OK
    print("SAFE DEFAULTS (supervisor-enforced, section 7):")
    for tool, cfg in SAFE_DEFAULTS.items():
        print(f"  {tool:<14} {cfg}")
    return EXIT_OK


def cmd_matrix(args) -> int:
    """Decision matrix (addendum 6): the next tool call for the footprint."""
    import json as _json
    from .evidence import _default_target, build_evidence_graph, stack_profile
    from .matrix import next_tool_call
    conn = _open_db()
    try:
        target = args.target or _default_target(conn, args.mission) or f"mission-{args.mission}"
        graph = build_evidence_graph(conn, args.mission, target)
        profile = stack_profile(graph)
        profile["waf_detected"] = graph.waf["detected"]
        call = next_tool_call(profile, graph.attack_surface, target,
                              services=graph.services)
        print(f"TARGET : {target}")
        print(f"STACK  : {_json.dumps({k: v for k, v in profile.items() if isinstance(v, bool)})}")
        print(f"WAF    : {graph.waf['detected']} (conf {graph.waf['confidence']})")
        if call:
            print(f"NEXT   : {call['tool']} params={call['params']}")
            print(f"WHY    : {call['why']}")
        else:
            print("NEXT   : none — footprint yields nothing actionable (no guessing)")
        return EXIT_OK
    finally:
        conn.close()


def cmd_wafkb(args) -> int:
    """WAF-bypass knowledge base (addendum 8C, local KB — no vector DB)."""
    from . import waf_kb
    if args.action == "seed":
        print(f"seeded: {waf_kb.seed_example()}")
        return EXIT_OK
    if args.action == "query":
        if not args.query:
            print("waf-kb query needs --query", file=sys.stderr)
            return EXIT_ERR
        results = waf_kb.query(args.query, top_k=args.top or 3)
        if not results:
            print("no KB matches — the AI gets NO WAF knowledge to invent from")
            return EXIT_OK
        for r in results:
            print(f"== {r['doc']} (score {r['score']}) ==")
            print(r["passage"][:500])
            print()
        return EXIT_OK
    print(waf_kb.summary())
    return EXIT_OK


def cmd_recon(args) -> int:
    """Phase 1 — gradual supervised recon (Agent 2): staged, gated, stealth."""
    import json as _json
    from .recon import run_recon
    conn = _open_db()
    try:
        data = run_recon(conn, args.mission, args.target,
                         stage=args.stage, force=args.force,
                         operator_approved=args.operator_approved)
        print(f"RECON target={data['target']}")
        for st in data["stages"]:
            if st.get("gate") == "BLOCKED":
                print(f"  ✗ {st['name']:<10} BLOCKED: {st.get('reason')}")
            elif st.get("gate") == "skipped":
                print(f"  – {st['name']:<10} skipped ({st.get('reason')})")
            else:
                print(f"  ✓ {st['name']:<10} approved · {st.get('facts', 0)} "
                      f"facts · exit {st.get('exit')}")
        return EXIT_OK
    except Exception as exc:
        print(f"recon blocked: {exc}", file=sys.stderr)
        return EXIT_ERR
    finally:
        conn.close()


def cmd_keys(args) -> int:
    """Secure key store (secrets vault): set/get/list/rm/import.

    Values are DPAPI-encrypted on Windows (bound to the current user) and are
    NEVER echoed — `get` masks to the last 4 chars unless --show is passed.
    """
    import sys as _sys
    import os as _os
    from .secrets import SecretsError, default_vault
    vault = default_vault()
    try:
        if args.action == "set":
            if not args.name:
                print("keys set requires --name", file=_sys.stderr)
                return EXIT_ERR
            if args.value is not None:
                value = args.value
            elif args.file:
                with open(args.file, "r", encoding="utf-8") as f:
                    value = f.read().strip()
                try:
                    import stat as _stat
                    mode = _stat.S_IMODE(_os.stat(args.file).st_mode)
                    if mode & 0o077:
                        print(f"WARNING: source file {args.file!r} is not "
                              f"0600-protected (mode {mode:o}) — keys should be "
                              "uploaded from a private file", file=_sys.stderr)
                except OSError:
                    pass
            elif args.stdin:
                value = _sys.stdin.read().strip()
            else:
                print("keys set requires one of --value, --file, --stdin",
                      file=_sys.stderr)
                return EXIT_ERR
            if args.delete_after and not args.file:
                print("--delete-after only applies with --file", file=_sys.stderr)
                return EXIT_ERR
            vault.set(args.name, value)
            db.log_audit(_open_db(), "cli", "keys.set",
                         f"name={args.name} source={'file' if args.file else
                         ('stdin' if args.stdin else 'arg')}")
            if args.delete_after:
                _os.remove(args.file)
                print(f"key {args.name!r} stored in encrypted vault; "
                      f"plaintext source removed")
            else:
                print(f"key {args.name!r} stored in encrypted vault "
                      f"(masked: {vault.masked(args.name)})")
            return EXIT_OK
        if args.action == "get":
            if not args.name:
                print("keys get requires --name", file=_sys.stderr)
                return EXIT_ERR
            if args.show:
                print(vault.get(args.name))
                db.log_audit(_open_db(), "cli", "keys.get_show",
                             f"name={args.name}")
            else:
                print(f"{args.name}: {vault.masked(args.name)} "
                      "(use --show for the full value)")
            return EXIT_OK
        if args.action == "list":
            entries = vault.list()
            if not entries:
                print("vault is empty")
                return EXIT_OK
            print(f"{'name':<24}{'hint':<10}created")
            for name in sorted(entries):
                e = entries[name]
                print(f"{name:<24}{'****' + e['hint']:<10}{e['created_at']}")
            return EXIT_OK
        if args.action == "rm":
            if not args.name:
                print("keys rm requires --name", file=_sys.stderr)
                return EXIT_ERR
            vault.remove(args.name)
            db.log_audit(_open_db(), "cli", "keys.rm", f"name={args.name}")
            print(f"key {args.name!r} removed")
            return EXIT_OK
        if args.action == "import":
            if not args.file:
                print("keys import requires --file <key=value lines>",
                      file=_sys.stderr)
                return EXIT_ERR
            count = 0
            with open(args.file, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        print(f"skip line {lineno}: no '=' (not key=value)",
                              file=_sys.stderr)
                        continue
                    name, _, value = line.partition("=")
                    name = name.strip()
                    if not name:
                        continue
                    vault.set(name, value)
                    count += 1
            db.log_audit(_open_db(), "cli", "keys.import",
                         f"file={args.file} keys={count}")
            if args.delete_after:
                _os.remove(args.file)
                print(f"imported {count} keys into the encrypted vault; "
                      "plaintext source removed")
            else:
                print(f"imported {count} keys into the encrypted vault "
                      f"(source kept: {args.file})")
            return EXIT_OK
    except SecretsError as exc:
        print(f"keys error: {exc}", file=_sys.stderr)
        return EXIT_ERR
    return EXIT_ERR


def cmd_pc(args) -> int:
    """pentest-core integration (P4): stats / sync run -> facts / gated write-back."""
    import os as _os
    from . import pentestcore
    pc_path = args.db or config.PENTEST_CORE_DB
    if not _os.path.exists(pc_path):
        print(f"pentest-core db not found: {pc_path}\n"
              "set INTECTED_PENTEST_CORE_DB to the real db path "
              "(e.g. \\\\wsl$\\...\\.pentest-core\\pentest.db or a backup copy).",
              file=sys.stderr)
        return EXIT_ERR
    pc_conn = pentestcore.connect(pc_path)
    try:
        if args.pc_action == "stats":
            s = pentestcore.stats(pc_conn)
            print(f"pentest-core db: {pc_path}")
            print(f"runs={s['runs']}  findings={s['findings']}")
            print("by severity: " + ", ".join(
                f"{k}={v}" for k, v in sorted(s["by_severity"].items(),
                                              key=lambda kv: -kv[1])))
            print("by engine:   " + ", ".join(
                f"{k}={v}" for k, v in s["by_engine"].items()))
            print("\nrecent runs:")
            for r in pentestcore.list_runs(pc_conn, limit=10):
                sev = ", ".join(f"{k}={v}" for k, v in sorted(
                    r["by_severity"].items(), key=lambda kv: -kv[1]))
                print(f"  {r['run_id']:<40} target={r['target']:<22} "
                      f"findings={r['findings']} ({sev})")
            return EXIT_OK

        conn = _open_db()
        if args.pc_action == "sync":
            if not args.run or args.mission is None:
                print("pc sync requires --run <run_id> and --mission <id>",
                      file=sys.stderr)
                return EXIT_ERR
            res = pentestcore.sync_run(conn, pc_conn, args.run, args.mission)
            print(f"synced run {res['run']} (target {res['target']}) into "
                  f"mission {args.mission}: {res['facts_added']} facts added, "
                  f"{res['skipped']} already present")
            return EXIT_OK
        if args.pc_action == "write":
            if not args.target or not args.engine or not args.severity or not args.title:
                print("pc write requires --target --engine --severity --title "
                      "(and --mission)", file=sys.stderr)
                return EXIT_ERR
            # explicit scope-gated write -> writable connection
            pc_conn.close()
            pc_conn = pentestcore.connect_rw(pc_path)
            fid = pentestcore.write_finding(
                pc_conn, conn, args.mission, args.target, args.engine,
                args.severity, args.title, port=args.port, path=args.path or "",
                detail=args.detail or "", cwe=[c.strip() for c in
                (args.cwe or "").split(",") if c.strip()],
                cve=[c.strip() for c in (args.cve or "").split(",") if c.strip()])
            print(f"finding {fid} written to pentest-core run "
                  f"{pentestcore.run_id_for(args.target)} (target {args.target}, "
                  f"engine {args.engine}, {args.severity})")
            return EXIT_OK
    except (pentestcore.PentestCoreError, ValueError, db.sqlite3.Error,
            db.sqlite3.OperationalError) as exc:
        print(f"pc error: {exc}", file=sys.stderr)
        return EXIT_ERR
    finally:
        pc_conn.close()
    return EXIT_ERR


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

    p = sub.add_parser("evidence", help="evidence graph for a mission (structured per-target model)")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--target", help="optional target override")
    p.set_defaults(fn=cmd_evidence)

    p = sub.add_parser("plan", help="evidence-based attack plan for a mission (ranked)")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--target", help="optional target override")
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("run", help="run a registered tool through the Supervisor gate")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--tool", required=True,
                   help="registered tool name (nmap_ports, nikto, http_headers, ...)")
    p.add_argument("--target", required=True)
    p.add_argument("--ports", help="port list or top1000/all")
    p.add_argument("--rate", type=int, help="packets/s (supervisor-capped)")
    p.add_argument("--operator-approved", action="store_true",
                   help="explicit operator approval (needed for full -p- scans)")
    p.add_argument("--raw", action="store_true", help="print raw tool output")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("tools", help="tool configurator/validator: safe defaults + live version probe")
    p.add_argument("action", choices=["defaults", "probe"])
    p.add_argument("--tool", help="probe one tool only")
    p.set_defaults(fn=cmd_tools)

    p = sub.add_parser("matrix", help="decision matrix: next tool call for the footprint")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--target", help="optional target override")
    p.set_defaults(fn=cmd_matrix)

    p = sub.add_parser("waf-kb", help="WAF-bypass knowledge base (local KB)")
    p.add_argument("action", choices=["seed", "query", "summary"])
    p.add_argument("--query", help="question (query action)")
    p.add_argument("--top", type=int, help="top_k passages (default 3)")
    p.set_defaults(fn=cmd_wafkb)

    p = sub.add_parser("recon", help="Phase 1: gradual supervised recon (staged, gated)")
    p.add_argument("--mission", type=int, required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--stage", choices=["ports", "services", "headers", "content"],
                   help="run a single stage only")
    p.add_argument("--force", action="store_true", help="re-run stages even with evidence")
    p.add_argument("--operator-approved", action="store_true")
    p.set_defaults(fn=cmd_recon)

    p = sub.add_parser("keys", help="secure key store (DPAPI vault): set/get/list/rm/import")
    p.add_argument("action", choices=["set", "get", "list", "rm", "import"],
                   help="set | get | list | rm | import")
    p.add_argument("--name", help="key name (required for set/get/rm)")
    p.add_argument("--value", help="key value (set; avoid — prefer --file/--stdin)")
    p.add_argument("--file", help="source file (set/import): key=value lines or single value")
    p.add_argument("--stdin", action="store_true", help="read the value from stdin (set)")
    p.add_argument("--show", action="store_true",
                   help="print the full value (get; default is masked)")
    p.add_argument("--delete-after", action="store_true",
                   help="delete the plaintext source file after successful import")
    p.set_defaults(fn=cmd_keys)

    p = sub.add_parser("pc", help="pentest-core integration (P4): stats/sync/write")
    p.add_argument("pc_action", choices=["stats", "sync", "write"],
                   help="stats | sync <run> | write <finding>")
    p.add_argument("--db", help="path to pentest-core pentest.db "
                                "(default: INTECTED_PENTEST_CORE_DB or ~/.pentest-core/pentest.db)")
    p.add_argument("--run", help="pentest-core run_id to sync (with sync)")
    p.add_argument("--mission", type=int, help="INTECTED mission id (with sync/write)")
    p.add_argument("--target", help="target host/IP:port (with write; scope-checked)")
    p.add_argument("--engine", help="engine name (with write)")
    p.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                   help="severity (with write)")
    p.add_argument("--title", help="finding title (with write)")
    p.add_argument("--port", type=int, help="port (with write)")
    p.add_argument("--path", help="path (with write)")
    p.add_argument("--detail", help="detail text (with write)")
    p.add_argument("--cwe", help="comma-separated CWE ids (with write)")
    p.add_argument("--cve", help="comma-separated CVE ids (with write)")
    p.set_defaults(fn=cmd_pc)

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
