"""Reasoning module — next-step engine on deepseek-v4-flash.

Flow (next_step):
  1. Build a compact mission digest (task tree + compacted facts + recent
     commands) — the LLM never sees the raw transcript.
  2. Ask the reasoning route (flash) for STRICT JSON:
       {"objective", "analysis", "task_updates": [...],
        "suggested_command": {tool, cmd, task_id?, rationale} | null,
        "open_questions": [...]}
  3. Apply task_updates through PTM ops (invalid ids/statuses skipped + warned).
  4. Scope-validate the suggested command via MissionScope; out-of-scope or
     duplicate commands are REJECTED (state recorded, never run).
  5. Completion guard: commands targeting a completed task are rejected.
  6. Persist the command + audit trail, return the structured result.

The router is injectable so tests stub the network boundary.
"""

import json
import re

from . import db, ptm, scope
from .router import Router

SYSTEM_PROMPT = """You are INTECTED, an AI co-pilot for authorized penetration tests.
You maintain a Pentest Task Tree and recommend the single best next step.

RULES (hard):
- Only use facts from the provided mission state. NEVER invent findings, ports, or versions.
- Suggested commands MUST target hosts inside the allowed scope list.
- A command is single-purpose: one tool, one objective.
- Destructive/aggressive operations (sqlmap --drop/--tamper, rm -rf, DROP) MUST be
  flagged with "aggressive": true in the command object.
- Phishing / MFA-bypass / EDR-evasion tools (gophish, evilginx2, syswhispers,
  pe-bearer) MUST be flagged aggressive:true AND surfaced in open_questions for
  explicit tester approval — never proposed as routine next steps.
- Only suggest tools listed in AVAILABLE TOOLS — a tool absent from that list is
  not installed and its command will be rejected.
- Never re-propose a command that a completed task already covers.
- Respond with STRICT JSON ONLY (no markdown fences, no commentary).
- Output in English.

JSON SCHEMA (respond exactly this shape):
{
  "objective": "<current objective title>",
  "analysis": "<1-2 sentence evidence-based analysis>",
  "task_updates": [
    {"task_id": <id>, "status": "pending|in_progress|completed|failed|blocked"},
    {"title": "<new task title>", "category": "<recon|scan|exploit|privesc|post|cleanup>", "depends_on": [<ids>]}
  ],
  "suggested_command": {
    "tool": "<tool name>", "cmd": "<exact shell command>",
    "task_id": <optional task id this advances>, "rationale": "<why>",
    "aggressive": false
  },
  "open_questions": ["<question for the human tester>"]
}
suggested_command may be null when no command should run next.

FEW-SHOT: NEGATIVE EXAMPLES (commands the SUPERVISOR rejects — never propose them):
1. "hydra -l admin -P rockyou.txt 10.0.0.5 ssh"
   REJECTED: brute-force tool not in the registry; mass credential attempts
   are banned by supervisor policy (no availability impact, no IDS bait).
2. "nmap -T5 -p- --min-rate 10000 10.0.0.5"
   REJECTED: aggressive timing/rate caps — -p- requires explicit operator
   approval and rates above the cap (300 pps) are always blocked.
3. "sqlmap -u http://target/item?id=1 --dump --batch"
   REJECTED: --dump extracts data (PII guard — GDPR/SOC2); the registry has
   no data-extraction path; SELECT version()-style proof only.
4. "nuclei -u http://target -tags unknown-fake-tag"
   REJECTED: hallucinated flag — nuclei tags must come from the live template
   set (intected tools probe shows real flags) or the NVD lookup.
5. "nikto -h http://10.0.0.99"   (when 10.0.0.99 is not in the scope)
   REJECTED: target outside the allowed scope — deny by default.

The pattern: every suggestion must be a REGISTERED tool, in-scope, rate-
bounded, evidence-based, and operator-approvable. When in doubt, propose
nothing (suggested_command: null) and ask the tester an open_question."""

_REPLY_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class ReasoningError(RuntimeError):
    """LLM reply could not be parsed / engine precondition failed."""


def _strip_fences(reply: str) -> str:
    m = _REPLY_RE.search(reply)
    return m.group(1).strip() if m else reply.strip()


def parse_plan_json(reply: str) -> dict:
    """Parse the model's STRICT-JSON reply; raise ReasoningError on garbage."""
    text = _strip_fences(reply)
    if not text:
        raise ReasoningError("empty model reply")
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as exc:
        # try to salvage a JSON object substring as a last resort
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                plan = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                raise ReasoningError(f"reply is not valid JSON: {exc}") from exc
        else:
            raise ReasoningError(f"reply is not valid JSON: {exc}") from exc
    if not isinstance(plan, dict):
        raise ReasoningError("reply JSON is not an object")
    return plan


def build_digest(conn, mission_id: int, max_facts: int = 30,
                 max_commands: int = 10) -> str:
    """Compact mission state for the reasoning LLM (bounded text)."""
    mission = db.get_mission(conn, mission_id)
    if mission is None:
        raise ReasoningError(f"mission {mission_id} not found")
    lines = [f"MISSION {mission['name']} (id={mission_id}) status={mission['status']}",
             f"ALLOWED SCOPE: {mission['allowed_hosts_json']}"]
    try:
        from . import arsenal
        lines.append(f"AVAILABLE TOOLS (live-probed): {arsenal.arsenal_summary()}")
    except Exception:  # noqa: BLE001 — arsenal probe must never break reasoning
        pass
    try:
        authz = json.loads(mission["authorizations_json"] or "[]")
    except (KeyError, TypeError, ValueError):
        authz = []
    lines.append(f"AUTHORIZED RISK CATEGORIES: {sorted(authz)}")
    try:
        from . import arsenal
        blocked = arsenal.blocked_categories(set(authz))
        if blocked:
            lines.append(f"BLOCKED TOOL CATEGORIES (commands rejected): {blocked}")
    except Exception:  # noqa: BLE001
        pass
    lines.append("TASK TREE:")
    nodes = ptm.task_tree(conn, mission_id)
    if not nodes:
        lines.append("  (no tasks yet — propose the first task)")
    for node in nodes:
        lines.append(f"  [{node['id']}] {node['status']:<10} {node['category']:<8} "
                     f"{node['title']}")
        for child in node["children"]:
            lines.append(f"    [{child['id']}] {child['status']:<10} "
                         f"{child['category']:<8} {child['title']}")
    facts = db.get_facts(conn, mission_id)
    # Drop scan-coverage noise (ZAP PASS rules etc.) before compaction: a PASS
    # level means "no issue found" — it belongs in the fact store, not in the
    # reasoning context, where it drowns the findings (verified live 2026-08-10:
    # 61/75 facts were PASS rules and the LLM degraded to prose on the bloat).
    def _is_pass_rule(f):
        v = f["value_json"] if not isinstance(f, dict) else f.get("value", {})
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                return False
        return isinstance(v, dict) and v.get("level") == "PASS"

    facts = [f for f in facts if not _is_pass_rule(f)]
    compacted = ptm.compact_facts(facts, limit=max_facts)
    lines.append(f"FACTS ({len(facts)} relevant, {len(compacted)} shown, evidence-linked):")
    for f in compacted:
        lines.append(f"  [{f['id']}] {f['tool']}/{f['fact_type']}: "
                     f"{json.dumps(f['value'], ensure_ascii=True)[:160]}")
    cmds = conn.execute(
        "SELECT id, tool, cmd, state FROM commands WHERE mission_id=? "
        "ORDER BY id DESC LIMIT ?", (mission_id, max_commands),
    ).fetchall()
    if cmds:
        lines.append(f"RECENT COMMANDS ({len(cmds)}):")
        for c in reversed(cmds):
            lines.append(f"  [{c['id']}] {c['state']:<9} {c['cmd'][:140]}")
    return "\n".join(lines)


class ReasoningEngine:
    def __init__(self, router: Router | None = None):
        self._router = router or Router()

    def next_step(self, conn, mission_id: int, user_input: str = "",
                  max_tokens: int = 4096) -> dict:
        """One reasoning turn: digest -> LLM -> apply updates -> validate cmd.

        max_tokens must be generous: deepseek-v4-flash runs a heavy thinking
        phase before emitting content (measured 4800-5200 chars of reasoning on
        a 15-fact digest); 1200 tokens left it finish=length with EMPTY content
        (verified live 2026-08-10).
        """
        digest = build_digest(conn, mission_id)
        user_msg = f"MISSION STATE:\n{digest}\n\n"
        if user_input:
            user_msg += f"TESTER INPUT: {user_input}\n\n"
        user_msg += "What is the next step? Reply STRICT JSON per schema."
        reply = None
        try:
            reply = self._router.chat(
                "reasoning",
                [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user_msg}],
                max_tokens=max_tokens,
            )
        except Exception as exc:  # RouteError and friends
            return {"ok": False, "error": f"LLM route failed: {exc}",
                    "task_updates_applied": [], "command": None}

        plan = None
        parse_error = None
        try:
            plan = parse_plan_json(reply)
        except ReasoningError as exc:
            parse_error = exc
        if plan is None:
            # One corrective retry: models occasionally emit prose instead of JSON.
            try:
                retry = self._router.chat(
                    "reasoning",
                    [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user_msg},
                     {"role": "assistant", "content": reply},
                     {"role": "user",
                      "content": "That reply was not valid JSON. Output ONLY the "
                                 "JSON object per the schema — no prose, no fences."}],
                    max_tokens=max_tokens,
                )
                plan = parse_plan_json(retry)
            except Exception as exc:  # ReasoningError or RouteError
                parse_error = exc
        if plan is None:
            return {"ok": False,
                    "error": f"unparsable model reply (after 1 retry): {parse_error}",
                    "task_updates_applied": [], "command": None,
                    "raw_reply": (reply or "")[:500]}

        applied = self._apply_task_updates(conn, mission_id, plan.get("task_updates", []))
        cmd_result = self._handle_command(conn, mission_id, plan.get("suggested_command"))
        db.log_audit(conn, "reasoning", "next_step",
                     f"objective={plan.get('objective', '')[:80]!r} "
                     f"updates={len(applied)} cmd_state={cmd_result['state']}")
        return {
            "ok": True,
            "objective": plan.get("objective", ""),
            "analysis": plan.get("analysis", ""),
            "open_questions": plan.get("open_questions", []),
            "task_updates_applied": applied,
            "command": cmd_result,
        }

    # -- internals -----------------------------------------------------------

    def _apply_task_updates(self, conn, mission_id: int, updates: list) -> list:
        applied = []
        for u in updates or []:
            if not isinstance(u, dict):
                continue
            if "task_id" in u:
                task_id = u["task_id"]
                status = u.get("status")
                if status not in db.TASK_STATUSES:
                    db.log_audit(conn, "reasoning", "update.skipped",
                                 f"bad status {status!r}")
                    continue
                if ptm.get_task(conn, task_id) is None:
                    db.log_audit(conn, "reasoning", "update.skipped",
                                 f"unknown task {task_id}")
                    continue
                try:
                    ptm._transition(conn, task_id, status)
                    applied.append(f"task {task_id} -> {status}")
                except ptm.TaskError:
                    continue
            elif "title" in u:
                # Model-invented FK guard (pitfall: depends_on ids are NOT
                # validated by db.add_task and would crash the task_deps
                # INSERT). Validate TYPE and ids — a non-list (5, "x") must not
                # crash either (control-review M1, verified live). Drop unknown
                # ones cleanly (never let an INSERT crash).
                raw_deps = u.get("depends_on")
                if not isinstance(raw_deps, list):
                    deps, hallucinated = [], raw_deps is not None
                else:
                    deps = [d for d in raw_deps if isinstance(d, int)
                            and ptm.get_task(conn, d) is not None]
                    hallucinated = len(deps) != len(raw_deps)
                if hallucinated:
                    db.log_audit(conn, "reasoning", "update.skipped",
                                 "model hallucinated depends_on ids — dropped "
                                 f"{u.get('depends_on')!r}")
                try:
                    tid = ptm.propose_task(
                        conn, mission_id, u["title"], u.get("category", "general"),
                        depends_on=deps,
                    )
                except (ptm.TaskError, db.sqlite3.IntegrityError) as exc:
                    db.log_audit(conn, "reasoning", "update.skipped",
                                 f"task insert failed: {exc}")
                    continue
                applied.append(f"created task {tid} ({u['title'][:50]})")
        return applied

    def _handle_command(self, conn, mission_id: int, cmd_spec) -> dict:
        if not cmd_spec:
            return {"state": "none", "cmd": None}
        if not isinstance(cmd_spec, dict) or not cmd_spec.get("cmd"):
            db.log_audit(conn, "reasoning", "command.skipped", "malformed cmd spec")
            return {"state": "rejected", "cmd": None, "reason": "malformed command spec"}
        cmd = cmd_spec["cmd"]
        mission = db.get_mission(conn, mission_id)
        allowed = json.loads(mission["allowed_hosts_json"])
        try:
            authz = json.loads(mission["authorizations_json"] or "[]")
        except (KeyError, TypeError, ValueError):
            authz = []
        task_id = cmd_spec.get("task_id")
        aggressive = cmd_spec.get("aggressive", False)

        # 1. completion guard: never advance a completed task; reject unknown ids
        if task_id is not None:
            status = ptm.task_status(conn, task_id)
            if status is None:
                return {"state": "rejected", "cmd": cmd, "task_id": task_id,
                        "reason": f"unknown task_id {task_id} (model hallucination)"}
            if status == "completed":
                return {"state": "rejected", "cmd": cmd, "task_id": task_id,
                        "reason": "target task already completed (anti-loop)"}
        # 2. duplicate guard: identical commands are refused
        if ptm.duplicate_command(conn, mission_id, cmd):
            return {"state": "rejected", "cmd": cmd,
                    "reason": "duplicate of an existing/previous command (anti-loop)"}
        # 3. scope gate: host tokens must be inside allowed scope AND gated
        #    tools need their risk category in the mission's authorizations
        try:
            scope.check_command(cmd, allowed, aggressive=aggressive is True,
                                authorizations=set(authz))
        except scope.ScopeViolation as exc:
            db.log_audit(conn, "reasoning", "command.rejected", str(exc))
            return {"state": "rejected", "cmd": cmd, "reason": str(exc)}
        # 4. persist
        cid = db.add_command(conn, mission_id, cmd,
                             tool=cmd_spec.get("tool"),
                             rationale=cmd_spec.get("rationale"),
                             task_id=task_id)
        return {"state": "approved", "cmd": cmd, "command_id": cid,
                "rationale": cmd_spec.get("rationale", "")}
