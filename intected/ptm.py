"""PTM — Pentest Task Manager operations.

Higher-level task-tree ops on top of db.py, with the anti-loop guards that
prevent duplicate scans and re-proposing work on completed tasks.
"""

from . import db

# Fact-type priority for digest compaction (highest first — CVEs and
# injectable params survive compaction; low-value notes drop first).
FACT_PRIORITY = {"cve": 0, "param": 1, "port": 2, "version": 3, "service": 4,
                 "path": 5, "note": 6}


class TaskError(ValueError):
    """Invalid PTM operation."""


def propose_task(conn, mission_id: int, title: str, category: str = "general",
                 depends_on: list[int] | None = None, parent_id: int | None = None) -> int:
    return db.add_task(conn, mission_id, title, category,
                       parent_id=parent_id, depends_on=depends_on)


def _transition(conn, task_id: int, status: str, reason: str = "") -> None:
    if status not in db.TASK_STATUSES:
        raise TaskError(f"bad status {status!r}")
    db.set_task_status(conn, task_id, status)
    if reason:
        db.log_audit(conn, "ptm", f"task.{status}", f"task={task_id} reason={reason}")


def complete_task(conn, task_id: int, reason: str = "") -> None:
    _transition(conn, task_id, "completed", reason)


def fail_task(conn, task_id: int, reason: str = "") -> None:
    _transition(conn, task_id, "failed", reason)


def block_task(conn, task_id: int, reason: str) -> None:
    _transition(conn, task_id, "blocked", reason)


def get_task(conn, task_id: int) -> db.sqlite3.Row | None:
    return conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()


def task_status(conn, task_id: int) -> str | None:
    row = get_task(conn, task_id)
    return row["status"] if row else None


def unmet_deps(conn, task_id: int) -> list[int]:
    """Dep ids that are not completed — a task with unmet deps stays pending."""
    rows = conn.execute(
        "SELECT d.depends_on, t.status FROM task_deps d "
        "LEFT JOIN tasks t ON t.id = d.depends_on WHERE d.task_id=?",
        (task_id,),
    ).fetchall()
    return [r["depends_on"] for r in rows if r["status"] != "completed"]


def command_signature(cmd: str) -> str:
    """Normalize a command for duplicate detection (whitespace + case)."""
    return " ".join(cmd.strip().lower().split())


def duplicate_command(conn, mission_id: int, cmd: str) -> bool:
    """True if an identical command already exists in this mission (anti-loop)."""
    sig = command_signature(cmd)
    for row in conn.execute(
        "SELECT cmd FROM commands WHERE mission_id=? AND state IN "
        "('proposed','approved','ran')", (mission_id,),
    ).fetchall():
        if command_signature(row["cmd"]) == sig:
            return True
    return False


def next_objective(conn, mission_id: int):
    """Deterministic fallback: highest-priority pending task with no unmet deps."""
    for t in conn.execute(
        "SELECT * FROM tasks WHERE mission_id=? AND status='pending' "
        "ORDER BY priority, id", (mission_id,),
    ).fetchall():
        if not unmet_deps(conn, t["id"]):
            return t
    return None


def task_tree(conn, mission_id: int) -> list[dict]:
    """Nested task tree (children under parents) for digest/dashboard."""
    rows = db.get_tasks(conn, mission_id)
    nodes = {r["id"]: {"id": r["id"], "title": r["title"], "category": r["category"],
                       "status": r["status"], "priority": r["priority"],
                       "children": []} for r in rows}
    roots = []
    for r in rows:
        node = nodes[r["id"]]
        if r["parent_id"] and r["parent_id"] in nodes:
            nodes[r["parent_id"]]["children"].append(node)
        else:
            roots.append(node)
    return roots


def compact_facts(facts: list, limit: int = 30) -> list[dict]:
    """Compaction for the digest: priority-sorted, capped, deduped.

    Accepts sqlite3.Row facts (value_json string) or dict facts (value dict).
    cve/param facts survive first; low-value notes drop first.
    """
    import json as _json
    normalized = []
    for f in facts:
        if isinstance(f, dict):
            norm = {"fact_type": f["fact_type"], "value": f["value"]}
        else:  # sqlite3.Row
            norm = {"fact_type": f["fact_type"],
                    "value": _json.loads(f["value_json"])}
        # preserve row metadata (id/tool) when present, for digest display
        if isinstance(f, dict):
            for k in ("id", "tool"):
                if k in f:
                    norm[k] = f[k]
        else:
            for k in ("id", "tool"):
                if k in f.keys():
                    norm[k] = f[k]
        normalized.append(norm)
    ordered = sorted(normalized,
                     key=lambda f: FACT_PRIORITY.get(f["fact_type"], 9))
    seen = set()
    out = []
    for f in ordered:
        key = (f["fact_type"], str(sorted(f["value"].items())))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= limit:
            break
    return out
