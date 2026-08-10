"""SQLite persistence for INTECTED (PTM store + fact store + audit).

Schema mirrors the pentest-core pattern (runs/findings/audit) and the plan's
data model (§4). No ORM — stdlib sqlite3, parameterized queries only.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS missions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{}',
  allowed_hosts_json TEXT NOT NULL DEFAULT '[]',
  auth_ref TEXT,
  authorizations_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  closed_at TEXT
);
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  parent_id INTEGER REFERENCES tasks(id),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','in_progress','completed','failed','blocked')),
  priority INTEGER NOT NULL DEFAULT 5,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS task_deps(
  task_id INTEGER NOT NULL REFERENCES tasks(id),
  depends_on INTEGER NOT NULL REFERENCES tasks(id),
  PRIMARY KEY (task_id, depends_on)
);
CREATE TABLE IF NOT EXISTS facts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  task_id INTEGER REFERENCES tasks(id),
  tool TEXT NOT NULL,
  fact_type TEXT NOT NULL
    CHECK (fact_type IN ('port','service','version','path','param','cve','credential','note')),
  value_json TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 1.0,
  evidence_ref TEXT,
  sha256 TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS commands(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id INTEGER NOT NULL REFERENCES missions(id),
  task_id INTEGER REFERENCES tasks(id),
  tool TEXT,
  cmd TEXT NOT NULL,
  rationale TEXT,
  state TEXT NOT NULL DEFAULT 'proposed'
    CHECK (state IN ('proposed','approved','rejected','ran','failed')),
  exit_code INTEGER,
  output_ref TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
"""

TASK_STATUSES = ("pending", "in_progress", "completed", "failed", "blocked")
FACT_TYPES = ("port", "service", "version", "path", "param", "cve", "credential", "note")
COMMAND_STATES = ("proposed", "approved", "rejected", "ran", "failed")


def connect(db_path: str | os.PathLike) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Apply schema + version bookkeeping. Idempotent; migrates v1 -> v2."""
    conn.executescript(SCHEMA)
    # v1 -> v2 migration: missions.authorizations_json (risk-category gates)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(missions)")}
    if "authorizations_json" not in cols:
        conn.execute("ALTER TABLE missions ADD COLUMN "
                     "authorizations_json TEXT NOT NULL DEFAULT '[]'")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version(version) VALUES (?)",
                     (SCHEMA_VERSION,))
    elif row["version"] != SCHEMA_VERSION:
        conn.execute("UPDATE schema_version SET version=? WHERE version=?",
                     (SCHEMA_VERSION, row["version"]))
    conn.commit()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- Missions ---------------------------------------------------------------

def create_mission(conn, name: str, allowed_hosts: list[str],
                   auth_ref: str | None = None, scope: dict | None = None,
                   authorizations: list[str] | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO missions(name, scope_json, allowed_hosts_json, auth_ref, "
        "authorizations_json) VALUES (?,?,?,?,?)",
        (name, json.dumps(scope or {}), json.dumps(allowed_hosts), auth_ref,
         json.dumps(authorizations or [])),
    )
    conn.commit()
    log_audit(conn, "cli", "mission.create",
              f"name={name!r} hosts={allowed_hosts} "
              f"authz={authorizations or []}")
    return cur.lastrowid


def get_mission(conn, mission_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()


def add_mission_target(conn, mission_id: int, target: str) -> list[str]:
    """Append a validated target to a mission's allowed-hosts scope (deduped).

    Returns the updated scope list. The caller validates the target
    (scope.validate_target) BEFORE calling this.
    """
    mission = get_mission(conn, mission_id)
    if mission is None:
        raise KeyError(mission_id)
    hosts = json.loads(mission["allowed_hosts_json"] or "[]")
    if not isinstance(hosts, list):
        hosts = []
    if target not in hosts:
        hosts.append(target)
        conn.execute("UPDATE missions SET allowed_hosts_json=? WHERE id=?",
                     (json.dumps(hosts), mission_id))
        conn.commit()
        log_audit(conn, "dashboard", "mission.add_target",
                  f"mission={mission_id} target={target}")
    return hosts


def remove_mission_target(conn, mission_id: int, target: str) -> list[str]:
    """Remove a target from a mission's allowed-hosts scope.

    Returns the updated scope list. Raises ValueError if the target is not in
    the scope. Operator action — audited.
    """
    mission = get_mission(conn, mission_id)
    if mission is None:
        raise KeyError(mission_id)
    hosts = json.loads(mission["allowed_hosts_json"] or "[]")
    if not isinstance(hosts, list):
        hosts = []
    if target not in hosts:
        raise ValueError(f"target {target!r} is not in the mission scope")
    hosts = [h for h in hosts if h != target]
    conn.execute("UPDATE missions SET allowed_hosts_json=? WHERE id=?",
                 (json.dumps(hosts), mission_id))
    conn.commit()
    log_audit(conn, "dashboard", "mission.remove_target",
              f"mission={mission_id} target={target}")
    return hosts


def start_mission_test(conn, mission_id: int) -> tuple[list[str], int, int]:
    """Create scan tasks for every scope target (deduped by title).

    Returns (targets, created_count, existing_count) — existing are targets
    that already have their scan task. Raises ValueError if the mission has no
    targets. Only the dashboard/operator calls this — the reasoning engine
    never self-starts.
    """
    mission = get_mission(conn, mission_id)
    if mission is None:
        raise KeyError(mission_id)
    hosts = json.loads(mission["allowed_hosts_json"] or "[]")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("mission has no targets — add a target first")
    existing_titles = {r["title"] for r in get_tasks(conn, mission_id)}
    created = 0
    existing = 0
    for target in hosts:
        title = f"Run penetration test against {target}"
        if title in existing_titles:
            existing += 1
            continue
        add_task(conn, mission_id, title, "scan")
        created += 1
    log_audit(conn, "dashboard", "mission.start_test",
              f"mission={mission_id} targets={len(hosts)} "
              f"tasks_created={created} tasks_existing={existing}")
    return hosts, created, existing


def list_missions(conn) -> list[sqlite3.Row]:
    return conn.execute("SELECT id, name, status, created_at, auth_ref "
                        "FROM missions ORDER BY id DESC").fetchall()


# --- Tasks (PTM) ------------------------------------------------------------

def add_task(conn, mission_id: int, title: str, category: str,
             parent_id: int | None = None, priority: int = 5,
             depends_on: list[int] | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO tasks(mission_id, parent_id, category, title, priority) "
        "VALUES (?,?,?,?,?)",
        (mission_id, parent_id, category, title, priority),
    )
    task_id = cur.lastrowid
    for dep in depends_on or []:
        conn.execute("INSERT INTO task_deps(task_id, depends_on) VALUES (?,?)", (task_id, dep))
    conn.commit()
    log_audit(conn, "cli", "task.create", f"task={task_id} title={title!r}")
    return task_id


def set_task_status(conn, task_id: int, status: str) -> None:
    if status not in TASK_STATUSES:
        raise ValueError(f"bad status {status!r}; expected one of {TASK_STATUSES}")
    completed_at = now_iso() if status in ("completed", "failed") else None
    conn.execute(
        "UPDATE tasks SET status=?, updated_at=?, completed_at=? WHERE id=?",
        (status, now_iso(), completed_at, task_id),
    )
    conn.commit()
    log_audit(conn, "cli", "task.status", f"task={task_id} -> {status}")


def get_tasks(conn, mission_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM tasks WHERE mission_id=? ORDER BY priority, id", (mission_id,)
    ).fetchall()


# --- Facts ------------------------------------------------------------------

def add_fact(conn, mission_id: int, tool: str, fact_type: str, value: dict,
             evidence_ref: str | None = None, sha256: str | None = None,
             task_id: int | None = None, confidence: float = 1.0) -> int:
    if fact_type not in FACT_TYPES:
        raise ValueError(f"bad fact_type {fact_type!r}; expected one of {FACT_TYPES}")
    cur = conn.execute(
        "INSERT INTO facts(mission_id, task_id, tool, fact_type, value_json, "
        "confidence, evidence_ref, sha256) VALUES (?,?,?,?,?,?,?,?)",
        (mission_id, task_id, tool, fact_type, json.dumps(value),
         confidence, evidence_ref, sha256),
    )
    conn.commit()
    return cur.lastrowid


def get_facts(conn, mission_id: int, fact_type: str | None = None) -> list[sqlite3.Row]:
    if fact_type:
        return conn.execute(
            "SELECT * FROM facts WHERE mission_id=? AND fact_type=? ORDER BY id",
            (mission_id, fact_type),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM facts WHERE mission_id=? ORDER BY id", (mission_id,)
    ).fetchall()


# --- Commands ---------------------------------------------------------------

def add_command(conn, mission_id: int, cmd: str, tool: str | None = None,
                rationale: str | None = None, task_id: int | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO commands(mission_id, task_id, tool, cmd, rationale) "
        "VALUES (?,?,?,?,?)",
        (mission_id, task_id, tool, cmd, rationale),
    )
    conn.commit()
    log_audit(conn, "cli", "command.propose", f"cmd={cmd!r}")
    return cur.lastrowid


# --- Audit ------------------------------------------------------------------

def log_audit(conn, actor: str, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO audit(actor, action, detail) VALUES (?,?,?)",
                 (actor, action, detail))
    conn.commit()


def get_audit(conn, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
