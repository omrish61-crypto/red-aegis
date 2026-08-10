"""Canonical tests: SQLite schema + PTM CRUD (stdlib unittest — results to stderr)."""

import sqlite3
import tempfile
import unittest

from intected import db


class DbTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()  # Windows: mkstemp/NamedTemporaryFile returns open fd
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)

    def tearDown(self):
        self.conn.close()
        import os
        os.unlink(self._tmp.name)

    def test_schema_initialized(self):
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("missions", "tasks", "task_deps", "facts", "commands", "audit",
                  "schema_version"):
            self.assertIn(t, tables)
        self.assertEqual(
            self.conn.execute("SELECT version FROM schema_version").fetchone()[0],
            db.SCHEMA_VERSION,
        )

    def test_mission_roundtrip(self):
        mid = db.create_mission(self.conn, "eng-1", ["10.0.0.5", "dvwa.local"],
                                auth_ref="AUTH-001")
        m = db.get_mission(self.conn, mid)
        self.assertEqual(m["name"], "eng-1")
        self.assertIn("dvwa.local", m["allowed_hosts_json"])
        self.assertEqual(m["auth_ref"], "AUTH-001")
        self.assertEqual(m["status"], "active")

    def test_task_status_lifecycle(self):
        mid = db.create_mission(self.conn, "eng-2", ["10.0.0.6"])
        t1 = db.add_task(self.conn, mid, "nmap scan", "recon")
        t2 = db.add_task(self.conn, mid, "web recon", "recon", depends_on=[t1])
        db.set_task_status(self.conn, t1, "completed")
        rows = db.get_tasks(self.conn, mid)
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(by_id[t1]["status"], "completed")
        self.assertIsNotNone(by_id[t1]["completed_at"])
        self.assertEqual(by_id[t2]["status"], "pending")
        # dependency recorded
        deps = self.conn.execute(
            "SELECT depends_on FROM task_deps WHERE task_id=?", (t2,)).fetchall()
        self.assertEqual([d[0] for d in deps], [t1])

    def test_task_status_validation(self):
        mid = db.create_mission(self.conn, "eng-3", ["10.0.0.7"])
        t = db.add_task(self.conn, mid, "x", "recon")
        with self.assertRaises(ValueError):
            db.set_task_status(self.conn, t, "banana")

    def test_fact_requires_known_type(self):
        mid = db.create_mission(self.conn, "eng-4", ["10.0.0.8"])
        with self.assertRaises(ValueError):
            db.add_fact(self.conn, mid, "nmap", "madeup", {"x": 1})
        fid = db.add_fact(self.conn, mid, "nmap", "port",
                          {"port": 80, "state": "open"},
                          evidence_ref="runs/x.raw", sha256="ab" * 32)
        facts = db.get_facts(self.conn, mid)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["sha256"], "ab" * 32)

    def test_audit_append_only(self):
        mid = db.create_mission(self.conn, "eng-5", ["10.0.0.9"])
        rows = db.get_audit(self.conn, limit=10)
        self.assertTrue(any("mission.create" in r["action"] for r in rows))

    def test_foreign_keys_enforced(self):
        with self.assertRaises(sqlite3.IntegrityError):
            db.add_task(self.conn, 99999, "orphan", "recon")


if __name__ == "__main__":
    unittest.main(verbosity=2)
