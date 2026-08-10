"""P2 canonical tests: PTM ops, digest/compaction, next-step engine.

The LLM boundary is stubbed (network never touched). Real flash integration is
exercised separately via the CLI in the G3 gate.
"""

import json
import os
import tempfile
import unittest

from intected import db, ptm, scope
from intected.reasoning import (
    ReasoningEngine, ReasoningError, build_digest, parse_plan_json,
)

ALLOWED = ["127.0.0.1", "dvwa.local"]


class StubRouter:
    """Replaces the network boundary: returns a canned reply."""

    def __init__(self, reply: str):
        self.reply = reply
        self.calls = []

    def chat(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.reply


def plan(**overrides) -> str:
    base = {
        "objective": "web recon",
        "analysis": "found Apache 2.4.25 on :8001",
        "task_updates": [],
        "suggested_command": {"tool": "gobuster", "cmd": "gobuster dir -u http://dvwa.local -w list.txt",
                              "rationale": "discover paths"},
        "open_questions": [],
    }
    base.update(overrides)
    return json.dumps(base)


class ParsePlanJsonTest(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(parse_plan_json('{"a": 1}'), {"a": 1})

    def test_fenced_json(self):
        self.assertEqual(parse_plan_json('```json\n{"a": 1}\n```'), {"a": 1})

    def test_garbage_raises(self):
        with self.assertRaises(ReasoningError):
            parse_plan_json("sure, here you go: nmap -sV 10.0.0.5")

    def test_empty_raises(self):
        with self.assertRaises(ReasoningError):
            parse_plan_json("")

    def test_salvaged_object(self):
        self.assertEqual(parse_plan_json("prefix {\"a\": 1} suffix"), {"a": 1})


class CompactFactsTest(unittest.TestCase):
    def _fact(self, ftype, value):
        return {"fact_type": ftype, "value": value}

    def test_priority_ordering(self):
        facts = [
            self._fact("note", {"text": "banner"}),
            self._fact("cve", {"cve": "CVE-2021-1234"}),
            self._fact("param", {"param": "id", "injectable": True}),
        ]
        out = ptm.compact_facts(facts)
        self.assertEqual([f["fact_type"] for f in out],
                         ["cve", "param", "note"])

    def test_cap_and_dedupe(self):
        facts = [self._fact("note", {"text": f"x{i}"}) for i in range(10)]
        facts += [self._fact("note", {"text": "x0"})]  # duplicate
        out = ptm.compact_facts(facts, limit=5)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0]["value"]["text"], "x0")
        # cve survives over notes when capped
        out2 = ptm.compact_facts([self._fact("note", {"text": "n"})] * 10 +
                                 [self._fact("cve", {"cve": "CVE-1"})], limit=3)
        self.assertEqual(out2[0]["fact_type"], "cve")


class PtmOpsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)
        self.mid = db.create_mission(self.conn, "ptm", ALLOWED, auth_ref="A")

    def tearDown(self):
        self.conn.close()
        os.unlink(self._tmp.name)

    def test_task_lifecycle_ops(self):
        t = ptm.propose_task(self.conn, self.mid, "scan", "recon")
        ptm.complete_task(self.conn, t)
        self.assertEqual(ptm.task_status(self.conn, t), "completed")
        ptm.fail_task(self.conn, t)
        self.assertEqual(ptm.task_status(self.conn, t), "failed")
        ptm.block_task(self.conn, t, "no auth")
        self.assertEqual(ptm.task_status(self.conn, t), "blocked")

    def test_unmet_deps_gate_next_objective(self):
        t1 = ptm.propose_task(self.conn, self.mid, "nmap", "recon")
        t2 = ptm.propose_task(self.conn, self.mid, "web", "recon", depends_on=[t1])
        # t2 blocked by t1
        self.assertEqual(ptm.next_objective(self.conn, self.mid)["id"], t1)
        ptm.complete_task(self.conn, t1)
        self.assertEqual(ptm.next_objective(self.conn, self.mid)["id"], t2)

    def test_duplicate_command_detection(self):
        db.add_command(self.conn, self.mid, "nmap -sV  127.0.0.1")
        self.assertTrue(ptm.duplicate_command(self.conn, self.mid, "nmap -sV 127.0.0.1"))
        self.assertFalse(ptm.duplicate_command(self.conn, self.mid, "nmap -p 22 127.0.0.1"))

    def test_task_tree_nesting(self):
        t1 = ptm.propose_task(self.conn, self.mid, "recon", "recon")
        ptm.propose_task(self.conn, self.mid, "child", "scan", parent_id=t1)
        tree = ptm.task_tree(self.conn, self.mid)
        self.assertEqual(len(tree), 1)
        self.assertEqual(len(tree[0]["children"]), 1)


class DigestTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)
        self.mid = db.create_mission(self.conn, "digest", ALLOWED, auth_ref="A")
        db.add_task(self.conn, self.mid, "nmap scan", "recon")
        db.add_fact(self.conn, self.mid, "nmap", "port", {"port": 80})
        db.add_fact(self.conn, self.mid, "nmap", "note", {"text": "noise" * 100})

    def tearDown(self):
        self.conn.close()
        os.unlink(self._tmp.name)

    def test_digest_contains_state(self):
        d = build_digest(self.conn, self.mid)
        self.assertIn("MISSION digest", d)
        self.assertIn("ALLOWED SCOPE", d)
        self.assertIn("nmap scan", d)
        self.assertIn("port", d)

    def test_digest_fact_compaction(self):
        d = build_digest(self.conn, self.mid, max_facts=1)
        # with cap 1, the port fact (priority 2) survives over the note (6)
        self.assertIn("port", d)
        self.assertNotIn("noise", d)


class EngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)
        self.mid = db.create_mission(self.conn, "eng", ALLOWED, auth_ref="A")
        self.t = db.add_task(self.conn, self.mid, "web recon", "recon")

    def tearDown(self):
        self.conn.close()
        os.unlink(self._tmp.name)

    def _run(self, reply):
        return ReasoningEngine(router=StubRouter(reply)).next_step(self.conn, self.mid)

    def test_valid_plan_applies_updates_and_approves(self):
        res = self._run(plan(
            task_updates=[{"task_id": self.t, "status": "in_progress"}],
            suggested_command={"tool": "gobuster",
                               "cmd": "gobuster dir -u http://dvwa.local -w list.txt",
                               "task_id": self.t, "rationale": "paths"},
        ))
        self.assertTrue(res["ok"])
        self.assertEqual(res["command"]["state"], "approved")
        self.assertIsNotNone(res["command"]["command_id"])
        self.assertEqual(ptm.task_status(self.conn, self.t), "in_progress")
        row = self.conn.execute("SELECT * FROM commands WHERE id=?",
                                (res["command"]["command_id"],)).fetchone()
        self.assertEqual(row["state"], "proposed")  # persisted as proposed; run happens later

    def test_out_of_scope_command_rejected(self):
        res = self._run(plan(suggested_command={"tool": "nmap",
                                                "cmd": "nmap -sV 8.8.8.8",
                                                "rationale": "scan"}))
        self.assertTrue(res["ok"])
        self.assertEqual(res["command"]["state"], "rejected")
        self.assertIn("outside allowed scope", res["command"]["reason"])

    def test_duplicate_command_rejected(self):
        db.add_command(self.conn, self.mid, "gobuster dir -u http://dvwa.local -w list.txt")
        res = self._run(plan(suggested_command={"tool": "gobuster",
                                                "cmd": "gobuster dir -u http://dvwa.local -w list.txt",
                                                "rationale": "again"}))
        self.assertEqual(res["command"]["state"], "rejected")
        self.assertIn("duplicate", res["command"]["reason"])

    def test_completed_task_guard(self):
        ptm.complete_task(self.conn, self.t)
        res = self._run(plan(suggested_command={"tool": "nmap",
                                                "cmd": "nmap -sV 127.0.0.1",
                                                "task_id": self.t,
                                                "rationale": "recheck"}))
        self.assertEqual(res["command"]["state"], "rejected")
        self.assertIn("already completed", res["command"]["reason"])

    def test_hallucinated_task_id_rejected_not_crash(self):
        """Model inventing a task_id must be rejected cleanly (FK-safe)."""
        res = self._run(plan(suggested_command={"tool": "nmap",
                                                "cmd": "nmap -sV 127.0.0.1",
                                                "task_id": 9999,
                                                "rationale": "x"}))
        self.assertEqual(res["command"]["state"], "rejected")
        self.assertIn("unknown task_id", res["command"]["reason"])

    def test_hallucinated_depends_on_ids_dropped_not_crash(self):
        """PITFALL FIX (live 2026-08-10): model-invented depends_on ids crashed
        the task_deps INSERT (FK). Unknown deps are dropped, task still created."""
        res = self._run(plan(task_updates=[
            {"title": "enumerate metrics", "category": "recon",
             "depends_on": [self.t, 9999]},  # 9999 does not exist
        ]))
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["task_updates_applied"]), 1)
        row = self.conn.execute(
            "SELECT * FROM tasks WHERE title='enumerate metrics'").fetchone()
        self.assertIsNotNone(row)
        deps = self.conn.execute(
            "SELECT depends_on FROM task_deps WHERE task_id=?", (row["id"],)).fetchall()
        self.assertEqual([d["depends_on"] for d in deps], [self.t])  # only valid dep

    def test_non_list_depends_on_does_not_crash(self):
        """CONTROL-REVIEW M1 (verified live): depends_on: 5 raised an unhandled
        TypeError. Non-list types are treated as no deps, task still created."""
        for bad in (5, True, "x", 3.14):
            res = self._run(plan(task_updates=[
                {"title": f"t-{bad}", "category": "recon", "depends_on": bad},
            ]))
            self.assertTrue(res["ok"])
            self.assertEqual(len(res["task_updates_applied"]), 1)
            row = self.conn.execute(
                "SELECT * FROM tasks WHERE title=?", (f"t-{bad}",)).fetchone()
            self.assertIsNotNone(row)
            n = self.conn.execute(
                "SELECT COUNT(*) n FROM task_deps WHERE task_id=?",
                (row["id"],)).fetchone()["n"]
            self.assertEqual(n, 0)

    def test_digest_filters_pass_level_facts(self):
        """PASS-level ZAP rules are scan-coverage noise — filtered from digest."""
        from intected.reasoning import build_digest
        db.add_fact(self.conn, self.mid, "zap", "note",
                    {"zap_rule": "10003", "level": "PASS", "name": "X"}, confidence=1.0)
        db.add_fact(self.conn, self.mid, "zap", "note",
                    {"zap_rule": "10010", "level": "WARN", "name": "Y"}, confidence=1.0)
        d = build_digest(self.conn, self.mid)
        self.assertNotIn("10003", d)
        self.assertIn("10010", d)

    def test_destructive_marker_string_true_rejected(self):
        """Model sending aggressive:"true" (string) must NOT unlock --drop."""
        res = self._run(plan(suggested_command={
            "tool": "sqlmap",
            "cmd": "sqlmap -u http://dvwa.local/x?id=1 --drop",
            "aggressive": "true", "rationale": "drop"}))
        self.assertEqual(res["command"]["state"], "rejected")
        self.assertIn("aggressive", res["command"]["reason"])

    def test_destructive_marker_strict_true_approved(self):
        res = self._run(plan(suggested_command={
            "tool": "sqlmap",
            "cmd": "sqlmap -u http://dvwa.local/x?id=1 --drop",
            "aggressive": True, "rationale": "drop"}))
        self.assertEqual(res["command"]["state"], "approved")

    def test_garbage_reply_graceful_failure(self):
        class GarbageRouter(StubRouter):
            def __init__(self):
                super().__init__("I would scan port 80 next.")

            def chat(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return self.reply  # garbage every time, even on retry

        res = ReasoningEngine(router=GarbageRouter()).next_step(self.conn, self.mid)
        self.assertFalse(res["ok"])
        self.assertIn("unparsable", res["error"])
        self.assertIn("after 1 retry", res["error"])

    def test_retry_recovers_valid_json(self):
        """First reply is prose; corrective retry returns valid JSON."""

        class FlakyRouter:
            def __init__(self):
                self.n = 0

            def chat(self, *args, **kwargs):
                self.n += 1
                if self.n == 1:
                    return "Let me think: the web server on 8001 is old."
                return plan(suggested_command={"tool": "curl",
                                               "cmd": "curl -sS -i http://dvwa.local:8001/",
                                               "rationale": "headers"})

        res = ReasoningEngine(router=FlakyRouter()).next_step(self.conn, self.mid)
        self.assertTrue(res["ok"])
        self.assertEqual(res["command"]["state"], "approved")

    def test_empty_command_spec_skipped(self):
        res = self._run(plan(suggested_command=None))
        self.assertTrue(res["ok"])
        self.assertEqual(res["command"]["state"], "none")

    def test_invalid_task_update_skipped(self):
        res = self._run(plan(task_updates=[
            {"task_id": 9999, "status": "completed"},
            {"task_id": self.t, "status": "banana"},
        ]))
        self.assertTrue(res["ok"])
        self.assertEqual(res["task_updates_applied"], [])

    def test_new_task_created_from_update(self):
        res = self._run(plan(task_updates=[
            {"title": "dir brute", "category": "scan", "depends_on": [self.t]}]))
        self.assertEqual(len(res["task_updates_applied"]), 1)
        rows = self.conn.execute("SELECT * FROM tasks WHERE title=?",
                                 ("dir brute",)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["category"], "scan")

    def test_router_failure_reported(self):
        class BoomRouter:
            def chat(self, *a, **k):
                raise RuntimeError("bridge down")
        res = ReasoningEngine(router=BoomRouter()).next_step(self.conn, self.mid)
        self.assertFalse(res["ok"])
        self.assertIn("LLM route failed", res["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
