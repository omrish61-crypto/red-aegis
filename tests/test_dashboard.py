"""P3 canonical tests: dashboard API + auth + evidence drill-down.

Requires the `test` extra (httpx) for TestClient.
"""

import json
import os
import tempfile
import unittest

from intected import config, db
from intected.dashboard import create_app, mission_bundle

try:
    from fastapi.testclient import TestClient
    HAVE_HTTPX = True
except ImportError:  # pragma: no cover
    HAVE_HTTPX = False


class MissionBundleTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)
        self.mid = db.create_mission(self.conn, "bundle", ["127.0.0.1"],
                                     auth_ref="A-1")

    def tearDown(self):
        self.conn.close()
        os.unlink(self._tmp.name)

    def test_bundle_structure(self):
        db.add_task(self.conn, self.mid, "recon", "recon")
        db.add_fact(self.conn, self.mid, "nmap", "port", {"port": 80},
                    evidence_ref="x.raw", sha256="ab" * 32)
        db.add_command(self.conn, self.mid, "nmap -sV 127.0.0.1")
        b = mission_bundle(self.conn, self.mid)
        self.assertEqual(b["mission"]["name"], "bundle")
        self.assertEqual(len(b["tasks"]), 1)
        self.assertEqual(len(b["facts"]), 1)
        self.assertEqual(len(b["commands"]), 1)
        self.assertEqual(b["stats"]["facts"]["port"], 1)
        self.assertEqual(b["stats"]["tasks"]["pending"], 1)

    def test_bundle_unknown_mission(self):
        with self.assertRaises(KeyError):
            mission_bundle(self.conn, 999)


@unittest.skipUnless(HAVE_HTTPX, "httpx not installed (uv sync --extra test)")
class ApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._tmp_dir = tempfile.TemporaryDirectory()
        # real evidence file first, then a fact whose sha256 matches it
        import hashlib
        self.ev_path = os.path.join(self._tmp_dir.name, "ev.raw")
        with open(self.ev_path, "w") as fh:
            fh.write("PORT STATE SERVICE\n80/tcp open http\n")
        self.ev_sha = hashlib.sha256(
            open(self.ev_path, "rb").read()).hexdigest()
        conn = db.connect(self._tmp.name)
        db.init_db(conn)
        self.mid = db.create_mission(conn, "api", ["127.0.0.1"], auth_ref="A")
        db.add_task(conn, self.mid, "scan", "recon")
        db.add_fact(conn, self.mid, "nmap", "port", {"port": 80},
                    evidence_ref=self.ev_path, sha256=self.ev_sha)
        conn.close()
        self.token = "test-token-123"
        app = create_app(token=self.token, db_path=self._tmp.name)
        self.client = TestClient(app)

    def tearDown(self):
        self._tmp_dir.cleanup()
        os.unlink(self._tmp.name)

    def test_missions_require_token(self):
        r = self.client.get("/api/missions")
        self.assertEqual(r.status_code, 401)
        r = self.client.get("/api/missions", params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()[0]["name"], "api")

    def test_spa_serves_auth_banner_element(self):
        """UX fix 2026-08-11: a missing/invalid token must not leave a silent
        empty shell — the SPA ships an auth-failure banner (shown by app.js)."""
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("auth-banner", r.text)
        self.assertIn("Authentication failed", r.text)

    def test_wrong_token_rejected(self):
        r = self.client.get("/api/missions", params={"token": "wrong"})
        self.assertEqual(r.status_code, 401)

    def test_header_token_accepted(self):
        r = self.client.get("/api/missions",
                            headers={"X-INTECTED-Token": self.token})
        self.assertEqual(r.status_code, 200)

    def test_bad_origin_rejected(self):
        r = self.client.get("/api/missions",
                            params={"token": self.token},
                            headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 401)

    def test_mission_endpoint(self):
        r = self.client.get(f"/api/missions/{self.mid}",
                            params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["stats"]["facts_total"], 1)

    def test_unknown_mission_404(self):
        r = self.client.get("/api/missions/999", params={"token": self.token})
        self.assertEqual(r.status_code, 404)

    def test_add_target_endpoint(self):
        r = self.client.post(f"/api/missions/{self.mid}/targets",
                             params={"token": self.token},
                             json={"target": "10.0.0.5"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("10.0.0.5", data["scope"])
        self.assertEqual(data["target"], "10.0.0.5")
        # mission bundle reflects the new scope
        r = self.client.get(f"/api/missions/{self.mid}",
                            params={"token": self.token})
        hosts = json.loads(r.json()["mission"]["allowed_hosts_json"])
        self.assertIn("10.0.0.5", hosts)

    def test_add_target_domain_and_range(self):
        for t in ("example.com", "192.168.1.0/24"):
            r = self.client.post(f"/api/missions/{self.mid}/targets",
                                 params={"token": self.token},
                                 json={"target": t})
            self.assertEqual(r.status_code, 200, t)
        hosts = self.client.get(f"/api/missions/{self.mid}",
                                params={"token": self.token}).json()["mission"]
        self.assertEqual(len(json.loads(hosts["allowed_hosts_json"])), 3)

    def test_add_target_dedupe(self):
        for _ in range(2):
            self.client.post(f"/api/missions/{self.mid}/targets",
                             params={"token": self.token},
                             json={"target": "10.0.0.5"})
        hosts = self.client.get(f"/api/missions/{self.mid}",
                                params={"token": self.token}).json()["mission"]
        scope = json.loads(hosts["allowed_hosts_json"])
        self.assertEqual(scope.count("10.0.0.5"), 1)  # added exactly once

    def test_add_target_invalid_rejected(self):
        for bad in ("http://evil.com", "10.0.0.999", "a b c", "", "1.2.3"):
            r = self.client.post(f"/api/missions/{self.mid}/targets",
                                 params={"token": self.token},
                                 json={"target": bad})
            self.assertEqual(r.status_code, 422, bad)

    def test_add_target_requires_auth(self):
        r = self.client.post(f"/api/missions/{self.mid}/targets",
                             json={"target": "10.0.0.5"})
        self.assertEqual(r.status_code, 401)

    def test_remove_target(self):
        self.client.post(f"/api/missions/{self.mid}/targets",
                         params={"token": self.token},
                         json={"target": "10.0.0.5"})
        r = self.client.delete(
            f"/api/missions/{self.mid}/targets",
            params={"token": self.token, "target": "10.0.0.5"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("10.0.0.5", r.json()["scope"])
        # removing again -> 422 (not in scope)
        r = self.client.delete(
            f"/api/missions/{self.mid}/targets",
            params={"token": self.token, "target": "10.0.0.5"})
        self.assertEqual(r.status_code, 422)

    def test_remove_target_cidr_roundtrip(self):
        # CIDR contains '/', must survive URL-encoded query param roundtrip
        r = self.client.post(f"/api/missions/{self.mid}/targets",
                             params={"token": self.token},
                             json={"target": "192.168.1.0/24"})
        self.assertEqual(r.status_code, 200)
        r = self.client.delete(
            f"/api/missions/{self.mid}/targets",
            params={"token": self.token, "target": "192.168.1.0/24"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("192.168.1.0/24", r.json()["scope"])

    def test_remove_target_requires_auth(self):
        r = self.client.delete(f"/api/missions/{self.mid}/targets",
                               params={"target": "10.0.0.5"})
        self.assertEqual(r.status_code, 401)

    def test_start_test_requires_targets(self):
        # a mission with an empty scope must refuse to start (422)
        c2 = db.connect(self._tmp.name)
        db.init_db(c2)
        empty = db.create_mission(c2, "no-scope", [])
        c2.close()
        try:
            r = self.client.post(f"/api/missions/{empty}/start",
                                 params={"token": self.token})
            self.assertEqual(r.status_code, 422)
        finally:
            c3 = db.connect(self._tmp.name)
            c3.execute("DELETE FROM missions WHERE id=?", (empty,))
            c3.commit()
            c3.close()

    def test_start_test_creates_scan_tasks(self):
        r = self.client.post(f"/api/missions/{self.mid}/start",
                             params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertGreaterEqual(data["tasks_created"], 1)
        self.assertIn("127.0.0.1", data["targets"])
        bundle = self.client.get(f"/api/missions/{self.mid}",
                                 params={"token": self.token}).json()
        titles = [t["title"] for t in bundle["tasks"]]
        self.assertTrue(any("Run penetration test" in t for t in titles))

    def test_start_test_idempotent(self):
        first = self.client.post(f"/api/missions/{self.mid}/start",
                                 params={"token": self.token}).json()
        self.assertGreaterEqual(first["tasks_created"], 1)
        self.assertEqual(first["tasks_existing"], 0)
        second = self.client.post(f"/api/missions/{self.mid}/start",
                                  params={"token": self.token}).json()
        # second start creates nothing new — reports them as existing
        self.assertEqual(second["tasks_created"], 0)
        self.assertGreaterEqual(second["tasks_existing"], 1)

    def test_start_test_requires_auth(self):
        r = self.client.post(f"/api/missions/{self.mid}/start")
        self.assertEqual(r.status_code, 401)

    def test_command_run_endpoints(self):
        """Run/Run-all endpoints: auth, gating, state transitions."""
        # 401 without token (auth fires before any DB access)
        r = self.client.post("/api/commands/999/run")
        self.assertEqual(r.status_code, 401)
        # run-all: 401 without token
        r = self.client.post(f"/api/missions/{self.mid}/commands/run-all")
        self.assertEqual(r.status_code, 401)
        # run-all with token but no runnable commands -> clean empty result
        r = self.client.post(
            f"/api/missions/{self.mid}/commands/run-all?token={self.token}")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["ran"], 0)
        self.assertIn("results", data)

    def test_command_run_supervisor_block(self):
        """A command targeting an out-of-scope host is rejected (422)."""
        from intected import db as _db
        conn = _db.connect(self._tmp.name)
        _db.init_db(conn)
        _db.add_command(conn, self.mid,
                        "nikto -h http://10.9.9.9", tool="nikto")
        cmd_id = conn.execute(
            "SELECT id FROM commands WHERE mission_id=? ORDER BY id DESC LIMIT 1",
            (self.mid,)).fetchone()[0]
        conn.close()
        r = self.client.post(f"/api/commands/{cmd_id}/run?token={self.token}")
        self.assertEqual(r.status_code, 422)
        data = r.json()
        self.assertEqual(data["state"], "rejected")
        # state persisted
        conn = _db.connect(self._tmp.name)
        st = conn.execute("SELECT state FROM commands WHERE id=?",
                          (cmd_id,)).fetchone()[0]
        conn.close()
        self.assertEqual(st, "rejected")

    def test_plan_endpoint(self):
        """Evidence-based plan API (methodology 11/12): graph + ranked plan."""
        r = self.client.get(f"/api/missions/{self.mid}/plan",
                            params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("graph", data)
        self.assertIn("plan", data)
        self.assertEqual(data["plan"]["target"], "127.0.0.1")
        # every plan item is evidence-based (the core rule)
        for item in data["plan"]["plan"]:
            self.assertTrue(item["based_on"])

    def test_plan_requires_auth(self):
        r = self.client.get(f"/api/missions/{self.mid}/plan")
        self.assertEqual(r.status_code, 401)

    def test_evidence_endpoint(self):
        r = self.client.get(f"/api/missions/{self.mid}/evidence/1",
                            params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("80/tcp", data["content"])
        self.assertTrue(data["matches"])
        self.assertEqual(data["sha256"], self.ev_sha)

    def test_evidence_tampered_hash_detected(self):
        # corrupt the file after the fact was recorded -> mismatch must surface
        with open(self.ev_path, "w") as fh:
            fh.write("PORT STATE SERVICE\n80/tcp open http\n# tampered\n")
        r = self.client.get(f"/api/missions/{self.mid}/evidence/1",
                            params={"token": self.token})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["matches"])

    def test_evidence_missing_file_404(self):
        os.unlink(self.ev_path)  # remove the file -> endpoint must 404
        r = self.client.get(f"/api/missions/{self.mid}/evidence/1",
                            params={"token": self.token})
        self.assertEqual(r.status_code, 404)

    def test_spa_served(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("INTECTED", r.text)
        r = self.client.get("/app.js")
        self.assertEqual(r.status_code, 200)
        self.assertIn("loadMissions", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
