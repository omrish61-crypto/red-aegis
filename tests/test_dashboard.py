"""P3 canonical tests: dashboard API + auth + evidence drill-down.

Requires the `test` extra (httpx) for TestClient.
"""

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
