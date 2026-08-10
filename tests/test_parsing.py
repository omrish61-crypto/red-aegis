"""P1 canonical tests: extractors against REAL lab captures + fault injection.

Real fixtures live in tests/fixtures/ (see fixtures/README.md for provenance).
Fault-injection inputs are synthetic by design.
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from intected import db
from intected.parsing import (
    EXTRACTORS, ParseError, parse_tool_output, sha256_bytes, store_evidence,
    verify_evidence,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def extract(tool: str, name: str):
    return EXTRACTORS[tool](fixture(name))


def find_facts(facts, fact_type: str, **value_subset) -> list[dict]:
    out = []
    for f in facts:
        if f["fact_type"] != fact_type:
            continue
        if all(f["value"].get(k) == v for k, v in value_subset.items()):
            out.append(f)
    return out


class NmapRealFixtureTest(unittest.TestCase):
    def test_fresh_scan_ports(self):
        facts, _ = extract("nmap", "real-nmap-20260810.xml")
        ports = {f["value"]["port"] for f in find_facts(facts, "port")}
        self.assertEqual(ports, {3000, 8001, 8080})

    def test_fresh_scan_versions(self):
        facts, _ = extract("nmap", "real-nmap-20260810.xml")
        apache = find_facts(facts, "version", port=8001, product="Apache httpd")
        self.assertEqual(len(apache), 1)
        self.assertEqual(apache[0]["value"]["version"], "2.4.25")
        tomcat = find_facts(facts, "version", port=8080, product="Apache Tomcat")
        self.assertEqual(tomcat[0]["value"]["version"], "10.1.36")

    def test_services_extracted(self):
        facts, _ = extract("nmap", "real-nmap-20260810.xml")
        services = {f["value"]["service"] for f in find_facts(facts, "service")}
        self.assertIn("http", services)

    def test_juiceshop_scan_parses(self):
        facts, _ = extract("nmap", "real-nmap-juiceshop-20260809.xml")
        self.assertIn(3000, {f["value"]["port"] for f in find_facts(facts, "port")})

    def test_vuln_scan_notes(self):
        facts, _ = extract("nmap", "real-nmap-vuln-20260809.xml")
        notes = find_facts(facts, "note")
        self.assertGreaterEqual(len(notes), 1, "expected NSE script notes")
        # the fixture's script FAILED to run — that fact must be preserved
        clam = find_facts(facts, "note", script="clamav-exec")
        self.assertEqual(len(clam), 1)
        self.assertIn("ERROR", clam[0]["value"]["output"])


class GobusterRealFixtureTest(unittest.TestCase):
    def test_dvwa_paths(self):
        facts, _ = extract("gobuster", "real-gobuster-dvwa-20260809.txt")
        paths = {f["value"]["path"] for f in find_facts(facts, "path")}
        for expected in ("login.php", "setup.php", "vulnerabilities", "robots.txt",
                         "index.php", "config"):
            self.assertIn(expected, paths, f"missing gobuster path {expected}")
        # redirect captured
        idx = find_facts(facts, "path", path="index.php")
        self.assertEqual(idx[0]["value"].get("status"), 302)

    def test_error_stderr_becomes_note(self):
        facts, warnings = extract("gobuster", "real-gobuster-error-20260809.stderr.txt")
        notes = find_facts(facts, "note")
        self.assertGreaterEqual(len(notes), 1)
        self.assertTrue(any("timeout" in n["value"].get("text", "") for n in notes))


class NucleiRealFixtureTest(unittest.TestCase):
    def test_findings_extracted(self):
        facts, _ = extract("nuclei", "real-nuclei-juiceshop-20260809.jsonl")
        notes = find_facts(facts, "note")
        self.assertGreaterEqual(len(notes), 1)
        prom = find_facts(facts, "note", template_id="prometheus-metrics")
        self.assertEqual(len(prom), 1)
        self.assertEqual(prom[0]["value"]["severity"], "medium")
        self.assertIn("host.docker.internal", prom[0]["value"]["url"])


class SqlmapRealFixtureTest(unittest.TestCase):
    def test_injectable_param(self):
        facts, _ = extract("sqlmap", "real-sqlmap-dvwa-20260809.txt")
        params = find_facts(facts, "param", param="id", injectable=True)
        self.assertGreaterEqual(len(params), 1)
        self.assertIn("MySQL", str(params[0]["value"].get("type", "")) +
                      str(facts))  # type string carries the technique
        dbms = find_facts(facts, "note", dbms="MySQL")
        self.assertGreaterEqual(len(dbms), 1)

    def test_not_injectable_negative_kept(self):
        facts, _ = extract("sqlmap", "real-sqlmap-dvwa-20260809.txt")
        # fixture IS injectable — negative handling covered in fault tests


class ZapRealFixtureTest(unittest.TestCase):
    def test_alert_lines(self):
        facts, _ = extract("zap", "real-zap-baseline-20260809.txt")
        notes = find_facts(facts, "note")
        self.assertGreaterEqual(len(notes), 5)
        self.assertTrue(any("zap_rule" in n["value"] for n in notes))
        self.assertTrue(any(n["value"].get("zap_total_urls") == 158 for n in notes))


class FormatSampleTest(unittest.TestCase):
    """Documented-format conformance (no real lab capture available for these)."""

    def test_ffuf_json_lines(self):
        sample = ('{"input":{"FUZZ":"admin"},"status":301,"length":312,'
                  '"url":"http://10.0.0.5/FUZZ","redirectlocation":"http://10.0.0.5/admin/"}\n'
                  '{"input":{"FUZZ":"api"},"status":200,"length":5123,'
                  '"url":"http://10.0.0.5/FUZZ"}\n')
        facts, _ = EXTRACTORS["ffuf"](sample)
        paths = {f["value"]["path"]: f["value"] for f in find_facts(facts, "path")}
        # FUZZ placeholder substituted with the concrete input
        self.assertIn("http://10.0.0.5/admin", paths)
        self.assertEqual(paths["http://10.0.0.5/admin"]["status"], 301)
        self.assertEqual(paths["http://10.0.0.5/admin"]["redirect"],
                         "http://10.0.0.5/admin/")
        self.assertIn("http://10.0.0.5/api", paths)

    def test_burp_sitemap(self):
        sample = ('<sitemap><host name="http://10.0.0.5:8080" ip="10.0.0.5">'
                  '<url><url>http://10.0.0.5:8080/login</url>'
                  '<params><param name="user"/><param name="pass"/></params></url>'
                  '</host></sitemap>')
        facts, _ = EXTRACTORS["burp"](sample)
        self.assertEqual(len(find_facts(facts, "path")), 1)
        params = {f["value"]["param"] for f in find_facts(facts, "param")}
        self.assertEqual(params, {"user", "pass"})

    def test_nikto(self):
        sample = ("+ Server: Apache/2.4.25 (Debian)\n"
                  "+ Target IP: 10.0.0.5\n"
                  "+ /login.php: Admin login page/section found.\n"
                  "- ERROR: Error limit (20) reached.\n")
        facts, warnings = EXTRACTORS["nikto"](sample)
        self.assertEqual(len(find_facts(facts, "version")), 1)
        self.assertEqual(len(find_facts(facts, "path")), 1)
        self.assertTrue(any("ERROR" in w for w in warnings))


class FaultInjectionTest(unittest.TestCase):
    def test_empty_input_is_valid_zero(self):
        for tool in EXTRACTORS:
            facts, _ = EXTRACTORS[tool]("")
            self.assertEqual(facts, [], f"{tool} must return [] on empty input")

    def test_malformed_xml_no_crash(self):
        facts, warnings = EXTRACTORS["nmap"]("<nmaprun><host><port")
        self.assertEqual(facts, [])
        self.assertTrue(warnings)

    def test_binary_garbage_no_crash(self):
        garbage = b"\x00\xff\xfe\x01garbage\x80\x81".decode("utf-8", errors="replace")
        for tool in EXTRACTORS:
            facts, _ = EXTRACTORS[tool](garbage)
            self.assertIsInstance(facts, list, f"{tool} crashed on garbage")

    def test_huge_line_no_crash(self):
        huge = "x" * (1 << 20)  # 1 MB single line
        facts, _ = EXTRACTORS["nuclei"](huge)
        self.assertIsInstance(facts, list)
        facts, _ = EXTRACTORS["gobuster"](huge)
        self.assertIsInstance(facts, list)

    def test_nuclei_garbage_lines_skipped_with_warning(self):
        text = "not-json\n{\"template-id\":\"ok\",\"info\":{\"severity\":\"low\"},\"url\":\"http://x/\"}\n"
        facts, warnings = EXTRACTORS["nuclei"](text)
        self.assertEqual(len(facts), 1)
        self.assertGreaterEqual(len(warnings), 1)

    def test_sqlmap_not_injectable_negative_kept(self):
        sample = ("[16:28:17] [INFO] testing if GET parameter 'id' is dynamic\n"
                  "[16:28:17] [WARNING] GET parameter 'id' does not appear to be dynamic\n"
                  "[16:28:20] [INFO] GET parameter 'id' is not injectable\n")
        facts, _ = EXTRACTORS["sqlmap"](sample)
        injectable = find_facts(facts, "param", injectable=True)
        self.assertEqual(injectable, [])
        neg = find_facts(facts, "note")
        self.assertTrue(any("not injectable" in n["value"].get("text", "") for n in neg))


class EvidenceStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ev_dir = os.path.join(self._tmp.name, "evidence")

    def tearDown(self):
        self._tmp.cleanup()

    def test_store_and_verify(self):
        raw = b"PORT STATE SERVICE\n80/tcp open http\n"
        path, sha = store_evidence(1, "nmap", raw, self.ev_dir)
        self.assertTrue(os.path.exists(path))
        self.assertEqual(sha, sha256_bytes(raw))
        self.assertTrue(verify_evidence(path, sha))
        self.assertFalse(verify_evidence(path, "deadbeef" * 8))

    def test_store_is_verbatim(self):
        raw = b"raw\x00bytes\xff" * 10
        path, _ = store_evidence(2, "gobuster", raw, self.ev_dir)
        self.assertEqual(Path(path).read_bytes(), raw)


class ParsePipelineTest(unittest.TestCase):
    """End-to-end: raw file -> DB facts, structural evidence enforcement."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._tmp_dir = tempfile.TemporaryDirectory()  # fixtures live in a DIR
        self.conn = db.connect(self._tmp.name)
        db.init_db(self.conn)
        self.mission_id = db.create_mission(self.conn, "p1-test", ["127.0.0.1"],
                                            auth_ref="AUTH-P1")

    def tearDown(self):
        self.conn.close()
        self._tmp_dir.cleanup()
        os.unlink(self._tmp.name)

    def _write_fixture(self, name: str) -> str:
        path = os.path.join(self._tmp_dir.name, name)
        Path(path).write_bytes(fixture_bytes(name))
        return path

    def test_pipeline_nmap_real(self):
        raw = self._write_fixture("real-nmap-20260810.xml")
        res = parse_tool_output(self.conn, self.mission_id, "nmap", raw)
        self.assertGreaterEqual(len(res["facts"]), 6)  # 3 ports + 3 versions + services
        rows = self.conn.execute(
            "SELECT * FROM facts WHERE mission_id=?", (self.mission_id,)).fetchall()
        self.assertEqual(len(rows), len(res["facts"]))
        # STRUCTURAL RULE: zero facts without evidence_ref + sha256
        bad = [r for r in rows if not r["evidence_ref"] or not r["sha256"]]
        self.assertEqual(bad, [], "every fact must carry evidence_ref + sha256")
        self.assertTrue(all(r["evidence_ref"].endswith("real-nmap-20260810.xml")
                            for r in rows))
        # recorded sha matches file hash
        self.assertEqual(res["sha256"], sha256_bytes(fixture_bytes("real-nmap-20260810.xml")))

    def test_pipeline_gobuster_real(self):
        raw = self._write_fixture("real-gobuster-dvwa-20260809.txt")
        res = parse_tool_output(self.conn, self.mission_id, "gobuster", raw)
        self.assertGreaterEqual(len(res["facts"]), 11)

    def test_pipeline_unknown_tool_raises(self):
        with self.assertRaises(ParseError):
            parse_tool_output(self.conn, self.mission_id, "nessus", "whatever.txt")

    def test_evidence_verify_pipeline(self):
        raw = self._write_fixture("real-nmap-20260810.xml")
        res = parse_tool_output(self.conn, self.mission_id, "nmap", raw)
        self.assertTrue(verify_evidence(raw, res["sha256"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
