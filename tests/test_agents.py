"""Canonical tests: Tool registry + Supervisor gate + NVD client + PII guard.

Verifies the multi-agent constraints from the spec:
- function-calling only (no raw bash path), params whitelisted + bounded
- supervisor blocks: out-of-scope, over-rate, full -p- without approval,
  brute-force/data-extraction tools
- NVD: cpe_from_banner honest (no version -> None), lookup failure is loud
- PII: detection + redaction, DB-proof values PII-safe
"""

import unittest
import tempfile

from intected import pii, supervisor, tools
from intected.cve import cpe_from_banner


class ToolRegistryTest(unittest.TestCase):
    def test_unknown_tool_rejected(self):
        with self.assertRaises(tools.ToolError):
            tools.validate_params("evil_script", {})

    def test_unknown_param_rejected(self):
        with self.assertRaises(tools.ToolError):
            tools.validate_params("nmap_ports",
                                  {"target": "x", "--script": "vuln"})

    def test_rate_bounded(self):
        with self.assertRaises(tools.ToolError):
            tools.validate_params("nmap_ports",
                                  {"target": "x", "rate": 5000})
        ok = tools.validate_params("nmap_ports", {"target": "x", "rate": 200})
        self.assertEqual(ok["rate"], 200)

    def test_defaults_applied(self):
        ok = tools.validate_params("nikto", {"target": "x"})
        self.assertEqual(ok["maxtime"], 90)

    def test_list_tools_whitelist(self):
        names = tools.list_tools()
        self.assertIn("nmap_ports", names)
        self.assertNotIn("os.system", names)


class SupervisorTest(unittest.TestCase):
    SCOPE = ["scanme.nmap.org", "127.0.0.1"]

    def test_approves_in_scope_recon(self):
        r = supervisor.validate_tool_call(
            "nmap_ports", {"target": "scanme.nmap.org", "rate": 150},
            self.SCOPE)
        self.assertTrue(r["ok"])
        self.assertTrue(supervisor.auto_approvable(
            "nmap_ports", {"target": "scanme.nmap.org"}))

    def test_blocks_out_of_scope(self):
        from intected.scope import ScopeViolation
        with self.assertRaises(ScopeViolation):
            supervisor.validate_tool_call(
                "nmap_ports", {"target": "10.0.0.99"}, self.SCOPE)

    def test_blocks_full_scan_without_operator(self):
        with self.assertRaises(ValueError):
            supervisor.validate_tool_call(
                "nmap_ports", {"target": "scanme.nmap.org", "ports": "all"},
                self.SCOPE)
        # operator-explicit approval passes
        r = supervisor.validate_tool_call(
            "nmap_ports", {"target": "scanme.nmap.org", "ports": "all"},
            self.SCOPE, operator_approved=True)
        self.assertTrue(r["ok"])

    def test_blocks_bruteforce_tools(self):
        # brute-force / data-extraction tools are not in the registry at all —
        # rejected at the registry level (they never reach execution)
        with self.assertRaises(tools.ToolError):
            supervisor.validate_tool_call(
                "hydra", {"target": "scanme.nmap.org"}, self.SCOPE)
        with self.assertRaises(tools.ToolError):
            supervisor.validate_tool_call(
                "sqlmap", {"target": "scanme.nmap.org", "params": "--dump"},
                self.SCOPE)

    def test_over_rate_blocked(self):
        with self.assertRaises(tools.ToolError):
            supervisor.validate_tool_call(
                "ffuf_content", {"target": "scanme.nmap.org", "rate": 1000},
                self.SCOPE)


class CveClientTest(unittest.TestCase):
    def test_cpe_from_banner(self):
        self.assertEqual(cpe_from_banner("Apache httpd 2.4.7 (Ubuntu)"),
                         "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*")
        self.assertEqual(cpe_from_banner("nginx 1.18.0"),
                         "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")

    def test_cpe_none_without_version(self):
        self.assertIsNone(cpe_from_banner("Apache (no version here)"))

    def test_lookup_failure_is_loud(self):
        # unreachable NVD endpoint -> LookupError, never an invented CVE
        from intected.cve import lookup_cpe
        with self.assertRaises(LookupError):
            lookup_cpe("cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*",
                       api_key="invalid-key-for-unreachable-test")


class PiiGuardTest(unittest.TestCase):
    def test_detect(self):
        self.assertIn("email", pii.detect("contact admin@example.com now"))
        self.assertIn("credit_card", pii.detect("4111 1111 1111 1111"))

    def test_redact(self):
        out = pii.redact("mail me at a@b.com or call +972 50 1234567")
        self.assertNotIn("a@b.com", out)
        self.assertIn(pii.REDACTED, out)

    def test_db_proof_safe(self):
        self.assertTrue(pii.is_pii_safe("SELECT version(); -> 8.0.36"))
        self.assertFalse(pii.is_pii_safe("SELECT email FROM users -> "
                                         "bob@example.com"))


class DecisionMatrixTest(unittest.TestCase):
    def test_web_no_auth_surface_content_discovery(self):
        from intected.matrix import next_tool_call
        call = next_tool_call({"web": True, "waf_detected": False,
                               "api": False, "graphql": False},
                              ["/index.html"], "scanme.nmap.org")
        self.assertEqual(call["tool"], "ffuf_content")
        self.assertIn("why", call)

    def test_waf_changes_strategy(self):
        from intected.matrix import next_tool_call
        call = next_tool_call({"web": True, "waf_detected": True,
                               "api": False, "graphql": False},
                              ["/login"], "target.example")
        self.assertEqual(call["tool"], "http_headers")
        self.assertIn("WAF", call["why"])

    def test_network_branch(self):
        from intected.matrix import next_tool_call
        call = next_tool_call({"web": False, "network": True,
                               "waf_detected": False, "api": False,
                               "graphql": False}, [], "10.0.0.5")
        self.assertEqual(call["tool"], "nmap_services")

    def test_no_footprint_passive_only(self):
        from intected.matrix import next_tool_call
        call = next_tool_call({"web": False, "network": False,
                               "waf_detected": False, "api": False,
                               "graphql": False}, [], "10.0.0.5")
        self.assertEqual(call["tool"], "nmap_ports")


class WafKbTest(unittest.TestCase):
    def test_seed_and_query(self):
        import shutil
        from intected import config, waf_kb
        old = config.STATE_DIR
        tmp = tempfile.mkdtemp()
        config.STATE_DIR = tmp  # isolated KB dir
        try:
            path = waf_kb.seed_example()
            self.assertTrue(path.endswith("cloudflare-basics.md"))
            results = waf_kb.query("cloudflare rate limit bypass")
            self.assertTrue(results)
            self.assertIn("doc", results[0])
            self.assertGreater(results[0]["score"], 0)
            self.assertNotIn("query", waf_kb.query("zzz-unrelated-topic"))
        finally:
            config.STATE_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)


class ToolConfiguratorTest(unittest.TestCase):
    def test_safe_defaults_are_stealth(self):
        from intected.tools import SAFE_DEFAULTS
        self.assertLessEqual(SAFE_DEFAULTS["nmap_ports"]["rate"], 50)
        self.assertEqual(SAFE_DEFAULTS["ffuf_content"]["delay"], 1)
        self.assertEqual(SAFE_DEFAULTS["nuclei"]["rate_limit"], 10)
        self.assertEqual(SAFE_DEFAULTS["nuclei"]["concurrency"], 5)

    def test_safe_defaults_respected_by_execution_builder(self):
        from intected.tools import _build_command, validate_params
        merged = validate_params("nuclei", {"target": "x"})
        cmd = _build_command("nuclei", merged)
        self.assertIn("-rl", cmd)
        self.assertIn("10", cmd)
        self.assertIn("-c", cmd)
        self.assertIn("5", cmd)
        nmap_cmd = _build_command("nmap_ports",
                                  validate_params("nmap_ports",
                                                  {"target": "x"}))
        self.assertIn("--max-rate", nmap_cmd)
        self.assertIn("--data-length", nmap_cmd)
        self.assertIn("32", nmap_cmd)
        self.assertIn("-T3", nmap_cmd)


if __name__ == "__main__":
    unittest.main()
