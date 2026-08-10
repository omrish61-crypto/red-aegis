"""Canonical tests: MissionScope hard gate."""

import unittest

from intected import scope


class ScopeHostTest(unittest.TestCase):
    def test_exact_ip_allowed(self):
        scope.check_target("10.0.0.5", ["10.0.0.5"])
        scope.check_target("http://10.0.0.5:8080/path", ["10.0.0.5"])

    def test_cidr_allowed(self):
        scope.check_target("10.0.0.42", ["10.0.0.0/24"])

    def test_subdomain_of_allowed_hostname(self):
        scope.check_target("app.dvwa.local", ["dvwa.local"])
        scope.check_target("https://app.dvwa.local:8443/login", ["dvwa.local"])

    def test_deny_by_default(self):
        with self.assertRaises(scope.ScopeViolation):
            scope.check_target("10.0.0.99", ["10.0.0.5"])
        with self.assertRaises(scope.ScopeViolation):
            scope.check_target("evil.com", ["dvwa.local"])
        with self.assertRaises(scope.ScopeViolation):
            scope.check_target("dvwa.evil.com", ["dvwa.local"])  # suffix, not subdomain

    def test_no_allowed_hosts_refuses_everything(self):
        with self.assertRaises(scope.ScopeViolation):
            scope.check_target("10.0.0.5", [])


class ScopeTargetValidateTest(unittest.TestCase):
    """Dashboard target input (IP / domain / IP range) — validate_target."""

    def test_accepts_ipv4(self):
        self.assertEqual(scope.validate_target("10.0.0.5"), "10.0.0.5")

    def test_accepts_domain(self):
        self.assertEqual(scope.validate_target("Example.COM"), "example.com")

    def test_accepts_ipv4_range(self):
        self.assertEqual(scope.validate_target("192.168.1.0/24"), "192.168.1.0/24")

    def test_accepts_ipv6(self):
        self.assertEqual(scope.validate_target("2001:db8::1"), "2001:db8::1")

    def test_rejects_out_of_range_octet(self):
        with self.assertRaises(ValueError):
            scope.validate_target("10.0.0.999")

    def test_rejects_url(self):
        for bad in ("http://example.com", "https://evil.com/x", "example.com/path"):
            with self.assertRaises(ValueError):
                scope.validate_target(bad)

    def test_rejects_garbage(self):
        for bad in ("", "   ", "a b c", "10.0.0.1:8080", "1.2.3", "-bad-.com",
                    "192.168.1.0/33", "10.0.0.1/abc"):
            with self.assertRaises(ValueError):
                scope.validate_target(bad)


class ScopeCommandTest(unittest.TestCase):
    def test_command_with_in_scope_hosts_passes(self):
        scope.check_command("nmap -sV 10.0.0.5", ["10.0.0.5"])
        scope.check_command("ffuf -u http://dvwa.local/FUZZ -w list.txt", ["dvwa.local"])

    def test_command_with_out_of_scope_host_rejected(self):
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("nmap -sV 10.0.0.99", ["10.0.0.5"])
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("hydra -l admin 10.0.0.5 1.2.3.4", ["10.0.0.5"])

    def test_destructive_marker_requires_strict_true(self):
        cmd = "sqlmap -u http://10.0.0.5/x?id=1 --drop"
        # string "true" must NOT count as approval (proven pentest-core pitfall)
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command(cmd, ["10.0.0.5"], aggressive="true")
        # different destructive family also gated:
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("rm -rf /tmp/x && nmap 10.0.0.5", ["10.0.0.5"])
        # approved path: strict True + in-scope hosts
        scope.check_command(cmd, ["10.0.0.5"], aggressive=True)

    def test_host_token_extraction(self):
        tokens = scope.host_tokens("nmap -sV 10.0.0.5 && curl http://dvwa.local/a")
        self.assertIn("10.0.0.5", tokens)
        self.assertIn("dvwa.local", tokens)

    def test_key_value_script_args_are_not_hosts(self):
        """PITFALL FIX (live 2026-08-10): nmap --script-args http-fetch.paths=/metrics
        was falsely rejected — `http-fetch.paths` looks like a hostname."""
        cmd = ("nmap -Pn -p 3000 --script http-fetch "
               "--script-args http-fetch.paths={/metrics} 127.0.0.1")
        scope.check_command(cmd, ["127.0.0.1"])  # must NOT raise
        # a real out-of-scope host in an arg value is STILL caught
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command('curl -s http://dvwa.local/ -H "Host: evil.example.com"',
                                ["dvwa.local"])
        # an out-of-scope IP in a spoof header is still a host token
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command('curl -s http://dvwa.local/ -H "X-Forwarded-For: 1.2.3.4"',
                                ["dvwa.local"])

    def test_equals_skip_cannot_bypass_scope(self):
        """CONTROL-REVIEW H1 (live-verified bypass): any host token followed by
        `=` was exempted. IP literals and URL-context hosts are ALWAYS checked."""
        # positional IP with = suffix (reviewer's exploit) -> must raise
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("nmap -sV 10.0.0.99=x", ["10.0.0.5"])
        # out-of-scope host inside a URL value -> must raise
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("curl -s http://dvwa.local/ -e http://evil.com= "
                                "http://dvwa.local/", ["dvwa.local"])
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("curl --url=http://evil.com= http://dvwa.local/",
                                ["dvwa.local"])
        # hostname-shaped bare option name still exempted (legit script-args)
        scope.check_command("nmap -Pn -p 3000 --script http-fetch "
                            "--script-args http-fetch.paths=/metrics 127.0.0.1",
                            ["127.0.0.1"])
        # in-scope value assignment passes
        scope.check_command("curl --url=http://dvwa.local/a http://dvwa.local/",
                            ["dvwa.local"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
