"""Authorization-category gate tests (phishing / c2 / evasion / credential).

These tools are REJECTED by default; a mission must declare the category in
`missions.authorizations_json` (via `intected init --authz ...`).
"""

import unittest

from intected import scope


class ScopeAuthorizationGateTest(unittest.TestCase):
    def test_gated_tools_denied_without_authorization(self):
        for cmd in ("sliver generate --mtls 10.0.0.5:8888",
                    "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
                    "evilginx2 -p phishlet.conf",
                    "python3 syswhispers.py --preset all -o syscalls",
                    "Rubeus.exe kerberoast /outfile:hashes.txt",
                    "donut -f payload.exe -o payload.bin",
                    "certipy find -u u@d.local -p pass",
                    "impacket-secretsdump user@10.0.0.5"):
            with self.assertRaises(scope.ScopeViolation, msg=cmd):
                scope.check_command(cmd, ["10.0.0.5"])

    def test_gated_tool_denied_with_string_authz(self):
        """A bare string NEVER counts as authorization (strict, like aggressive)."""
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("sliver server", ["10.0.0.5"],
                                authorizations="c2")

    def test_gated_tools_allowed_with_declared_category(self):
        scope.check_command("sliver generate --mtls 10.0.0.5:8888",
                            ["10.0.0.5"], authorizations={"c2"})
        scope.check_command("mimikatz.exe \"sekurlsa::logonpasswords\"",
                            ["10.0.0.5"], authorizations=["credential"])
        scope.check_command("evilginx2 -p phishlet.conf",
                            ["10.0.0.5"], authorizations={"phishing"})
        scope.check_command("python3 syswhispers.py --preset all -o syscalls",
                            ["10.0.0.5"], authorizations={"evasion"})

    def test_authorization_does_not_relax_host_gate(self):
        with self.assertRaises(scope.ScopeViolation):
            scope.check_command("sliver generate --mtls 10.0.0.99:8888",
                                ["10.0.0.5"], authorizations={"c2"})

    def test_ungated_tools_unaffected(self):
        for cmd, allowed in (("nmap -sV 10.0.0.5", ["10.0.0.5"]),
                             ("responder -I eth0 -wv", ["10.0.0.5"]),
                             ("netexec smb 10.0.0.5 -u u -p p", ["10.0.0.5"]),
                             ("msfvenom -p linux/x64/shell_reverse_tcp "
                              "LHOST=127.0.0.1 LPORT=4444 -f elf -o shell.elf",
                              ["10.0.0.5", "127.0.0.1"]),
                             ("chisel server -p 8080 --reverse", ["10.0.0.5"]),
                             ("bloodhound --no-sandbox", ["10.0.0.5"]),
                             ("impacket-psexec user@10.0.0.5 cmd.exe",
                              ["10.0.0.5"]),
                             ("theharvester -d dvwa.local -b all",
                              ["dvwa.local"])):
            scope.check_command(cmd, allowed)


if __name__ == "__main__":
    unittest.main()
