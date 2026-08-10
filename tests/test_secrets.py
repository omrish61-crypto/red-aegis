"""Canonical tests: secrets vault (DPAPI on Windows; obfuscation fallback).

Covers: set/get roundtrip, masking (never leak), list (names+hints only),
remove, tamper detection, value validation, no-plaintext-on-disk, import +
--delete-after, and the CLI surface. On Windows the DPAPI path is exercised
for real (encryption bound to the current user).
"""

import json
import os
import stat
import sys
import tempfile
import unittest

from intected import db, secrets
from intected.secrets import SecretsError, Vault


def _tmp_state() -> str:
    d = tempfile.mkdtemp(prefix="intected-vault-")
    return d


class VaultCoreTest(unittest.TestCase):
    def setUp(self):
        self.state = _tmp_state()
        self.vault = Vault(self.state)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.state, ignore_errors=True)

    def test_set_get_roundtrip(self):
        self.vault.set("api_key", "sk-abc123XYZ")
        self.assertEqual(self.vault.get("api_key"), "sk-abc123XYZ")

    def test_value_never_plaintext_on_disk(self):
        secret = "sk-super-secret-value-987654321"
        self.vault.set("k", secret)
        raw = open(os.path.join(self.state, secrets.VAULT_FILENAME),
                   encoding="utf-8").read()
        self.assertNotIn(secret, raw)          # no plaintext
        self.assertNotIn("super-secret", raw)  # not even a fragment

    def test_masked_shows_only_last4(self):
        self.vault.set("k", "sk-abcdefgh1234")
        m = self.vault.masked("k")
        self.assertEqual(m, "****1234")
        self.assertNotIn("abcdef", m)

    def test_list_never_includes_values(self):
        self.vault.set("k1", "value-one")
        self.vault.set("k2", "value-two")
        listing = self.vault.list()
        self.assertEqual(set(listing), {"k1", "k2"})
        for meta in listing.values():
            self.assertNotIn("value-", json.dumps(meta))

    def test_short_value_no_hint(self):
        """Review WARN fix: a hint must never disclose the value (values
        shorter than MASK_LEN+4 get no hint at all)."""
        self.vault.set("short", "12345")
        self.assertEqual(self.vault.masked("short"), "****")
        entry = json.load(open(self.vault.path, encoding="utf-8"))
        self.assertEqual(entry["entries"]["short"]["hint"], "")

    def test_remove(self):
        self.vault.set("k", "v")
        self.vault.remove("k")
        with self.assertRaises(SecretsError):
            self.vault.get("k")
        self.assertFalse(self.vault.has("k"))

    def test_tamper_detected(self):
        self.vault.set("k", "secret-value")
        path = self.vault.path
        data = json.load(open(path, encoding="utf-8"))
        entry = data["entries"]["k"]
        # flip a base64 char in the MIDDLE of the ciphertext (payload bytes are
        # integrity-protected by DPAPI; a header-edge flip can be tolerated)
        c = entry["cipher_b64"]
        mid = len(c) // 2
        flipped = c[:mid] + ("A" if c[mid] != "A" else "B") + c[mid + 1:]
        data["entries"]["k"]["cipher_b64"] = flipped
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        # a FRESH vault load must see the tamper (the running instance holds
        # its own in-memory view — same as any config cache)
        with self.assertRaises(SecretsError):
            Vault(self.state).get("k")

    def test_bad_value_rejected(self):
        for bad in ("", "   ", "has\nnewline"):
            with self.assertRaises(SecretsError):
                self.vault.set("k", bad)

    def test_corrupt_vault_file(self):
        with open(os.path.join(self.state, secrets.VAULT_FILENAME), "w",
                  encoding="utf-8") as f:
            f.write("{ not json")
        with self.assertRaises(SecretsError):
            Vault(self.state)

    def test_vault_file_perms_restricted_on_posix(self):
        if sys.platform == "win32":
            self.skipTest("POSIX perms not applicable on Windows (ACLs)")
        self.vault.set("k", "v")
        mode = stat.S_IMODE(os.stat(self.vault.path).st_mode)
        self.assertEqual(mode & 0o077, 0)  # no group/other access

    def test_dpapi_bound_to_user_on_windows(self):
        """DPAPI roundtrip must succeed for the current user (real crypto)."""
        if sys.platform != "win32":
            self.skipTest("DPAPI is Windows-only")
        self.vault.set("k", "dpapi-roundtrip-value")
        self.assertEqual(self.vault.get("k"), "dpapi-roundtrip-value")


class VaultCliTest(unittest.TestCase):
    def setUp(self):
        self.state = _tmp_state()
        fd, self.src = tempfile.mkstemp(prefix="keys-", suffix=".env")
        os.close(fd)
        self._old_state = os.environ.get("INTECTED_STATE")
        os.environ["INTECTED_STATE"] = self.state

    def tearDown(self):
        import shutil
        if self._old_state is None:
            os.environ.pop("INTECTED_STATE", None)
        else:
            os.environ["INTECTED_STATE"] = self._old_state
        shutil.rmtree(self.state, ignore_errors=True)
        if os.path.exists(self.src):
            os.unlink(self.src)

    def test_cli_set_get_masked_and_show(self):
        from intected.cli import main
        rc = main(["keys", "set", "--name", "demo", "--value", "sk-demo-9999"])
        self.assertEqual(rc, 0)
        rc = main(["keys", "get", "--name", "demo"])
        self.assertEqual(rc, 0)  # masked output, no value echoed
        rc = main(["keys", "get", "--name", "demo", "--show"])
        self.assertEqual(rc, 0)

    def test_cli_import_and_delete_after(self):
        from intected.cli import main
        with open(self.src, "w", encoding="utf-8") as f:
            f.write("# comment line\nfirst_key=value-1\nsecond_key=value-2\n")
        rc = main(["keys", "import", "--file", self.src, "--delete-after"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.src))  # plaintext source removed
        v = Vault(self.state)
        self.assertEqual(v.get("first_key"), "value-1")
        self.assertEqual(v.get("second_key"), "value-2")
        # audit trail exists and contains NO values
        conn = db.connect(os.path.join(self.state, "intected.db"))
        rows = conn.execute(
            "SELECT detail FROM audit WHERE action LIKE 'keys.%'").fetchall()
        self.assertTrue(rows)
        self.assertFalse(any("value-1" in r[0] or "value-2" in r[0] for r in rows))

    def test_cli_import_skips_garbage_lines(self):
        from intected.cli import main
        with open(self.src, "w", encoding="utf-8") as f:
            f.write("ok=1\nno-equals-here\n# comment\nanother=2\n")
        rc = main(["keys", "import", "--file", self.src])
        self.assertEqual(rc, 0)
        v = Vault(self.state)
        self.assertEqual(v.get("ok"), "1")
        self.assertEqual(v.get("another"), "2")

    def test_cli_requires_name(self):
        """Review WARN fix: set/get/rm without --name must fail."""
        from intected.cli import main
        self.assertNotEqual(main(["keys", "set", "--value", "x"]), 0)
        self.vault = Vault(self.state)
        self.vault.set("named", "value-1")
        self.assertNotEqual(main(["keys", "get"]), 0)
        self.assertNotEqual(main(["keys", "rm"]), 0)

    def test_cli_rm(self):
        from intected.cli import main
        main(["keys", "set", "--name", "tmp", "--value", "x"])
        rc = main(["keys", "rm", "--name", "tmp"])
        self.assertEqual(rc, 0)
        self.assertFalse(Vault(self.state).has("tmp"))


if __name__ == "__main__":
    unittest.main()
