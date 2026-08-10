# CONTROL-REPORT-SECRETS.md — Independent security review: secrets vault feature

- **Date:** 2026-08-11
- **Reviewer:** independent CONTROL subagent (read-only; no git commands; live key never printed — only masked `****` + last-4, lengths, and booleans appear in this report)
- **Scope:** `intected/secrets.py` (DPAPI vault), `intected keys` CLI (`cmd_keys`, `intected/cli.py`), `config.state_dir()/db_path()` lazy resolution (`intected/config.py`), bridge integration (`~/deepseek-ollama-bridge.py` `master_key()`), `tests/test_secrets.py`, live vault at `~/.intected/secrets.vault`, plus user-requested fact #18 evidence-chain verification.

## 1. Verdict table

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| 1 | Full test suite green | **PASS** | `uv run pytest -q` → `155 passed, 1 skipped in 6.74s` (verbatim below). Count matches the expected 155+1. |
| 2 | `tests/test_secrets.py` | **PASS** | `13 passed, 1 skipped`; the skip is `test_vault_file_perms_restricted_on_posix` (correctly skipped on win32 — ACLs govern, POSIX perms N/A). |
| 3 | DPAPI bound to current user, no passphrase on disk | **PASS** | `secrets.py:48-49`: `CryptProtectData(..., None, None, None, None, 0, ...)` — `dwFlags=0` → **current-user scope** (no `CRYPTPROTECT_LOCAL_MACHINE`), no entropy, no passphrase anywhere in code or vault JSON (only `cipher_b64` + `created_at` + `hint`). `test_dpapi_bound_to_user_on_windows` ran real crypto on win32 and PASSED; live vault `get` succeeds. |
| 4 | Vault file contains no plaintext key | **PASS** | Probe on live `~/.intected/secrets.vault`: `VAULT_PLAINTEXT_KEY_IN_FILE: False`; head of file is JSON `{"vault_version":1,"entries":{"deepseek_master":{"cipher_b64":…` — values stored only as DPAPI blobs (base64-wrapped). |
| 5 | Masking never leaks values | **PASS** | `cli.py:291` `get` prints `name: ****<hint>` unless `--show`; `cli.py:302` `list` prints `****` + hint only; `secrets.py:148-157` masked()/list() return hints, never values. Live probe: `CLI_SET_LEAKS_VALUE: False`, `CLI_GET_MASKED_LEAKS_VALUE: False` (output `t: ****c21x`), `CLI_LIST_LEAKS_VALUE: False`. |
| 6 | Audit rows never contain values | **PASS** | `cli.py:276-278` (`keys.set` → `name=… source=arg/file/stdin`), `:306` (`keys.rm` → name), `:330-331` (`keys.import` → `file=… keys=N`). Probe on a TEMP state DB (per brief): `AUDIT_LEAKS_VALUE: False`, sample row `name=t source=arg`. Live DB has exactly 1 `keys.*` row (`keys.set`). |
| 7 | Tamper detection works | **PASS** | `secrets.py:69-72`: `CryptUnprotectData` failure → `SecretsError("vault tampered or bound to a different Windows user")`. Unit test `test_tamper_detected` PASSED; **independent probe on a copy of the REAL vault** (mid-ciphertext base64 flip): `TAMPER_DETECTED: YES -> CryptUnprotectData failed — vault tampered or bound to a different Win…`. |
| 8 | `--delete-after` only deletes on success | **PASS** | `cli.py:275-280`: `vault.set()` raises `SecretsError` → `except` at `:340` → file NOT removed; `cli.py:328-333` (import): remove only after the loop. Probe: failure path (`set --file empty --delete-after`) → RC 1, `DELETE_AFTER_FAIL_KEEPS_FILE: True`; success path → `DELETE_AFTER_SUCCESS_DELETES: True`. |
| 9 | No key material in repo / git | **PASS** | 1,659 files scanned (INTECTED tree + bridge + `~/.deepseek` + `~/.intected`) for the real key bytes: **zero hits in the repo**. `.git/objects` loose-object zlib scan: no hits; **no pack files exist** (`.git/objects/pack/` empty), so the loose-object scan covers the entire git object DB — key was never committed. |
| 10 | Bridge resolves key from vault first, falls back safely | **PASS** (with WARN, see #11) | `bridge:33-48`: env `DEEPSEEK_MASTER_KEY` → vault `deepseek_master` (`:40-41` `if vault.has(): return vault.get()`) → legacy plaintext file → `""`. Probe: `BRIDGE_KEY_EQUALS_VAULT: True`, `LEN: 64`; live `:11435` serves **10 models** incl. `deepseek-v4-flash`/`deepseek-v4-pro` — consistent with vault-only operation. |
| 11 | Silent `except` cannot mask real failures — **evaluation** | **WARN** | `bridge:42-43` `except Exception: pass` CAN mask a real failure: vault tamper/corruption is swallowed and the bridge silently downgrades to the legacy plaintext file (`:44-48`). If that file also holds a stale/revoked key, requests 401 with the root cause invisible; if the file is gone, `master_key()` returns `""` → `Bearer ` empty → upstream 401 (visible, but misdiagnosable). No security downgrade vs. pre-feature state (the file was always the fallback), but tamper detection is defeated at the integration layer. **Fix:** log vault failures to stderr (never the key), and fail loud when the vault file exists but cannot be decrypted. |
| 12 | Legacy plaintext key still on disk | **WARN** | `~/.deepseek/master_key` **exists right now** (66 bytes, mtime 2026-08-09) and its content is the real key in plaintext — outside the repo (no CRITICAL), but the brief's premise ("temporarily moved aside") no longer holds on this host. The bridge prefers the vault, so this file is redundant. **Fix:** delete it now that the vault is verified as the sole working source. |
| 13 | `keys set --value` argv exposure | **WARN** | `cli.py:489` help text correctly warns "avoid — prefer --file/--stdin"; a `--value` key is visible in the process command line (tasklist/WMI) and shell history. Mitigated by guidance; consider blocking `--value` for names containing `master`/`key` or removing the flag. |
| 14 | `hint` = last-4 stored in plaintext | **WARN** | `secrets.py:132,152`: hint is the value's last 4 chars. For values ≤ 4 chars the hint IS the whole value (complete disclosure in the vault JSON and `list` output). Fix: store hint only when `len(value) >= MASK_LEN`, else `""`. |
| 15 | Bridge vault path ignores `INTECTED_STATE` | **WARN** | `bridge:39` hardcodes `~/.intected` instead of `config.state_dir()`; a bridge run under a different `INTECTED_STATE` silently misses the vault and falls to the plaintext file. |
| 16 | `--name` not enforced as required | **WARN** | `cli.py:488` `--name` is optional; `keys set --value x` (no name) stores under dict key `None` → serialized as JSON `"null"` (`secrets.py:129`) — retrievable only as `get("null")`. Robustness, not confidentiality. Fix: `required=True` for set/get/rm. |
| 17 | `keys get` (incl. `--show`) not audited | **INFO** | No `keys.get` audit row is written (`cli.py:287-293`). A secret read with `--show` leaves no trail. Fix: `db.log_audit(…, "keys.get", f"name=… show={args.show}")` (never the value). |
| 18 | POSIX fallback honesty + perms | **PASS** | `secrets.py:120-123` prints a LOUD stderr warning when DPAPI is unavailable; `_save()` chmods 0600 (`:108-111`); test `test_vault_file_perms_restricted_on_posix` asserts mode&0o077==0 (skipped on win32, valid on POSIX). Fallback is documented as obfuscation, not encryption. |

## 2. Evidence-chain verification (user request — fact #18 modal)

| Check | Result |
|---|---|
| DB row `facts id=18` | `mission_id=3, tool=nmap, fact_type=port, value_json={"port": 3000, "protocol": "tcp"}` |
| `sha256` in row | `0a2585962281387eb20a7783a3f27d5435c6d0debb6e583ad7c7431dad965f67` |
| File on disk | `~/.intected/evidence/mission-3/nmap-0a2585962281.raw` — recomputed sha256: `0a2585962281387eb20a7783a3f27d5435c6d0debb6e583ad7c7431dad965f67` → **MATCH (byte-for-byte)** |
| `evidence_ref` resolves | `True` (stored ref mixes `\` and `/` separators, but basename matches and the file exists) |
| Content head | `Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-11 00:36 +0300` / `Nmap scan report for localhost (127.0.0.1)` / `3000/tcp open ppp?` — the nmap banner the modal showed. **AUTHENTIC.** |

**Verdict on fact #18:** the user-pasted evidence modal is fully verified — DB sha256 == disk sha256 == expected `0a…f67`, and the file begins with the Nmap 7.99 banner. The `3000/tcp` fact is real and backed by the exact evidence file referenced.

## 3. Verbatim test output

Mandated invocation (from repo root):

```
$ uv run pytest -q
........................................................................ [ 46%]
........................................................................ [ 92%]
.......s....                                                             [100%]
============================== warnings summary ===============================
.venv\Lib\site-packages\fastapi\testclient.py:1
  C:\Users\onris\INTECTED\.venv\Lib\site-packages\fastapi\testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
155 passed, 1 skipped, 1 warning in 6.74s
```

Targeted secrets suite:

```
$ uv run pytest tests/test_secrets.py -v
… 14 items collected; 13 passed, 1 skipped in 0.21s
  (skip: test_vault_file_perms_restricted_on_posix — POSIX perms not applicable on win32)
  (test_dpapi_bound_to_user_on_windows PASSED — real DPAPI roundtrip executed on this host)
```

All 14 secrets tests exercised real code paths (DPAPI encrypt/decrypt, tamper flip, audit-content assertions, delete-after both branches); the suite's only skip is platform-appropriate.

## 4. Issues summary

- **WARN #11 (bridge silent except)** — the only finding that touches tamper detection end-to-end; one-line fix (stderr log + fail loud on corrupt vault).
- **WARN #12 (legacy plaintext file present)** — action item for the operator: delete `~/.deepseek/master_key` (vault is verified working; bridge already prefers it).
- **WARN #13–16** — hardening/robustness (argv exposure guidance, short-value hint, INTECTED_STATE consistency, `--name` enforcement).
- **INFO #17** — audit coverage for `keys get --show`.
- No CRITICAL, no HIGH, no FAIL. No findings in the repo tree; no key material ever committed to git.

## 5. Overall verdict

# **APPROVED**

The secrets vault (DPAPI key store + `keys` CLI + bridge integration) is secure for its threat model: values are DPAPI-encrypted and bound to the current Windows user, never plaintext on disk, never leaked by the CLI or audit log, tamper-evident, and `--delete-after` is success-gated. The bridge resolves the key from the vault first and serves 10 models from it. The fact-#18 evidence modal is authentic (sha256 chain verified). The WARN items above are recommended hardening, not blockers — with #12 (delete the legacy plaintext file) and #11 (make the bridge's vault failure audible) recommended for immediate follow-up.

---

## RESOLUTION (2026-08-11 01:45) — WARN items addressed by fix-forward

- **Bridge vault failure now audible**: `deepseek-ollama-bridge.py` prints a
  stderr warning ("secrets vault unavailable (…)") instead of silently
  downgrading to the plaintext file — a tampered vault can no longer mask
  itself. The key value is never part of the message.
- **`--name` required** for `keys set/get/rm` (argparse + runtime guard).
- **`keys get --show` is audited** (`keys.get_show` row, name only).
- **Hint suppression**: values shorter than `MASK_LEN+4` store no hint, so a
  masked value can never disclose a short value (masked → `****`).
- Tests added (`test_short_value_no_hint`, `test_cli_requires_name`); full
  suite now **157 passed, 1 skipped**.
