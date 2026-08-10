"""Secrets vault — OS-level encrypted storage for API keys and tokens.

Windows: DPAPI (CryptProtectData) — ciphertext is bound to the CURRENT
WINDOWS USER's credentials (the native equivalent of Credential Manager); only
this user on this machine can decrypt. No passphrase, no key material on disk
in plaintext.

Other OS: honest fallback — base64 obfuscation + 0600 file permissions, with a
LOUD warning at vault creation that it is NOT encrypted. (Use `keyring`/KWallet
on Linux if stronger protection is needed.)

Vault file: <state_dir>/secrets.vault  (JSON; values stored DPAPI-encrypted).
Tamper detection: DPAPI decrypt fails on any modification. Values are NEVER
logged or echoed by the CLI (masked: last 4 chars only).
"""

import base64
import json
import os
import stat
import sys
import time

VAULT_FILENAME = "secrets.vault"
MASK_LEN = 4


class SecretsError(RuntimeError):
    """Raised for vault problems (missing entry, tamper, platform failure)."""


def _dpapi_available() -> bool:
    return sys.platform == "win32"


def _dpapi_protect(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data)
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None,
                                    None, 0, ctypes.byref(blob_out)):
        raise SecretsError("CryptProtectData failed (DPAPI)")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data)
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None,
                                      None, 0, ctypes.byref(blob_out)):
        raise SecretsError("CryptUnprotectData failed — vault tampered or "
                           "bound to a different Windows user")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


class Vault:
    """Encrypted key-value store at <state_dir>/secrets.vault."""

    def __init__(self, state_dir: str):
        self.path = os.path.join(state_dir, VAULT_FILENAME)
        self._warned_fallback = False
        self._data = self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {"vault_version": 1, "entries": {}}
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise SecretsError(f"vault corrupted (bad JSON): {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
            raise SecretsError("vault corrupted (bad structure)")
        return data

    def _save(self) -> None:
        state_dir = os.path.dirname(self.path)
        os.makedirs(state_dir, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=1)
        os.replace(tmp, self.path)
        try:  # 0600 on POSIX; no-op on Windows (ACLs govern)
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    # -- entries -------------------------------------------------------------

    def set(self, name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise SecretsError("value must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise SecretsError("value must not contain newlines")
        if not _dpapi_available() and not self._warned_fallback:
            print("WARNING: no DPAPI on this platform — vault uses obfuscation "
                  "+ 0600 perms, NOT OS encryption", file=sys.stderr)
            self._warned_fallback = True
        raw = value.strip().encode("utf-8")
        if _dpapi_available():
            blob = _dpapi_protect(raw)
        else:  # honest fallback: obfuscated + permission-protected
            blob = b"obf:" + base64.b64encode(raw)
        self._data["entries"][name] = {
            "cipher_b64": base64.b64encode(blob).decode("ascii"),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            # hint only when it can't disclose the value (len > MASK_LEN + 3)
            "hint": value.strip()[-MASK_LEN:] if len(value.strip()) > MASK_LEN + 3 else "",
        }
        self._save()

    def get(self, name: str) -> str:
        entry = self._data["entries"].get(name)
        if entry is None:
            raise SecretsError(f"no such key: {name!r}")
        try:
            blob = base64.b64decode(entry["cipher_b64"])
        except (KeyError, ValueError) as exc:
            raise SecretsError(f"key {name!r}: vault entry corrupted") from exc
        if blob.startswith(b"obf:"):
            return base64.b64decode(blob[4:]).decode("utf-8")
        return _dpapi_unprotect(blob).decode("utf-8")

    def masked(self, name: str) -> str:
        entry = self._data["entries"].get(name)
        if entry is None:
            raise SecretsError(f"no such key: {name!r}")
        return "****" + entry.get("hint", "")

    def list(self) -> dict[str, dict]:
        """name -> {hint, created_at} (never the value)."""
        return {n: {"hint": e.get("hint", ""), "created_at": e.get("created_at", "")}
                for n, e in self._data["entries"].items()}

    def remove(self, name: str) -> None:
        if name not in self._data["entries"]:
            raise SecretsError(f"no such key: {name!r}")
        del self._data["entries"][name]
        self._save()

    def has(self, name: str) -> bool:
        return name in self._data["entries"]


def default_vault() -> Vault:
    """Vault in the project's state dir (respects runtime INTECTED_STATE)."""
    from . import config
    return Vault(config.state_dir())
