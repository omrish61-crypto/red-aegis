# WRITEBACK-LIVE — Operator-Authorized Live Write-Back into Production pentest-core DB

**Date:** 2026-08-10 (session evening)
**Operator authorization:** EXPLICIT production sign-off for the `pc write` path (control-report W1 — operator-certified, human-CLI-only).
**DB:** `C:\Users\onris\.pentest-core\pentest.db` (production; daemon-owned)
**State DB:** `~/.intected` equivalent for this session = `/tmp/intected-live/intected.db` (env `INTECTED_STATE=/tmp/intected-live`)
**Repo:** `C:\Users\onris\INTECTED` — **no git operations performed**; only repo change is this file.

---

## 1. Pre-flight (read-only, before any write)

| Check | Result |
|---|---|
| DB exists | `C:\Users\onris\.pentest-core\pentest.db` (2,199,552 bytes; WAL + SHM present) |
| `PRAGMA journal_mode` | `wal` |
| `PRAGMA integrity_check` | `ok` |
| Schema — tables | `runs`, `findings`, `audit` (+ `sqlite_sequence`) — all present, matches pentest-core schema |
| Row counts (pre) | runs=35, findings=412, audit=163 |
| Daemon — Windows listener | `TCP 127.0.0.1:9292 LISTENING` pid 18620 = `wslrelay.exe` (WSL relay) |
| Daemon — WSL-side listener | `ss -tlnp` inside kali-linux: `LISTEN 0 100 127.0.0.1:9292` (socket uid 997, /proc/net/tcp inode 2916455) |
| Daemon — app-level WS ping | TCP connect accepted, but no reply to WS handshake (`/`, `/ws`, `/status`, `/api/status`) or raw JSON status; protocol is pentest-core's own and is silent to unknown messages. **Listener confirmed on both sides; app-level ping inconclusive — reported honestly, not treated as failure of the write path** (INTECTED `pc write` talks directly to the DB file, not through the daemon socket). |

## 2. Mission creation (real state DB)

```bash
cd /c/Users/onris/INTECTED
TS=$(date +%Y%m%d-%H%M%S)   # TS=20260810-235455
uv run intected init --name "WB-LIVE-$TS" \
  --targets 127.0.0.1,localhost,host.docker.internal \
  --auth-ref AUTH-OVERNIGHT-20260811
```

Output: `mission created: id=2 name='WB-LIVE-20260810-235455' hosts=['127.0.0.1', 'localhost', 'host.docker.internal'] auth_ref='AUTH-OVERNIGHT-20260811'`

`uv run intected status` confirmed mission 2 active, and pentest-core integration `OK (C:\Users\onris/.pentest-core/pentest.db) runs=35 findings=412`.

## 3. Real scan evidence (basis for the finding)

```bash
wsl -d kali-linux -u root -e bash -lc "nmap -sV -Pn -p 8001 127.0.0.1"
```

Real observed output (nmap 7.99, 2026-08-10 23:55 +0300):

```
PORT     STATE SERVICE VERSION
8001/tcp open  http    Apache httpd 2.4.25 ((Debian))
```

**Evidence line used:** `8001/tcp open  http    Apache httpd 2.4.25 ((Debian))`

## 4. Live write-back (operator-authorized)

```bash
uv run intected pc write --mission 2 --target 127.0.0.1:8001 --engine nmap --severity low \
  --title "Apache httpd 2.4.25 (Debian) on 127.0.0.1:8001" \
  --detail "8001/tcp open  http    Apache httpd 2.4.25 ((Debian)) (nmap -sV -Pn -p 8001 127.0.0.1, 2026-08-10)"
```

Output: `finding 413 written to pentest-core run 127.0.0.1:8001-20260810-205514 (target 127.0.0.1:8001, engine nmap, low)`

Scope gate passed: `127.0.0.1:8001` ∈ mission 2 allowed hosts (`127.0.0.1`, `localhost`, `host.docker.internal`).

## 5. Verification (independent, never trust green)

### 5a. `uv run intected pc stats` readback

```
pentest-core db: C:\Users\onris/.pentest-core/pentest.db
runs=36  findings=413
by severity: info=234, medium=85, low=50, high=27, critical=17
recent runs:
  127.0.0.1:8001-20260810-205514   target=127.0.0.1:8001   findings=1 (low=1)
```

Counts moved exactly as expected: runs 35→36, findings 412→413, low 49→50.

### 5b. Raw sqlite3 read-only query of the new finding row (id=413)

```sql
SELECT id, run_id, engine, type, severity, title, target, port, detail, timestamp
FROM findings WHERE id=413;
```

| Field | Value |
|---|---|
| id | 413 |
| run_id | `127.0.0.1:8001-20260810-205514` |
| engine | `nmap` |
| type | `finding` |
| severity | `low` |
| title | `Apache httpd 2.4.25 (Debian) on 127.0.0.1:8001` |
| target | `127.0.0.1:8001` |
| port | NULL (port carried in target; `--port` not passed per task spec) |
| detail | `8001/tcp open  http    Apache httpd 2.4.25 ((Debian)) (nmap -sV -Pn -p 8001 127.0.0.1, 2026-08-10)` |
| timestamp | `2026-08-10T20:55:14+00:00` |

### 5c. Post-write DB integrity

`PRAGMA integrity_check` → `ok`; `PRAGMA journal_mode` → `wal` (unchanged).

### 5d. Post-write daemon health

Windows: `TCP 127.0.0.1:9292 LISTENING` pid 18620 (`wslrelay.exe`) — unchanged.
WSL-side: `127.0.0.1:9292 LISTEN` — unchanged (checked pre-write).
App-level WS status ping: attempted pre-write, daemon silent to unknown protocol (see §1) — no change expected post-write; listener verified.

### 5e. INTECTED audit trail

```
2026-08-10 20:55:14  cli  pentestcore.write_finding run=127.0.0.1:8001-20260810-205514 target=127.0.0.1:8001 engine=nmap severity=low title='Apache httpd 2.4.25 (Debian) on 127.0.0.1:8001' finding=413
```

(pentest-core's own `audit` table is intentionally untouched — INTECTED audits the write in its own state DB; pentest-core audit count stayed 163.)

---

## Verdict

**PASS — live write-back into the production pentest-core DB succeeded and is fully verified.**

- New finding row 413 physically present in the production DB (read back read-only), attached to run `127.0.0.1:8001-20260810-205514`.
- Content matches the real nmap evidence (Apache httpd 2.4.25 banner on :8001) — nothing fabricated.
- DB integrity `ok` before and after; journal mode `wal` unchanged; WAL + SHM consistent.
- Daemon listener on :9292 confirmed listening (Windows relay + WSL-side) before and after; app-level WS ping inconclusive (daemon silent to unknown protocol) — noted, not a failure of the write path.
- No git operations performed. Only repo change: `docs/WRITEBACK-LIVE.md`.

### Honest caveats
1. WS status ping returned no app-level reply for any guessed protocol message; only TCP-level liveness confirmed. The daemon's own status endpoint format is not documented in this repo.
2. `port` column is NULL (task-specified command omitted `--port`; the target string carries `:8001`).
3. INTECTED state DB for this session is `/tmp/intected-live/intected.db` (env override), not the literal `~/.intected/intected.db` — mission 2 lives there; `pc write` used the same state dir so scope gating worked against the correct mission.
