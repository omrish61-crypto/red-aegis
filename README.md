# INTECTED — PentestDROR Co-Pilot

**INTECTED** is an AI penetration-testing co-pilot ("PentestDROR") that helps security
testers, Red Teams, and cyber researchers run structured, insight-driven pentests.

It maintains a **Pentest Task Tree (PTM)**, parses classic tool output (Nmap, FFUF,
Gobuster, Burp, Nuclei, SQLmap) into structured facts, and recommends the exact next
step with the exact command — while keeping a three-part memory architecture that
prevents LLM context loss on long engagements.

## Model routing (verified on this machine, 2026-08-10)

| Role | Model | Endpoint | Measured latency |
|---|---|---|---|
| Interactive reasoning / next-step | `deepseek-v4-flash` | bridge `127.0.0.1:11435/v1` | 0.9 s |
| Light offline tasks (classify, tiny extraction) | `llama3.2:latest` / `gemma3:4b` | bridge `:11435` | 15–17 s |
| Code-focused extraction | `qwen2.5-coder:7b` | bridge `:11435` | 25.7 s |
| Deep background reasoning | `deepseek-r1:8b` | **Ollama direct `127.0.0.1:11434`** (bridge 400s — name collision) | 52.6 s |

## Repository layout

```
INTECTED/
├── README.md                      ← this file
└── docs/
    ├── PENTESTDROR-PLAN.md        ← full build plan (the deliverable)
    └── PROJECT-DIARY.md           ← build diary, updated at every milestone
```

## Status

**G0 approved (Track B) · P0–P4 ✅ (126/126 tests, dashboard verified live,
pentest-core integration live-verified, acceptance scorecard 86.6% weighted) ·
plan complete.** See docs/ACCEPTANCE-SCORECARD.md for the quantified scorecard
and docs/CONTROL-REPORT-*.md for the independent audit verdicts.

```
P0 ✅  scaffold + schema + router + scope gate + CLI      (2026-08-10, G1 met)
P1 ✅  parsing module + evidence store + 8 extractors     (2026-08-10, G2 met)
P2 ✅  reasoning module + PTM ops + command generation    (2026-08-10, G3 met)
P3 ✅  dashboard: process + results + mission views       (2026-08-10, G4a met)
P4 ✅  pentest-core integration + hardening + scorecard   (2026-08-10, G4b met)
```

## Secure key store (secrets vault)

```
intected keys set --name <key> --file <path>|--stdin|--value <v>   # upload (file preferred)
intected keys import --file keys.env [--delete-after]              # bulk key=value upload
intected keys get --name <key> [--show]                            # masked by default
intected keys list                                                 # names + hints only
intected keys rm --name <key>
```

On Windows, values are encrypted with DPAPI (CryptProtectData) — bound to the
CURRENT WINDOWS USER's credentials, the native equivalent of Credential
Manager; the vault file (`<state>/secrets.vault`) never contains plaintext.
On other platforms the vault degrades honestly (obfuscation + 0600 perms) with
a loud warning. Values are never echoed: `get` masks to the last 4 chars
unless `--show` is passed, and audit rows record names only.

The LLM bridge (`deepseek-ollama-bridge.py`) resolves its master key as
env `DEEPSEEK_MASTER_KEY` → vault `deepseek_master` → legacy plaintext file, so
after `intected keys set --name deepseek_master --file <keyfile>` the plaintext
file can be deleted.

## pentest-core integration (P4)

```
intected pc stats [--db PATH]            # overview of the pentest-core DB
intected pc sync --run RUN_ID --mission N [--db PATH]   # import findings as facts (idempotent)
intected pc write --mission N --target T --engine E --severity S --title X [--db PATH]
                                         # scope-gated write-back (deny by default)
```

The reader opens pentest.db READ-ONLY and validates the schema; the only write
path is `pc write`, gated by MissionScope (target must be inside the mission's
allowed hosts) + a severity whitelist. Point `INTECTED_PENTEST_CORE_DB` at the
DB (e.g. a WSL path or backup copy). `intected status` reports the integration
state (probed, not assumed).
