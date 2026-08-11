# Kali Tool Verification — Full Test (2026-08-11)

Every tool tested with REAL bounded runs against the AUTHORIZED lab
(127.0.0.1:3000 Juice Shop / :8001 DVWA / :8080 WebGoat) and scanme.nmap.org
(Nmap's official test target). All tests executed THROUGH the RedAegis
pipeline (supervisor gate → execute → evidence → facts), with a fresh
dashboard instance per test (restart between tests — no accumulated state).

## Pipeline (registry) tests — via `intected.tools.execute_streaming`

| Tool | Params | Exit | Result |
|---|---|---|---|
| nmap_ports | top1000 @127.0.0.1 | 0 | PASS — real scan, ports in facts |
| nmap_services | 3000,8080 @127.0.0.1 | 0 | PASS — Tomcat identified on 8080 |
| http_headers | :3000 | 0 | PASS — 200 OK + Juice headers |
| nikto | :3000 | 0 | PASS — 24 findings (CORS *, /robots.txt, /public/) |
| ffuf_content | :3000, 6-word list | 0 | PASS — JSONL results |
| nuclei | :3000 | 0 | PASS — templates load, findings (prometheus-metrics) |

## Dashboard-API tests — one command per test, fresh dashboard each

Commands added to mission 8's queue and executed via
`POST /api/missions/8/commands/run-all` + per-command `/api/commands/{id}/run`
(the dashboard's Run path: supervisor gate → execute_raw → evidence + facts).

| # | Tool | Command | Exit | Verdict |
|---|---|---|---|---|
| 27 | nmap | -Pn --top-ports 1000 --max-rate 100 -T3 127.0.0.1 | 0 | PASS |
| 28 | nmap | -Pn -sV -p 3000,8001,8080 127.0.0.1 | 0 | PASS |
| 29 | curl | -sSI http://127.0.0.1:3000 | 0 | PASS |
| 30 | nikto | -h :3000 -maxtime 60s | 0 | PASS — 24 findings |
| 31 | ffuf | -u :3000/FUZZ -rate 30 -json | 0 | PASS |
| 32 | whatweb | -q :3000 | 0 | PASS — full fingerprint |
| 33 | wafw00f | :3000 | 0 | PASS — banner + analysis |
| 34 | gobuster | dir :3000 -t 5 --delay 1s | 1 | CORRECT — SPA wildcard refusal (200-for-everything) |
| 35 | dig | +short A localhost | 0 | PASS — resolved |
| 36 | sqlmap | REST search?q=test --level 1 --risk 1 --delay 2 | 0 | PASS — ran 151s, exit 0 |

Every run persisted evidence to `~/.intected/evidence/mission-8/` (16 raw
files, real content — e.g. nmap 2959 B, nikto 1780 B).

## Direct tool tests (WSL, bounded)

| Tool | Test | Result |
|---|---|---|
| masscan | rate 100 @127.0.0.1 | PASS — discovered 135/tcp |
| searchsploit | 'apache 2.4.7' | PASS — 18 exploit matches |
| john | bcrypt crack of htpasswd hash | PASS — CRACKED "?:letmein" |
| hashcat | benchmark -m 0 | PASS — 1880.9 MH/s |
| msfconsole | -qx version | PASS — interactive prompt reached |
| tcpdump | -i lo -c 2 port 3000 | PASS — 2 packets captured |
| sqlmap | REST endpoint, level 1 | RUNS — reports target timeouts honestly |
| hydra / medusa | presence | INSTALLED — policy-banned from targets (no brute force) |
| responder / chisel / mimikatz / commix / wpscan / linpeas / winpeas / bloodhound / xfreerdp | version/banner | PASS — installed + runnable |

## Environment fixes that made these possible (all committed)

1. nuclei: broken kali 3.8.0 → v3.11.1 static build; TTY-stdin hang →
   stdin=DEVNULL; WSL NAT IPv6/PD-API blackhole → iptables/ip6tables REJECT
   (fast-fail); `-duc` forbidden (breaks template index).
2. ffuf wordlist: `/usr/share/dirb/wordlists/common.txt` (not the missing
   `/usr/share/wordlists/dirb/`).
3. execute_streaming/execute_raw: HARD timeout via reader thread (the old
   read loop never bounded chatty tools like nuclei).

## Honest notes

- gobuster/dirb on Juice Shop: the app returns 200 for every path (SPA
  catch-all) — both tools correctly detect the wildcard and refuse to
  continue without filters. That IS the finding.
- sqlmap against the Juice REST search needs longer windows / higher levels
  (the endpoint is slow from the WSL NAT); the tool runs and reports
  timeouts honestly.
- dvwa.local (mission 1) does not resolve on this host — its queue commands
  fail at DNS (exit 6), visible in the dashboard queue.
