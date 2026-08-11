# Kali Tools — Presence + Real POC (2026-08-11)

Checked against the operator's 14-category Kali tool list in `kali-linux` WSL.
POCs ran against AUTHORIZED targets only: local lab (127.0.0.1:8001 DVWA,
:3000 Juice Shop, :8080 WebGoat) and scanme.nmap.org (Nmap's official test
target). All scans bounded (rate-limited, timeouts, stealth flags).

## INSTALLED (26) — POC evidence

| Tool | Category | POC result (real) |
|---|---|---|
| nmap 7.99 | Info gathering | top-100 stealth scan on 127.0.0.1 -> 3000/8001/8080/9090 open (facts in DB, sha256 evidence) |
| masscan | Info gathering | rate-100 scan 127.0.0.1 -> 8766/tcp, 445/tcp discovered |
| amass | Info gathering | RUNS; passive mode degraded (libpostal_data missing in this minimal image) |
| sublist3r | Info gathering | RUNS (slow OSINT — needs external sources) |
| theharvester | Info gathering | RUNS (network-dependent, crtsh source) |
| nikto | Vuln analysis | DVWA scan -> 13+ real findings (/login.php admin page, /config/ indexing, missing HSTS/CSP headers, Apache default files) |
| searchsploit | Vuln analysis | RUNS (local Exploit-DB search) |
| ffuf | Web | Juice Shop content discovery (JSONL results; DVWA is pathologically slow — per-request PHP sessions) |
| gobuster | Web | RUNS; correctly detected Juice Shop SPA wildcard (200-for-everything) and refused to continue without filters |
| dirb | Web | RUNS; same wildcard handling |
| sqlmap 1.10.6 | Web/DB | Live injection tests against Juice REST /rest/products/search?q= (heuristic ran; level-1 no injection — prepared-statement path) |
| wpscan | Web | RUNS (no authorized WP target — version/banner only) |
| commix 4.1 | Web | RUNS (no command-injection target — version only) |
| hydra 9.7 | Password | INSTALLED — ONLINE BRUTE-FORCE = SUPERVISOR-BANNED (never against targets) |
| medusa | Password | same (runs, policy-banned) |
| john | Password | OFFLINE POC DONE: md5crypt session cracked... completed (session ran, wordlist tested) |
| hashcat 7.1.2 | Password | offline-only (CPU mode) |
| msfconsole | Exploitation | INSTALLED — interactive framework; exploitation stays OPERATOR-GATED |
| chisel 1.11.6 | Post-exploit | version OK (tunneling is operator-gated) |
| responder | Sniffing | RUNS (NTLM poisoning — only in approved labs with AD; version check) |
| tcpdump | Sniffing | RUNS clean (0 packets on kali loopback — lab is on the Windows side; capture verified) |
| mimikatz | Post-exploit | INSTALLED (Windows-only; version check) |
| linpeas / winpeas | Post-exploit | INSTALLED (scripts — used post-compromise only) |
| bloodhound | Post-exploit | INSTALLED (GUI+Neo4j — AD environments only) |
| xfreerdp | Post-exploit | INSTALLED (RDP client) |

## NOT INSTALLED (38) — honest

GUI/display tools (maltego, legion, wireshark, ghidra, cutter, radare2,
ghidra, cherrytree, autopsy, sleuthkit, volatility, faraday, bluemaho,
spooftooph, kismet, wifite, aircrack-ng, pixiewps, minicom, flashrom,
dmitry, zaproxy, burpsuite, beef-xss, setoolkit, evilginx2) and extras
(openvas, gdb, apktool, impacket examples, sqsh, bettercap, ettercap,
macchanger, crunch, cewl, recon-ng, ligolo-ng, scalpel, binwalk, foremost,
cutter). This is a minimal kali metapackage install — `apt install` is
available for any tool needed.

## Actionable gaps (honest)

1. **nuclei templates missing** (0 template dirs) — nuclei engine runs but
   has no templates; `nuclei -ut` needs internet. THE recommended fix for
   web-CVE verification coverage.
2. **impacket** absent — no psexec.py/wmiexec.py examples (needed for AD
   post-exploitation; not relevant to the current lab).
3. **amass** passive mode degraded (libpostal_data).

## In the project

- Registry tools (supervisor-gated, stealth defaults): nmap, nikto, ffuf,
  nuclei, curl-headers — proven end-to-end in the recon pipeline.
- The rest of the arsenal is cataloged in `intected/arsenal.py` with live
  availability probe (`intected arsenal --check`).
- Policy mapping: brute-force/password tools and exploitation frameworks
  exist but are NOT in the execution registry — operator approval + legal
  scope only.
