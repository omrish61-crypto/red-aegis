# Test fixtures — REAL captured outputs

Every fixture is a genuine tool capture from the **authorized localhost lab**
(DVWA :8001, Juice Shop :3000, Tomcat :8080), copied verbatim — the older
batch from `~/.pentest-core/runs/*/raw/`, the 2026-08-10 batch direct from
kali-linux WSL against 127.0.0.1. None are synthetic.

| Fixture | Provenance | Content |
|---|---|---|
| `real-nmap-20260810.xml` | **fresh scan, this session** (`nmap -Pn -sT -sV -p 3000,8001,8080 127.0.0.1`, 2026-08-10) | Juice Shop :3000, Apache httpd 2.4.25 :8001, Apache Tomcat 10.1.36 :8080 |
| `real-nmap-juiceshop-20260809.xml` | run `localhost_3000-20260809-140817` | -sV on :3000 |
| `real-nmap-vuln-20260809.xml` | run `127.0.0.1_3000-20260809-141908` | vuln-script scan |
| `real-nmap-juiceshop-vulnscan-20260809.xml` | run `127.0.0.1_3000-20260809-141908` | nmap.xml from vuln run |
| `real-gobuster-dvwa-20260809.txt` | run `localhost_8001-20260809-131648` | 11 dir-mode paths (login.php, setup.php, vulnerabilities/…) |
| `real-gobuster-error-20260809.stderr.txt` | run `127.0.0.1_3000-20260809-141908` | gobuster timeout error (real failure capture) |
| `real-nuclei-juiceshop-20260809.jsonl` | run `localhost_3000-20260809-140817` | multiple findings (prometheus-metrics medium, …) |
| `real-sqlmap-dvwa-20260809.txt` | run `auth-sqlmap-fresh-162815` | MySQL boolean/error-based injection on GET `id` |
| `real-zap-baseline-20260809.txt` | run `127.0.0.1_3000-20260809-141908` | ZAP baseline report (PASS/WARN/FAIL) |
| `real-ffuf-dvwa-20260810.jsonl` | **fresh scan, this session** (`ffuf -u http://127.0.0.1:8001/FUZZ -w /usr/share/dirb/wordlists/common.txt -ac -t 20 -mc 200,204,301,302,307,401,403,500 -maxtime 120 -json`, kali-linux WSL, 2026-08-10) · sha256 `011f09544361837b10ac4c9d8cbb5410237bd266f04770db9473c60542f1a8e5` | 9 paths: /→login.php, config/ (301), docs/ (301), external/ (301), favicon.ico, index.php→login.php, php.ini, phpinfo.php→login.php, robots.txt |
| `real-ffuf-juiceshop-20260810.jsonl` | **fresh scan, this session** (same ffuf command vs `http://127.0.0.1:3000`, kali-linux WSL, 2026-08-10) · sha256 `e19cdb5f9c082c8d459c90caaabbb3e2754a47a131c47f03f8340b960ef527ea` | 16 paths after `-ac` wildcard auto-calibration: assets/→/assets/, media/→/media/, ftp, profile (500), robots.txt, 2.2 MB /video stream, … |
| `real-nikto-dvwa-20260810.txt` | **fresh scan, this session** (`nikto -h http://127.0.0.1:8001 -maxtime 90s -nointeractive`, kali-linux WSL, 2026-08-10) · sha256 `1dddc35684c37d33999abebb9dbf0151b080504b3847ab83da3c2dc014f2fc1a` | Apache/2.4.25 (Debian) banner, 13 findings (outdated Apache, missing security headers, /config/ dir indexing, /login.php admin page…), 2 `+ ERROR:` lines (update check 403, 90 s maxtime hit) |

Synthetic inputs appear ONLY in fault-injection tests (malformed XML, garbage
bytes, huge lines) — never as expected-finding fixtures.

| `real-ffuf-dvwa-20260811.jsonl` | **fresh scan, 2026-08-11 01:12** (same ffuf command, kali-linux WSL) · sha256 `ef6f6f08816a640c5af7997715fdcfb7732e48f6adf04047a123940ac62b723a` | 9 paths, same DVWA layout (redirects to login.php, /config 301, /docs, /robots.txt, /php.ini) |
| `real-nikto-dvwa-20260811.txt` | **fresh scan, 2026-08-11 01:12** (`nikto -h http://127.0.0.1:8001 -maxtime 90s -nointeractive`, kali-linux WSL) · sha256 `c0312733ae951f584209e2e31e4f4bfe3065b3fbd87ba91c73956798bcc45621` | Apache/2.4.25 (Debian) banner, 13 OSVDB findings (outdated Apache, missing security headers, /config/ dir indexing, /login.php admin page), completed cleanly within maxtime (0 ERROR lines — unlike the 2026-08-10 capture which hit the 90s limit) |

## Known gaps

- ~~nikto 2.6.0 OSVDB-id prefixes~~ **CLOSED 2026-08-11.** The extractor now
  lifts `[OSVDB-id]`-prefixed findings into facts (path/note with
  `nikto_osvdb`) and both `+ ERROR:` / `- ERROR:` lines into warnings
  (`intected/parsing/extractors/nikto.py`; regression tests
  `NiktoRealFixtureTest.test_osvdb_findings_parsed` +
  `ParsePipelineTest.test_pipeline_nikto_real`).
- **burp.** No burp CLI exists in this environment (Burp Suite is a GUI app and
  there is no `burpsuite`-CLI / REST-API capture path available on this host),
  so `burp` keeps its documented-format sample
  (`FormatSampleTest.test_burp_sitemap`) until a real sitemap export is
  captured. This is not faked — a real burp fixture will replace the sample
  when one is obtainable.
