# Test fixtures — REAL captured outputs

Every fixture is a genuine tool capture from the **authorized localhost lab**
(DVWA :8001, Juice Shop :3000, Tomcat :8080), copied verbatim from
`~/.pentest-core/runs/*/raw/`. None are synthetic.

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

Synthetic inputs appear ONLY in fault-injection tests (malformed XML, garbage
bytes, huge lines) — never as expected-finding fixtures.
