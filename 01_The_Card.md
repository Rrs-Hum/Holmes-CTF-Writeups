# Holmes CTF 2025 – The Card

**Category:** Blue Team  
**Difficulty:** Easy  
**Author:** Hack The Box  

---

## 🕵️ Challenge Brief

> Holmes receives a breadcrumb from Dr. Nicole Vale — fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed *JM*.

## Artifacts Provided

| File                     | SHA-256                                                              |
|--------------------------|----------------------------------------------------------------------|
| `Chapter1_The_Card.zip` | `99efc494ac61456dbe9560a24ca291a896df43b03c9abc6923984fe89060dd5b` |

## Skills Learned

- Log Analysis
- Extracting and Analyzing IOCs
- Threat Intelligence Pivoting

**Task:** Analyze the honeypot logs and CTI data to answer the following:

---

## Answers (TL;DR)

1) **First User-Agent used by the attacker:** `Lilnunc/4A4D — SpecterEye`  
2) **Web shell file name:** `temp_4A4D.php`  
3) **Exfiltrated database name:** `database_dump_4A4D.sql`  
4) **Recurring string:** `4A4D`  
5) **CTI (IP:port #1) — linked campaigns:** `5`  
6) **Total tools + malware across those campaigns:** `9`  
7) **Repeated malware SHA-256:** `7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477`  
8) **CogWork Security Platform (IP:port #2) — malware connects to IP:** `74.77.74.77`  
9) **Persistence file full path:** `/opt/lilnunc/implant/4a4d_persistence.sh`  
10) **CogNet Scanner (IP:port #3) — open ports:** `11`  
11) **Owning organization of the IP:** `SenseShield MSP`  
12) **Service banner cryptic message:** `He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE`  


---

## Environment

- **Host:** Kali Linux  
- **Tooling:** `bash`, `awk`, `grep`, `curl`, `jq`, `nmap`, `whois`  
- **Workflow:** logs → WAF bypass & web-shell → exfil traces → CTI enrichment → malware IOC pivot → infra recon

---

## Investigation Workflow (Mapped to Q1–Q12)

### 1) First User-Agent against the honeypot
**Method**  
Listed the first 10 access-log entries to identify the earliest request and extract its `User-Agent`.

```bash
head -10 access.log

```console
2025-05-01 08:23:12 121.36.37.224 - - [01/May/2025:08:23:12 +0000] "GET /robots.txt HTTP/1.1" 200 847 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:23:45 121.36.37.224 - - [01/May/2025:08:23:45 +0000] "GET /sitemap.xml HTTP/1.1" 200 2341 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:12 121.36.37.224 - - [01/May/2025:08:24:12 +0000] "GET /.well-known/security.txt HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:23 121.36.37.224 - - [01/May/2025:08:24:23 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:24:34 121.36.37.224 - - [01/May/2025:08:24:34 +0000] "GET /login HTTP/1.1" 200 4521 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:01 121.36.37.224 - - [01/May/2025:08:25:01 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:12 121.36.37.224 - - [01/May/2025:08:25:12 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:23 121.36.37.224 - - [01/May/2025:08:25:23 +0000] "GET /database HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-01 08:25:34 121.36.37.224 - - [01/May/2025:08:25:34 +0000] "GET /backup HTTP/1.1" 404 162 "-" "Lilnunc/4A4D - SpecterEye"
2025-05-03 14:12:43 121.36.37.224 - - [03/May/2025:14:12:43 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
