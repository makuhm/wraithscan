# Wraithscan 🕵️

A modular Python-based web application pentesting toolkit built for educational use and legal security testing.

## Modules

**Recon**
- `dirbrute` — Concurrent directory brute-forcing with wildcard detection
- `subdomains` — Subdomain enumeration via crt.sh certificate transparency logs

**Vulnerability Testing**
- `sqli` — SQL injection detection (error-based, boolean-based, time-based blind)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Help
python main.py --help

# Directory brute-force
python main.py -t http://localhost:3000 recon dirbrute

# Subdomain enumeration
python main.py -t http://localhost:3000 recon subdomains --domain example.com

# SQL injection scan (requires --confirm-legal on non-whitelisted targets)
python main.py -t http://localhost:3000 --confirm-legal vuln sqli --param id
```

## Legal

This tool is intended for use **only** on targets you have explicit permission to test, such as OWASP Juice Shop, HackTheBox, TryHackMe, or your own local environments. Unauthorized use is illegal.