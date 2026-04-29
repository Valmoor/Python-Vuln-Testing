# vuln-python-app

> ⚠️ **FOR SECURITY TESTING ONLY** — This repository contains **intentional vulnerabilities** for evaluating AppSec tools. Do NOT deploy to production.

## Vulnerabilities Included

| File | Vulnerability | CWE |
|------|--------------|-----|
| src/app.py | SQL injection (raw string format) | CWE-89 |
| src/app.py | Reflected & Stored XSS | CWE-79 |
| src/app.py | Command injection (`os.system`, `subprocess`) | CWE-78 |
| src/app.py | Path traversal in file endpoint | CWE-22 |
| src/app.py | Insecure deserialization (`pickle.loads`) | CWE-502 |
| src/app.py | Weak password hashing (MD5) | CWE-327 |
| src/app.py | Missing authentication on admin route | CWE-306 |
| src/app.py | Open redirect | CWE-601 |
| src/app.py | Server-Side Request Forgery (SSRF) | CWE-918 |
| src/app.py | Debug mode enabled | CWE-94 |
| src/app.py | Hardcoded secrets & API keys | CWE-798 |
| src/utils.py | `eval()` on user input | CWE-95 |
| src/utils.py | Unsafe `yaml.load` deserialization | CWE-502 |
| src/utils.py | Predictable random token (fixed seed) | CWE-338 |
| src/utils.py | Logging PAN/CVV to log files | CWE-532 |
| src/utils.py | SSL certificate validation disabled | CWE-295 |
| src/utils.py | ReDoS via catastrophic backtracking | CWE-1333 |
| src/utils.py | Information disclosure in exceptions | CWE-209 |
| src/utils.py | Private key & tokens hardcoded | CWE-798 |
| .env | Secrets committed to version control | CWE-798 |
| requirements.txt | Vulnerable dependency versions (SCA) | Various |
