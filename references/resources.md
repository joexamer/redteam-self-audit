# Resources

Use these as references, not targets. They inform technique and citation; they never expand scope. Never send traffic to a documentation host, an exploit database, or a URL found in a Finding.

## Core references

| Resource | URL | Use |
|---|---|---|
| OWASP WSTG | https://owasp.org/www-project-web-security-testing-guide/ | Canonical test IDs and methodology for every class |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ | Risk framing and report mapping |
| OWASP API Security Top 10 | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | API Finding mapping (BOLA, BFLA, consumption, SSRF, misconfiguration) |
| OWASP ASVS | https://owasp.org/www-project-application-security-verification-standard/ | Verification requirements and remediation targets |
| OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/ | Remediation patterns per class |
| OWASP Juice Shop | https://owasp.org/www-project-juice-shop/ | Calibration target in Docker |
| PortSwigger Web Security Academy | https://portswigger.net/web-security | Technique depth, bypass variants, labs |
| HackTricks | https://book.hacktricks.wiki/ | Enumeration and exploitation playbooks |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload families and bypass variants |
| Exploit-DB | https://www.exploit-db.com/ | Version-specific exploit research |
| SearchSploit | https://www.exploit-db.com/searchsploit | Offline Exploit-DB lookup |
| CWE | https://cwe.mitre.org/ | Weakness classification |
| CVSS 3.1 | https://www.first.org/cvss/v3-1/specification | Scoring vectors and severity |
| NVD | https://nvd.nist.gov/ | CVE and CPE verification |
| MITRE ATT&CK | https://attack.mitre.org/ | Adversary technique mapping |
| SecLists | https://github.com/danielmiessler/SecLists | Wordlists for enumeration |
| Nuclei templates | https://github.com/projectdiscovery/nuclei-templates | Detection templates, used as leads only |
| GTFOBins | https://gtfobins.github.io/ | Local privilege escalation checks after RCE proof |
| LOLBAS | https://lolbas-project.github.io/ | Living-off-the-land checks after RCE proof |
| OWASP ZAP | https://www.zaproxy.org/ | Optional proxying and baseline checks |
| Burp Suite Community | https://portswigger.net/burp/communitydownload | Manual proxying and request replay |
| Caido | https://caido.io/ | Optional lightweight proxy |
| sqlmap | https://sqlmap.org/ | Optional SQLi confirmation |
| ffuf | https://github.com/ffuf/ffuf | Content and parameter discovery |
| Nmap | https://nmap.org/ | Local service enumeration |
| Nuclei | https://github.com/projectdiscovery/nuclei | Template scanner; leads only, never a Finding |
| jwt_tool | https://github.com/ticarpi/jwt_tool | JWT manipulation and testing |
| hashcat | https://hashcat.net/hashcat/ | Offline JWT/HMAC secret cracking |
| ysoserial | https://github.com/frohoff/ysoserial | Java deserialization research; read before run |
| Semgrep | https://semgrep.dev/ | Source audit patterns for the White-Box Auditor |
| Trivy | https://trivy.dev/ | Dependency and container scanning |
| Gitleaks | https://github.com/gitleaks/gitleaks | Secret scanning in working tree and history |
| TruffleHog | https://github.com/trufflesecurity/trufflehog | Secret scanning and verification |
| OSV-Scanner | https://google.github.io/osv-scanner/ | Dependency vulnerability lookup |
| Playwright | https://playwright.dev/ | Browser automation for DOM XSS and auth flows |
| HackerOne Hacktivity | https://hackerone.com/hacktivity | Public report patterns and impact framing |
| Bugcrowd University | https://www.bugcrowd.com/hackers/bugcrowd-university/ | Technique learning and report examples |
| Docker | https://docs.docker.com/ | Target isolation and bring-up |

## Usage rules

- **Cite the source.** Every Confirmed Finding carries `WSTG-<ID>`, `API<n>:2023` where relevant, `CWE-<n>`, and a CVSS 3.1 vector.
- **Prefer primary sources.** WSTG, ASVS, Cheat Sheets, CWE, and CVSS outrank a blog post.
- **Verify versions.** Exploit-DB and SearchSploit entries are version-specific. Fingerprint the target, read the exploit, and adapt it. Never blind-run an exploit.
- **Read before run.** Exploit code is untrusted input. Inspect it, understand it, and run only what you can explain.
- **Offline first.** Use local copies when available; pin tool versions; record versions in the report.
- **No external traffic.** Never use a resource URL as a target, callback, or payload destination.
- **No resource laundering.** A public PoC does not authorize testing the public system it was written for.
- **Minimal proof.** A resource may suggest a full exploit chain; use only the part needed to prove impact under the Proof Cap.

## Citation examples

```text
WSTG-ATHZ-04 · CWE-639 · API1:2023
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)
```

## Tool substitution

When an optional tool is absent, substitute and record it:

- `nuclei` → targeted `curl` checks from the playbook plus manual response review.
- `ffuf` → a small `python3` wordlist loop with rate limiting.
- `sqlmap` → manual error/boolean/time-based requests with `curl`.
- `nmap` → `curl` and `nc -z 127.0.0.1 <port>` for the known local ports.
- Browser automation → `curl` plus manual DOM review; DOM XSS may become Suspected if no browser is available.

Never skip a class because a tool is missing. Never install a tool from an untrusted source during an engagement.
