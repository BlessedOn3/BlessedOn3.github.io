---
title: "hermes-control-interface — WebSocket RBAC Bypass → Viewer Gets OS Shell (CVSS 9.9)"
date: 2026-05-25 14:00:00 +0000
categories: [CVE, RCE]
tags: [hermes, websocket, rbac, privilege-escalation, responsible-disclosure]
---

## Overview

**Affected software:** xaspx/hermes-control-interface (latest)  
**CVSS 3.1:** 9.9 Critical — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`  
**Reported:** 2026-05-25

Two privilege escalation vulnerabilities in the RBAC implementation allow a **viewer-role user** to execute arbitrary OS commands and overwrite protected files.

## FINDING-01 — WebSocket Terminal RBAC Bypass (CVSS 9.9)

The WebSocket handler processes `terminal-input` messages from any authenticated user without checking the `terminal` permission. The REST API equivalent correctly enforces `requirePerm('terminal.exec')`, but the WebSocket path was overlooked.

**Vulnerable code** (`src/server.js` ~line 5083):

```javascript
// Only checks socket.authed — missing RBAC
if (msg.type === 'terminal-input' && socket.authed) {
    const session = ensureTerminalSession();
    if (session.proc) session.proc.write(data);  // shared PTY — anyone injects
}
```

**Contrast with the REST API** (correctly protected):
```javascript
app.post('/api/terminal/exec',
  requireAuth, requireCsrf, requirePerm('terminal.exec'), ...
```

**Aggravating factor:** The terminal is a **singleton shared by all users**. A viewer can inject commands into an admin's active session and receives the full terminal history on connection.

## FINDING-02 — File Write Missing Permission Check (CVSS 7.5)

`POST /api/file` applies CSRF validation but is missing `requirePerm('files.write')`. A viewer (who has `files.read`) can overwrite files within the explorer root using a valid CSRF token.

```javascript
// Missing requirePerm('files.write')
app.post('/api/file', requireCsrf, (req, res) => {
  const result = writeFileSafe(filePath, content);
  return res.json({ ok: true, ...result });
});
```

## Proof of Concept

```bash
pip install websockets requests
python3 ws_rbac_bypass.py http://target:3000 viewer viewer123 "id && whoami"
```

Expected output:
```
[+] Logged in as: viewer (role: viewer)
[+] WebSocket connected
[+] Terminal history received (admin session hijacked)
[RCE] uid=1000(ubuntu) gid=1000(ubuntu)
```

## PoC Code

Full exploit: [github.com/BlessedOn3/poc-hermes-ws-rbac-bypass](https://github.com/BlessedOn3/poc-hermes-ws-rbac-bypass)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-25 | Vulnerabilities discovered |
| 2026-05-25 | DM sent to @bayendor on X |
| 2026-05-27 | GitHub issue #66 opened (no response) |
