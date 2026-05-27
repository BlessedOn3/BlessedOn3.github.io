---
icon: fas fa-info-circle
order: 4
---

## About Me

I'm **theblessOne**, an independent security researcher focused on CVE discovery, responsible disclosure, and bug bounty hunting.

I specialize in:
- **Unauthenticated RCE** in self-hosted web applications
- **Broken access control** and RBAC bypasses
- **WebSocket security** — auth enforcement at upgrade and message level
- **Insecure defaults** — hardcoded secrets, open bindings, disabled auth flags

## Contact

- **Email:** theblessone.sec@gmail.com
- **GitHub:** [BlessedOn3](https://github.com/BlessedOn3)
- **Twitter/X:** [@theblessOne](https://twitter.com/theblessOne)

## CVEs / Advisories

| ID | Target | Severity | Status |
|---|---|---|---|
| GHSA-5x7j-xjpx-pmm5 | WonderCMS 3.6.0 — Stored XSS | High (7.4) | Published |
| Pending | hermes-control-interface — WebSocket RBAC Bypass | Critical (9.9) | Disclosed |
| Pending | saadnvd1/agent-os — Unauthenticated RCE | Critical (10.0) | Disclosed |
| Pending | pqhaz3925/ccweb — Unauthenticated RCE via Claude Code | Critical (10.0) | Disclosed |
| Pending | vasandkumar/triterm — Auth Disabled by Default | Critical (10.0) | Disclosed |
| Pending | iabdullahmumtaz/DeployHive — Unauthenticated RCE | Critical (10.0) | Disclosed |

## Disclosure Policy

I follow a **coordinated disclosure** model:
- Contact the maintainer privately first
- Allow **14–90 days** for a patch depending on severity
- Publish technical writeup after patch or deadline

All PoC code is available at [github.com/BlessedOn3](https://github.com/BlessedOn3).
