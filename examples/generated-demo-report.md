# VAPT Assessment Report — Sanitized Local Lab Demo

**Target:** `127.0.0.1`  
**Generated:** 2026-09-30T06:22:54+00:00  
**Scope:** Authorized assessment only

## Executive Summary

VAPTForge normalized **2** findings from the configured assessment tools.
Scanner output should be manually validated before a finding is marked VERIFIED.

## Risk Summary

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 1 |

## Technical Findings

### VF-001: Content Security Policy Missing

- **Severity:** MEDIUM
- **Status:** discovered
- **Asset:** `http://127.0.0.1:3000`
- **Location:** `http://127.0.0.1:3000/`
- **Source:** nuclei
- **Fingerprint:** `7bcf2f397f8519af`
- **CWE:** CWE-693

CSP header is missing.

**Evidence**
- `nuclei` — Template missing-csp matched at http://127.0.0.1:3000/

### VF-002: Open TCP port 80 (http)

- **Severity:** INFO
- **Status:** discovered
- **Asset:** `127.0.0.1`
- **Location:** `127.0.0.1:80`
- **Source:** nmap
- **Fingerprint:** `567cf1e290cec906`

Nmap identified an open service: Apache httpd 2.4.57.

**Evidence**
- `nmap` — tcp/80 open; service=Apache httpd 2.4.57
