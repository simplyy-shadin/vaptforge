# VAPTForge

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing orchestration framework** for authorized labs and environments. It combines custom web/TLS checks with established assessment tools, normalizes their output, correlates overlapping evidence, and generates repeatable VAPT reports.

> **Authorized testing only.** Every scan requires an explicit scope file. Use VAPTForge only on systems you own or have written permission to assess.

## Why this project exists

Professional VAPT work is not finished when a scanner exits. A useful assessment needs authorization, repeatable reconnaissance, evidence preservation, false-positive review, finding correlation, remediation guidance, and retesting.

```text
Authorization
     |
     v
Scope Enforcement
     |
     v
Recon + Web/TLS Assessment
     |
     v
Machine-readable Parsers
     |
     v
Normalized Findings
     |
     v
Correlation + Evidence
     |
     v
Manual Validation
     |
     v
Reporting -> Remediation -> Retest
```

## Current release: v0.2.0

### Built-in checks

VAPTForge includes Python-native checks that work without third-party scanners:

- HTTP security headers
- session/authentication cookie attributes
- CORS origin reflection
- HTTP TRACE exposure
- TLS certificate validation
- certificate expiration
- deprecated negotiated TLS versions
- weak negotiated cipher indicators

The checks use conservative lifecycle states: scanner observations are not automatically treated as verified vulnerabilities.

### External scanner adapters

| Adapter | Purpose | Machine-readable input |
|---|---|---|
| Nmap | service enumeration | XML |
| Nuclei | template-based vulnerability discovery | JSONL |
| Nikto | web-server assessment | JSON |
| ffuf | controlled content discovery | JSON |
| httpx | HTTP reconnaissance and technology metadata | JSONL |

Nuclei excludes `dos`, `fuzz`, and `bruteforce` tags by default. ffuf uses a small bundled wordlist, a request-rate limit, limited concurrency, and a fixed runtime cap.

## Key engineering features

- explicit JSON authorization/scope gate
- exact host/IP and CIDR scope matching
- subprocess execution with `shell=False`
- separate scanner and parser layers
- common Pydantic finding/evidence model
- deterministic finding fingerprints
- cross-scanner CVE correlation
- evidence deduplication
- finding lifecycle states
- CWE / OWASP / CVE fields
- Markdown and JSON output
- FastAPI foundation
- Docker training lab
- pytest + Ruff CI across Python 3.12 and 3.13
- scheduled dependency auditing

## Architecture

```text
                            +------------------+
                            | Authorized Scope |
                            +---------+--------+
                                      |
                                      v
+---------+            +--------------+--------------+
| CLI/API |----------->|       Scanner Registry     |
+---------+            +--------------+--------------+
                                      |
       +----------+-----------+-------+-------+----------+-----------+
       |          |           |               |          |           |
       v          v           v               v          v           v
     HTTP        TLS        Nmap            Nuclei     Nikto       ffuf/httpx
       |          |           |               |          |           |
       |          |           v               v          v           v
       |          |       XML parser       JSONL      JSON         JSON(L)
       |          |           \               |          /           /
       +----------+------------+---------------+---------+----------+
                                      |
                                      v
                              Normalized Finding[]
                                      |
                                      v
                           Correlation + Evidence
                                      |
                         +------------+------------+
                         v                         v
                    JSON export              Markdown report
```

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/methodology.md`](docs/methodology.md).

## Quick start

### Install

```bash
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows PowerShell

pip install -e ".[dev]"
```

Check optional tools:

```bash
vaptforge doctor
```

### Start the local vulnerable lab

```bash
docker compose -f labs/docker-compose.yml up -d
```

The bundled training applications bind only to loopback:

- OWASP Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:4280`

### Validate scope

```bash
vaptforge scope-check   http://127.0.0.1:3000   --scope config/scope.example.json
```

Out-of-scope targets are rejected before scanner execution.

### Built-in assessment

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,tls   --output reports/builtin.md   --json-output reports/builtin.json
```

### Full lab assessment

Install the external tools you want to use, verify them with `vaptforge doctor`, then select them explicitly:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,tls,httpx,nmap,nuclei,nikto,ffuf   --output reports/juice-shop.md   --json-output reports/juice-shop.json
```

## Finding lifecycle

```text
DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED
                         \-> FALSE_POSITIVE
```

Examples:

- an open Nmap service is normally `DISCOVERED`
- a Nikto observation is `POTENTIAL`
- a reflected arbitrary CORS origin is `POTENTIAL`
- only tester-reviewed evidence should promote a finding to `VERIFIED`

The v0.3 milestone will persist these transitions and validation notes.

## Correlation

VAPTForge keeps scanner provenance instead of hiding it. Exact duplicate findings use deterministic fingerprints. Findings that identify the same CVE on the same host/port are correlated across scanners even when their titles differ.

The resulting record retains:

- highest observed severity
- strongest lifecycle state
- unique evidence
- unique references
- CVE/CWE/OWASP mappings
- source scanner list

This reduces duplicate report noise while preserving the evidence trail.

## Scope format

```json
{
  "assessment_name": "Local Vulnerable Lab",
  "authorization_reference": "Locally owned Docker lab for security testing",
  "targets": [
    {"value": "127.0.0.1"},
    {"value": "172.20.0.0/24"}
  ]
}
```

Hostname scope entries use exact matching. Wildcard expansion is intentionally not implicit.

## Testing

```bash
pytest
ruff check .
```

Test coverage includes authorization, Nmap/Nuclei/Nikto/ffuf/httpx parsing, HTTP controls, TLS analysis, correlation, and reporting.

## API

```bash
uvicorn vaptforge.api.main:app --reload
```

Current endpoint:

```text
GET /health
```

Assessment, finding, evidence, validation, and retest APIs are planned for the persistence milestone.

## Project boundaries

VAPTForge is an **authorized assessment framework**, not an exploitation or evasion framework. Its defaults emphasize discovery, configuration assessment, evidence collection, and validation. Disruptive scan behavior is excluded or constrained by default.

## Roadmap

- **v0.1:** core orchestration, scope, Nmap/Nuclei, reporting
- **v0.2:** web/TLS checks, Nikto/ffuf/httpx, stronger correlation
- **v0.3:** SQLite assessment lifecycle, validation, CVSS and enrichment
- **v0.4:** remediation retesting and professional HTML/PDF reporting
- **v0.5:** assessment dashboard and API

See [`ROADMAP.md`](ROADMAP.md).

## Portfolio skills demonstrated

VAPT methodology, reconnaissance, web security assessment, TLS analysis, Python security engineering, secure process execution, machine-readable scanner integration, finding normalization, evidence correlation, false-positive awareness, remediation reporting, automated tests, CI, and dependency security.

## License

MIT — see [`LICENSE`](LICENSE).
