# VAPTForge

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing orchestration platform** for authorized environments. It combines custom web/TLS assessment, established security scanners, finding correlation, persistent validation workflows, remediation retesting, and professional multi-format reporting.

> **Authorized testing only.** Every scan requires explicit scope. Use VAPTForge only on systems you own or have written permission to assess.

## Current release: v0.4.0

```text
AUTHORIZED SCOPE
      |
      v
RECON + WEB/TLS ASSESSMENT
      |
      v
NORMALIZE + CORRELATE
      |
      v
PERSIST + VALIDATE
      |
      v
REMEDIATE + RETEST
      |
      v
MARKDOWN / JSON / HTML / PDF
```

## What VAPTForge demonstrates

### Assessment engine

- HTTP security headers
- sensitive cookie attributes
- CORS arbitrary-origin reflection
- HTTP TRACE exposure
- TLS validation, expiry, protocol and cipher observations
- Nmap service enumeration
- Nuclei template-based discovery
- Nikto web-server assessment
- ffuf bounded content discovery
- httpx HTTP reconnaissance

### Safety and scope

- mandatory JSON authorization scope
- exact hostname/IP and CIDR matching
- no implicit wildcard expansion
- structured subprocess arguments with `shell=False`
- Nuclei DoS/fuzz/bruteforce tags excluded by default
- ffuf rate, concurrency and runtime bounds
- local vulnerable labs bound to loopback
- findings remain DISCOVERED/POTENTIAL until explicit tester validation

### Analysis

- common Pydantic finding model
- deterministic fingerprints
- cross-scanner CVE correlation
- evidence deduplication
- CVSS v3.1 base scoring
- Nuclei CVSS normalization
- curated CWE -> OWASP Top 10 2021 enrichment

### Assessment lifecycle

SQLite persistence tracks:

- assessments
- assets
- normalized findings
- evidence
- validation notes
- status history

```text
DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED
                         \-> FALSE_POSITIVE
```

### Retesting

Two persisted assessments can be compared as:

- FIXED
- PERSISTENT
- CHANGED
- NEW

Use comparable scope/scanner profiles when treating absence as remediation evidence.

### Reporting

One assessment can produce:

- Markdown
- JSON
- standalone HTML
- PDF

Reports include severity metrics, finding metadata, CVSS/mappings, evidence, and remediation guidance.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
vaptforge doctor
```

Start the local training lab:

```bash
docker compose -f labs/docker-compose.yml up -d
```

- Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:4280`

Check scope:

```bash
vaptforge scope-check   http://127.0.0.1:3000   --scope config/scope.example.json
```

Run and persist an assessment:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nmap,nuclei,nikto,ffuf   --db data/vaptforge.db   --output reports/initial.md   --json-output reports/initial.json   --html-output reports/initial.html   --pdf-output reports/initial.pdf
```

Review and validate:

```bash
vaptforge assessment-list --db data/vaptforge.db
vaptforge finding-list <ASSESSMENT_ID> --db data/vaptforge.db

vaptforge finding-transition <FINDING_ID> verified   --db data/vaptforge.db   --note "Reproduced in the authorized lab."
```

After remediation, create a second assessment and compare:

```bash
vaptforge retest <BASELINE_ID> <RETEST_ID>   --db data/vaptforge.db   --output reports/retest.md
```

## Documentation

- [Architecture](docs/architecture.md)
- [Methodology](docs/methodology.md)
- [Assessment lifecycle](docs/assessment-lifecycle.md)
- [Retesting and reporting](docs/retesting.md)
- [Roadmap](ROADMAP.md)
- [Security policy](SECURITY.md)

## Testing and CI

```bash
ruff check .
pytest
```

GitHub Actions tests Python 3.12 and 3.13. A separate security workflow runs `pip-audit`.

Coverage includes authorization, scanner parsers, custom HTTP/TLS checks, correlation, CVSS, OWASP enrichment, SQLite lifecycle persistence, retest classification, HTML escaping, PDF generation, and report output.

## API

```bash
uvicorn vaptforge.api.main:app --reload
```

The current API exposes `GET /health`. The v0.5 milestone will expose the persisted assessment model through a dashboard/API.

## Project boundaries

VAPTForge is an **authorized assessment and validation platform**, not an exploitation or evasion framework. It is designed to demonstrate disciplined VAPT methodology: scope, discovery, validation, evidence, reporting, remediation, and retesting.

## Roadmap

- **v0.1:** core orchestration
- **v0.2:** web/TLS assessment + scanner integrations
- **v0.3:** persistent validation lifecycle
- **v0.4:** retesting + professional report formats
- **v0.5:** dashboard and assessment API

## License

MIT - see [LICENSE](LICENSE).
