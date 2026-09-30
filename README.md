# VAPTForge

[![CI](https://github.com/simplyy-shadin/vaptforge/actions/workflows/ci.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/ci.yml)
[![Security Checks](https://github.com/simplyy-shadin/vaptforge/actions/workflows/security.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/security.yml)
[![CodeQL](https://github.com/simplyy-shadin/vaptforge/actions/workflows/codeql.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing platform** for authorized environments. It brings scope enforcement, reconnaissance, web/TLS assessment, scanner orchestration, finding correlation, manual validation, remediation retesting, professional reporting, and a local assessment dashboard into one Python project.

> **Authorized testing only.** Every scan requires explicit scope. Use VAPTForge only on systems you own or have written permission to assess.

## Current release: v0.7.0

```text
AUTHORIZED SCOPE
      |
      v
RECON + WEB/TLS ASSESSMENT
      |
      v
NORMALIZE + CORRELATE + ENRICH
      |
      v
PERSIST + MANUALLY VALIDATE
      |
      v
REMEDIATE + RETEST
      |
      +---------------------------+
      |                           |
      v                           v
CLI REPORTS                 FASTAPI DASHBOARD
MD / JSON / HTML / PDF      FILTER / EXPORT / HISTORY
```

## Core capabilities

**Assessment**
- Python-native HTTP header, cookie, CORS, method, and TLS checks
- Nmap, Nuclei, Nikto, ffuf, and ProjectDiscovery httpx adapters
- machine-readable parser layer
- pluggable scanner SDK via `vaptforge.scanners` Python entry points

**Safety**
- mandatory explicit scope
- exact hostname/IP and CIDR matching
- `shell=False` command execution
- bounded ffuf defaults
- disruptive Nuclei tags excluded
- vulnerable labs bound to loopback
- scanner findings never auto-promoted to VERIFIED

**Analysis**
- Pydantic finding/evidence model
- deterministic fingerprints
- CVE-based cross-scanner correlation
- evidence deduplication
- CVSS v3.1 base scoring
- curated CWE -> OWASP Top 10 2021 enrichment

**Lifecycle**
- SQLite assessments, assets, findings, evidence, notes, and status history
- persistent background jobs and per-scanner audit/progress through a separate local worker
- DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED
- FALSE_POSITIVE workflow
- evidence attachment metadata

**Retesting**
- FIXED / PERSISTENT / CHANGED / NEW delta classification
- persisted retest history
- comparable-assessment guidance

**Reporting**
- Markdown
- JSON
- standalone HTML
- PDF (ReportLab)
- SARIF 2.1.0 import/export
- executive severity metrics
- sanitized example report

**Supply chain and compatibility**
- versioned SQLite migrations with forward-version protection
- CycloneDX JSON SBOM generation
- scanner plugin collision protection

**Dashboard/API**
- local assessment dashboard
- severity/status filters
- evidence previews
- retest history
- report export controls
- read API
- API-key-protected mutation endpoints

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
vaptforge doctor
```

Start the local vulnerable lab:

```bash
docker compose -f labs/docker-compose.yml up -d
```

Run and persist an authorized assessment:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nmap,nuclei,nikto,ffuf   --db data/vaptforge.db   --output reports/initial.md   --json-output reports/initial.json   --html-output reports/initial.html   --pdf-output reports/initial.pdf   --sarif-output reports/initial.sarif
```

For background execution, start a worker in a separate terminal and queue a job:

```bash
vaptforge worker --db data/vaptforge.db
vaptforge queue-assessment http://127.0.0.1:3000 --scope config/scope.example.json --scanners http,tls --db data/vaptforge.db
vaptforge job-status <JOB_ID> --db data/vaptforge.db
```

The dashboard shows scanner states and finding counts as the worker progresses. See [Background jobs](docs/background-jobs.md) for recovery, cancellation, and API usage.

Validate a finding:

```bash
vaptforge finding-transition <FINDING_ID> verified   --db data/vaptforge.db   --note "Reproduced in the authorized lab."
```

After remediation, create a fresh assessment and compare:

```bash
vaptforge retest <BASELINE_ID> <RETEST_ID>   --db data/vaptforge.db   --output reports/retest.md
```

## Dashboard

```bash
export VAPTFORGE_DB=data/vaptforge.db
uvicorn vaptforge.api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`.

API mutations are disabled by default. To enable them:

```bash
export VAPTFORGE_API_KEY="use-a-long-random-secret"
```

Then send the key using the `X-VAPTForge-API-Key` header.

See [API and Dashboard](docs/api-dashboard.md).

## Documentation

- [Architecture](docs/architecture.md)
- [VAPT methodology](docs/methodology.md)
- [Assessment lifecycle](docs/assessment-lifecycle.md)
- [Retesting and reporting](docs/retesting.md)
- [API and dashboard](docs/api-dashboard.md)
- [Scanner extensibility](docs/extensibility.md)
- [Database migrations](docs/database-migrations.md)
- [SARIF and SBOM](docs/sarif-sbom.md)
- [Background jobs](docs/background-jobs.md)
- [Security policy](SECURITY.md)
- [Roadmap](ROADMAP.md)

## Testing

```bash
ruff check .
pytest
```

GitHub Actions tests Python 3.12 and 3.13. A separate workflow runs `pip-audit`.

The test suite covers authorization, parser normalization, custom HTTP/TLS checks, correlation, CVSS, OWASP enrichment, SQLite migrations/lifecycle persistence, scanner plugin loading, SARIF interchange, SBOM generation, retest classification, HTML/PDF generation, FastAPI endpoints, API mutation security, report exports, and dashboard rendering.

## Portfolio positioning

VAPTForge is deliberately different from a DevSecOps pipeline project. It demonstrates **hands-on VAPT engineering and methodology**: authorized scoping, reconnaissance, web assessment, vulnerability triage, evidence management, manual validation, risk classification, reporting, remediation verification, and retesting.

## License

MIT - see [LICENSE](LICENSE).
