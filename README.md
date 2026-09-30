# VAPTForge

[![CI](https://github.com/simplyy-shadin/vaptforge/actions/workflows/ci.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/ci.yml)
[![Security Checks](https://github.com/simplyy-shadin/vaptforge/actions/workflows/security.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/security.yml)
[![CodeQL](https://github.com/simplyy-shadin/vaptforge/actions/workflows/codeql.yml/badge.svg)](https://github.com/simplyy-shadin/vaptforge/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing platform** for authorized environments. It brings scope enforcement, reconnaissance, web/TLS assessment, scanner orchestration, finding correlation, manual validation, remediation retesting, professional reporting, and a local assessment dashboard into one Python project.

> **Authorized testing only.** Every scan requires explicit scope. Use VAPTForge only on systems you own or have written permission to assess.

## Current release: v0.9.2

```text
AUTHORIZED SCOPE
      |
      v
RECON + WEB/TLS ASSESSMENT
      |
      v
DEEP ATTACK-SURFACE + SAFE NATIVE ANALYSIS
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
- native Deep Web engine with bounded same-origin crawling, static JavaScript API-route extraction, environment-backed authenticated sessions, page/form/GET-parameter inventory, benign reflection analysis, and SQL-error differential checks
- Nmap, Nuclei, Nikto, ffuf, and ProjectDiscovery httpx adapters
- machine-readable parser layer
- pluggable scanner SDK via `vaptforge.scanners` Python entry points

**Safety**
- mandatory explicit scope
- exact hostname/IP and CIDR matching
- `shell=False` command execution
- bounded ffuf defaults with automatic soft-404/wildcard calibration
- disruptive Nuclei tags excluded
- vulnerable labs bound to loopback
- scanner findings never auto-promoted to VERIFIED

**Analysis**
- Pydantic finding/evidence model with separate lifecycle status and evidence confidence
- deterministic fingerprints
- CVE-based cross-scanner correlation
- evidence deduplication
- CVSS v3.1 base scoring
- curated CWE -> OWASP Top 10 2021 enrichment

**Lifecycle**
- SQLite assessments, assets, findings, evidence, notes, and status history
- persistent background jobs and per-scanner audit/progress through a separate local worker
- guided `vaptforge start` launcher with automatic and manual workflows
- named assessment profiles with optional-tool availability checks
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

Install VAPTForge, then use the guided launcher. You do not need to memorize scanner flags or long commands.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
vaptforge start
```

The launcher offers two paths:

1. **Guided / Automatic** — choose an authorization scope, pick a suggested authorized target, select a simple assessment profile, then VAPTForge queues the job and starts the worker + dashboard.
2. **Manual / Advanced** — start the platform services and keep direct control of the CLI/API workflow.

Use either help flag at any time:

```bash
vaptforge -h
vaptforge --help
vaptforge start -h
```

List the simple profiles:

```bash
vaptforge profile-list
```

Profiles currently include **quick**, **web**, **network**, **full**, and **deep**. Deep mode adds the native attack-surface crawler and bounded active parameter analysis while preserving manual validation. Guided mode checks which optional scanner binaries are actually installed and clearly skips unavailable ones instead of hiding the decision.

Start the local vulnerable lab:

```bash
docker compose -f labs/docker-compose.yml up -d
```

Run and persist an authorized assessment:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nmap,nuclei,nikto,ffuf   --db data/vaptforge.db   --output reports/initial.md   --json-output reports/initial.json   --html-output reports/initial.html   --pdf-output reports/initial.pdf   --sarif-output reports/initial.sarif
```

For advanced/manual background execution, you can still control every component directly:

```bash
vaptforge worker --db data/vaptforge.db
vaptforge queue-assessment http://127.0.0.1:3000 --scope config/scope.example.json --profile deep --db data/vaptforge.db
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
- [Guided startup](docs/guided-startup.md)
- [Deep assessment engine](docs/deep-assessment.md)
- [Security policy](SECURITY.md)
- [Roadmap](ROADMAP.md)

## Testing

```bash
ruff check .
pytest
```

GitHub Actions tests Python 3.12 and 3.13. A separate workflow runs `pip-audit`.

The test suite covers authorization, parser normalization, custom HTTP/TLS checks, deep crawler boundaries, native vulnerability heuristics, correlation, CVSS, OWASP enrichment, SQLite migrations/lifecycle persistence, scanner plugin loading, SARIF interchange, SBOM generation, retest classification, HTML/PDF generation, FastAPI endpoints, API mutation security, report exports, and dashboard rendering.

## Portfolio positioning

VAPTForge is deliberately different from a DevSecOps pipeline project. It demonstrates **hands-on VAPT engineering and methodology**: authorized scoping, reconnaissance, web assessment, vulnerability triage, evidence management, manual validation, risk classification, reporting, remediation verification, and retesting.

## License

MIT - see [LICENSE](LICENSE).
