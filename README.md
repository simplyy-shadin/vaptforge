# VAPTForge

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing orchestration framework** for authorized environments. It combines custom web/TLS checks with established assessment tools, normalizes and correlates their output, persists the assessment lifecycle, and generates repeatable VAPT reports.

> **Authorized testing only.** Every scan requires explicit scope. Use VAPTForge only on systems you own or have written permission to assess.

## Current release: v0.3.0

VAPTForge now covers three layers of a real VAPT workflow:

```text
AUTHORIZED SCOPE
      |
      v
DISCOVERY + WEB/TLS ASSESSMENT
      |
      v
NORMALIZATION + CORRELATION
      |
      v
PERSISTED ASSESSMENT
      |
      +--> Evidence
      +--> Validation Notes
      +--> Status History
      +--> CVSS / CWE / OWASP
      |
      v
REPORTING -> REMEDIATION -> RETEST
```

## Capabilities

### Scope and orchestration

- mandatory JSON scope file
- exact hostname/IP and CIDR authorization
- `shell=False` subprocess execution
- scanner timeouts and conservative defaults
- Markdown + JSON report output

### Python-native assessment

- HTTP security headers
- sensitive cookie attributes
- CORS arbitrary-origin reflection
- HTTP TRACE exposure
- TLS certificate validation/expiry
- deprecated negotiated TLS versions
- weak negotiated cipher indicators

### External adapters

| Tool | Role | Parser |
|---|---|---|
| Nmap | service enumeration | XML |
| Nuclei | template-based discovery | JSONL |
| Nikto | web-server assessment | JSON |
| ffuf | bounded content discovery | JSON |
| httpx | HTTP reconnaissance | JSONL |

### Correlation and enrichment

- deterministic finding fingerprints
- CVE + host + port cross-scanner correlation
- evidence deduplication
- scanner provenance preservation
- CVSS v3.1 base scoring
- CVSS extraction from Nuclei classification
- curated CWE -> OWASP Top 10 2021 enrichment

### Persistent assessment lifecycle

SQLite persistence tracks:

- assessments
- assets
- normalized findings
- evidence
- validation notes
- status history

Lifecycle:

```text
DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED
                         \-> FALSE_POSITIVE
```

Scanner output is never promoted to VERIFIED automatically.

## Quick start

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Check optional external tools:

```bash
vaptforge doctor
```

### Start the authorized local lab

```bash
docker compose -f labs/docker-compose.yml up -d
```

- Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:4280`

### Scope check

```bash
vaptforge scope-check   http://127.0.0.1:3000   --scope config/scope.example.json
```

### Built-in scan

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,tls   --output reports/builtin.md
```

### Persistent assessment

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nmap,nuclei,nikto,ffuf   --db data/vaptforge.db   --output reports/initial.md   --json-output reports/initial.json
```

The command prints the new assessment UUID.

Review it:

```bash
vaptforge assessment-list --db data/vaptforge.db
vaptforge finding-list <ASSESSMENT_ID> --db data/vaptforge.db
```

Validate a finding:

```bash
vaptforge finding-transition <FINDING_ID> verified   --db data/vaptforge.db   --note "Reproduced in the authorized lab."
```

Attach evidence metadata:

```bash
vaptforge finding-evidence <FINDING_ID>   --db data/vaptforge.db   --source manual   --summary "Validation screenshot"   --attachment evidence/VF-001.png
```

See [`docs/assessment-lifecycle.md`](docs/assessment-lifecycle.md).

## Architecture

Core layers:

```text
CLI / future API
      |
AuthorizedScope
      |
Scanner adapters + Python-native checks
      |
Machine-readable parsers
      |
Finding normalization
      |
Correlation + OWASP/CVSS enrichment
      |
SQLite AssessmentStore
      |
Reports / validation / future retest engine
```

More detail:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/methodology.md`](docs/methodology.md)
- [`docs/assessment-lifecycle.md`](docs/assessment-lifecycle.md)

## Safety model

- no scan before authorization check
- no implicit hostname wildcards
- no shell command construction
- Nuclei excludes DoS/fuzz/bruteforce tags by default
- ffuf uses a small bundled wordlist with rate/concurrency/runtime limits
- vulnerable Docker labs bind to loopback
- defensive XML parsing via `defusedxml`
- external scanner findings remain DISCOVERED/POTENTIAL until review

## Testing

```bash
pytest
ruff check .
```

CI runs on Python 3.12 and 3.13. A separate workflow runs `pip-audit`.

Coverage includes scope enforcement, all machine-readable parsers, HTTP/TLS controls, correlation, CVSS calculation, OWASP enrichment, reporting, and SQLite lifecycle persistence.

## API

```bash
uvicorn vaptforge.api.main:app --reload
```

Current API is intentionally minimal (`GET /health`). The dashboard/API layer is planned after the retesting/reporting milestone.

## Roadmap

- **v0.1:** core engine, scope, Nmap/Nuclei, reporting
- **v0.2:** web/TLS assessment, Nikto/ffuf/httpx, stronger correlation
- **v0.3:** persistent lifecycle, validation evidence, CVSS, OWASP enrichment
- **v0.4:** retest/delta engine + HTML/PDF professional reporting
- **v0.5:** dashboard and assessment API

See [`ROADMAP.md`](ROADMAP.md).

## Portfolio skills demonstrated

VAPT methodology, reconnaissance, web security assessment, TLS analysis, secure Python engineering, scanner orchestration, parser design, finding normalization, correlation, CVSS, CWE/OWASP mapping, SQLite persistence, evidence handling, validation workflow, automated testing, CI, and dependency security.

## License

MIT — see [`LICENSE`](LICENSE).
