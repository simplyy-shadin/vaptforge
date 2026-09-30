# VAPTForge Roadmap

## v0.1 - Core engine

- [x] Scope enforcement
- [x] Nmap/Nuclei adapters and parsers
- [x] Normalized finding model
- [x] Correlation and Markdown reporting
- [x] CI and dependency audit

## v0.2 - Web assessment

- [x] HTTP/cookie/CORS/method checks
- [x] TLS checks
- [x] Nikto, ffuf, and httpx adapters
- [x] Cross-scanner correlation
- [x] Evidence deduplication

## v0.3 - Assessment lifecycle

- [x] SQLite assessments/assets/findings
- [x] Status transition history
- [x] Validation notes and evidence metadata
- [x] CVSS v3.1 scoring
- [x] CWE/OWASP enrichment
- [x] Persistent CLI workflow

## v0.4 - Retesting and reporting

- [x] Delta/retest engine
- [x] Fixed/persistent/changed/new classification
- [x] Markdown/JSON/HTML/PDF reporting
- [x] Executive metrics
- [x] Sanitized sample report

## v0.5 - Dashboard and API

- [x] Assessment API
- [x] Local dashboard summary
- [x] Severity/status finding filters
- [x] Evidence preview/detail API
- [x] Persisted retest history
- [x] Report export controls
- [x] API-key protected mutations
- [x] FastAPI integration tests

## Future v1.0 hardening

- [x] Database migrations/versioning
- [ ] Role-based multi-user authentication
- [ ] Background job queue for long-running scans
- [x] Pluggable scanner SDK
- [x] SARIF import/export
- [x] SBOM generation
- [ ] Signed release artifacts
- [ ] Browser-based evidence upload
- [ ] Deployment reference architecture
