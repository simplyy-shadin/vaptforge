# VAPTForge Roadmap

## v0.1 — Core engine

- [x] Scope enforcement
- [x] Finding model
- [x] Nmap adapter/parser
- [x] Nuclei adapter/parser
- [x] Correlation engine
- [x] Markdown reporting
- [x] CLI
- [x] FastAPI health endpoint
- [x] Local vulnerable lab
- [x] CI and dependency audit

## v0.2 — Web assessment

- [x] Target normalization for host-based scanners
- [x] Basic HTTP reconnaissance module
- [x] Security-header checks
- [x] Cookie security checks
- [x] CORS checks
- [x] HTTP method checks
- [x] TLS checks
- [x] Nikto adapter/parser
- [x] ffuf adapter/parser
- [x] httpx adapter/parser
- [x] Cross-scanner CVE correlation
- [x] Evidence deduplication
- [x] Conservative POTENTIAL status for scanner observations

## v0.3 — Assessment lifecycle

- [x] SQLite persistence
- [x] Assessment/asset entities
- [x] Finding status transitions with history
- [x] Manual validation notes
- [x] Evidence attachment metadata
- [x] CVSS v3.1 base scoring
- [x] Curated CWE/OWASP enrichment
- [x] Persistent-scan CLI workflow
- [x] Assessment and finding CLI commands

## v0.4 — Retesting and reporting

- [ ] Before/after diff engine
- [ ] Fixed/new/persistent classification
- [ ] HTML report
- [ ] PDF export
- [ ] Executive summary metrics
- [ ] Sanitized sample VAPT report

## v0.5 — Dashboard

- [ ] Assessment API
- [ ] Dashboard summary
- [ ] Findings filters
- [ ] Evidence view
- [ ] Retest history
- [ ] Export controls
