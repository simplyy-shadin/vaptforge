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

## v0.7 - Background assessment execution

- [x] SQLite-backed assessment jobs and scanner-run audit
- [x] Separate local worker with renewable lease and restart recovery
- [x] Per-scanner status, errors, counts, cancellation between scanners
- [x] API and dashboard progress, CLI queue/worker/status commands

## v0.8 - Guided startup and assessment profiles

- [x] Friendly `vaptforge start` launcher
- [x] Guided/automatic and manual/advanced modes
- [x] Authorized target suggestions and optional scope creation
- [x] Quick/web/network/full assessment profiles
- [x] Automatic optional-tool availability handling in guided mode
- [x] Root `-h` / `--help` experience and profile discovery


## v0.9 - Deep assessment engine

- [x] Deep assessment profile
- [x] Bounded same-origin crawler
- [x] Reachable page, form, and GET-parameter inventory
- [x] Native benign reflection analysis for potential XSS sinks
- [x] Native SQL-error differential analysis for potential injection
- [x] Finding confidence model separate from lifecycle status
- [x] Confidence surfaced in CLI, dashboard, and reports
- [x] Deep-assessment methodology and safety documentation
- [x] Environment-backed authenticated/session-aware crawling\n- [ ] Browser-driven authenticated navigation
- [x] JavaScript endpoint extraction
- [ ] Browser-assisted XSS context validation
- [ ] Additional safe native checks for redirects and API-specific input handling

## Future v1.0 hardening

- [x] Database migrations/versioning
- [ ] Role-based multi-user authentication
- [x] Background job queue for long-running scans
- [x] Unified platform startup and assessment profiles
- [x] Pluggable scanner SDK
- [x] SARIF import/export
- [x] SBOM generation
- [ ] Signed release artifacts
- [ ] Browser-based evidence upload
- [ ] Deployment reference architecture
