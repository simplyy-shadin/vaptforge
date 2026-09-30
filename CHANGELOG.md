# Changelog

All notable VAPTForge changes are documented here. The project follows semantic versioning for portfolio milestones.

## [0.8.1] - 2026-09-30

### Fixed
- External tool detection now verifies that `httpx` is the ProjectDiscovery scanner instead of trusting any executable with the same name.
- The Python `httpx` CLI installed as a package dependency is reported as incompatible rather than incorrectly enabling the VAPTForge httpx scanner.
- Guided profile readiness and `vaptforge doctor` now share the same scanner-tool verification logic and provide an explanatory status.

## [0.8.0] - 2026-09-30

### Added
- Guided `vaptforge start` launcher with recommended automatic and manual/advanced modes.
- Friendly authorized target suggestions, including local Juice Shop and DVWA lab targets.
- Quick, web, network, and full assessment profiles.
- Guided scanner availability detection that clearly skips missing optional tools.
- Manual `--profile` support for background assessment queueing.
- Short `vaptforge -h` help alias and improved root help guidance.
- Platform supervisor that starts the existing background worker and local FastAPI dashboard together.

### Security
- Guided mode still requires an explicit authorization scope and validates the selected target before queueing.
- New scope creation requires an explicit authorization confirmation.
- The platform continues to bind to localhost by default and does not start a scan merely because services start.

## [0.7.0] - 2026-09-30

### Added
- Durable SQLite background assessment jobs and ordered scanner-run records.
- Separate local worker with exclusive renewable lease, restart recovery, scanner error isolation, and cancellation between scanners.
- Authenticated job creation/cancellation API, job progress API, dashboard run status, and CLI queue/worker/status commands.
- Schema v3 migration retaining legacy scanner-run records.

### Security
- Target scope is checked before queueing and again before each scanner invocation.
- API queue/cancel mutations require the configured API key; scanner observations remain unverified.

## [0.6.0] - 2026-09-30

### Added
- Versioned SQLite schema migrations with legacy v0.5 upgrade support and forward-version rejection.
- Scanner plugin discovery through the `vaptforge.scanners` Python entry-point group.
- SARIF 2.1.0 export and import normalization.
- CycloneDX JSON SBOM generation.
- CLI commands for scanner discovery and database schema status.

### Security
- External scanner plugins cannot silently replace registered scanner names.
- Existing authorization enforcement remains part of the scanner plugin contract.

## [0.5.0] - 2026-09-30

### Added
- Local FastAPI assessment dashboard.
- Assessment/finding APIs with severity and lifecycle filters.
- API-key-protected finding transitions, notes, and evidence metadata.
- Persisted retest history and report export endpoints.
- Markdown, JSON, HTML, and PDF report access from the dashboard/API.

### Security
- API mutations are disabled unless `VAPTFORGE_API_KEY` is explicitly configured.
- API key comparison uses constant-time comparison.

## [0.4.0] - 2026-09-30

### Added
- Remediation retest engine.
- FIXED, PERSISTENT, CHANGED, and NEW delta classification.
- Standalone HTML and PDF VAPT reports.
- Executive severity metrics and sanitized sample report.

## [0.3.0] - 2026-09-30

### Added
- SQLite assessment, asset, finding, evidence, note, and status-history persistence.
- Manual validation lifecycle and evidence attachment metadata.
- CVSS v3.1 base-score calculation.
- Curated CWE to OWASP Top 10 (2021) enrichment.

## [0.2.0] - 2026-09-30

### Added
- Cookie, CORS, HTTP method, and TLS security checks.
- Nikto, ffuf, and ProjectDiscovery httpx adapters/parsers.
- Cross-scanner CVE correlation and evidence deduplication.

## [0.1.0] - 2026-09-30

### Added
- Explicit authorized-scope enforcement.
- Nmap and Nuclei adapters/parsers.
- Common finding model, CLI, Markdown/JSON reporting, local vulnerable lab, and CI.
