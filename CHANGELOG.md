# Changelog

All notable VAPTForge changes are documented here. The project follows semantic versioning for portfolio milestones.

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
