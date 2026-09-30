# VAPTForge

VAPTForge is a portfolio-grade **Vulnerability Assessment and Penetration Testing orchestration framework** for authorized labs and environments. It focuses on repeatable assessment workflows, explicit scope enforcement, normalized findings, evidence correlation, and professional reporting instead of simply wrapping scanner commands.

> **Authorized testing only.** VAPTForge refuses to scan targets that are not explicitly present in the supplied scope file. Use it only on systems you own or have written permission to assess.

## Why this project exists

Real VAPT work is more than running scanners. A useful assessment needs controlled scope, reproducible evidence, manual validation, finding normalization, risk classification, remediation guidance, and retesting. VAPTForge is being built around that lifecycle.

```text
Authorization -> Scope Validation -> Recon/Scanning -> Parsing
      -> Normalization -> Correlation -> Validation -> Reporting -> Retest
```

## Current release: v0.1.0

The first milestone provides:

- Explicit JSON-based authorization/scope gate
- Safe subprocess execution (`shell=False`)
- Nmap service-enumeration adapter
- Nuclei adapter with disruptive tags excluded by default
- Built-in HTTP security-header checks (no external scanner required)
- Structured Nmap XML and Nuclei JSONL parsing
- Common Pydantic finding model
- Finding fingerprinting and duplicate correlation
- Markdown VAPT report generation
- Optional JSON findings export
- CLI (`vaptforge`)
- FastAPI health endpoint
- Local DVWA + OWASP Juice Shop Docker lab
- Unit tests and GitHub Actions CI
- Scheduled dependency audit workflow

## Architecture

```text
                        +------------------+
                        | Authorized Scope |
                        +---------+--------+
                                  |
                                  v
+---------+      +----------------+----------------+
|   CLI   |----->|         Scanner Registry       |
+---------+      +-----------+----------+----------+
                            /            \
                           v              v
                     +----------+    +----------+
                     |   Nmap   |    |  Nuclei  |
                     +----+-----+    +----+-----+
                          |               |
                          v               v
                    XML Parser       JSONL Parser
                          \               /
                           v             v
                         +---------------+
                         | Normalization |
                         +-------+-------+
                                 |
                                 v
                         +---------------+
                         | Correlation   |
                         +-------+-------+
                                 |
                     +-----------+-----------+
                     v                       v
                JSON Findings          Markdown Report
```

See [`docs/architecture.md`](docs/architecture.md) for design details.

## Quick start

### 1. Install VAPTForge

```bash
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows PowerShell

pip install -e ".[dev]"
```

External tools are intentionally not hidden behind Python packages. Install only the scanners you intend to use, then check them with:

```bash
vaptforge doctor
```

### 2. Start the local vulnerable lab

```bash
docker compose -f labs/docker-compose.yml up -d
```

The lab binds only to loopback by default:

- OWASP Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:4280`

### 3. Review the authorized scope

```bash
cat config/scope.example.json
vaptforge scope-check http://127.0.0.1:3000 --scope config/scope.example.json
```

### 4. Run an assessment

Nmap only:

```bash
vaptforge scan 127.0.0.1 \
  --scope config/scope.example.json \
  --scanners nmap \
  --output reports/local-nmap.md \
  --json-output reports/local-nmap.json
```

Built-in HTTP checks + Nmap + Nuclei:

```bash
vaptforge scan http://127.0.0.1:3000 \
  --scope config/scope.example.json \
  --scanners http,nmap,nuclei \
  --output reports/juice-shop.md \
  --json-output reports/juice-shop.json
```

> VAPTForge normalizes URL targets for host-based scanners while preserving the original scope check.

## Scope file

Every scan requires a scope file:

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

An out-of-scope target is rejected before any scanner is executed.

## Finding model

VAPTForge normalizes scanner-specific output into one structure containing:

- title and severity
- affected asset and location
- source scanner
- lifecycle status
- CVE/CWE/OWASP mappings
- references and tags
- evidence
- remediation
- tool-specific metadata
- deterministic fingerprint for correlation

The intended lifecycle is:

```text
DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED
                         \-> FALSE_POSITIVE
```

Scanner output is not automatically treated as a confirmed vulnerability.

## Testing

```bash
pytest
ruff check .
```

Current test coverage includes scope authorization, Nmap parsing, Nuclei normalization, duplicate correlation, and report generation.

## API

Run the development API:

```bash
uvicorn vaptforge.api.main:app --reload
```

Health endpoint:

```text
GET /health
```

The API will later expose assessments, assets, findings, validation state, evidence, and retest history.

## Roadmap

The next milestones are intentionally VAPT-focused:

1. Assessment workspace and persistent assessment IDs
2. Expand built-in HTTP checks to cookie/CORS/method analysis
3. Nikto, ffuf, httpx, and TLS adapters
4. CVSS v3.1/v4 scoring support and OWASP/CWE enrichment
5. Manual validation workflow with evidence attachments
6. SQLite persistence and finding lifecycle history
7. Retest/delta engine for before-vs-after remediation
8. HTML/PDF professional report templates
9. FastAPI assessment API and dashboard
10. Sanitized demo assessment against the bundled lab

See [`ROADMAP.md`](ROADMAP.md).

## Project boundaries

VAPTForge is designed as an **authorized assessment framework**, not an exploitation or evasion framework. Default adapters prioritize enumeration and vulnerability discovery. Potentially disruptive scan categories such as DoS, fuzzing, and brute force are excluded from the default Nuclei execution path.

## Portfolio value

This project is designed to demonstrate:

- VAPT methodology
- reconnaissance and service enumeration
- web vulnerability assessment
- secure process execution
- scanner integration and parsing
- finding normalization and correlation
- false-positive awareness
- evidence-driven reporting
- remediation and retesting concepts
- Python security engineering
- CI and dependency security

## License

MIT — see [`LICENSE`](LICENSE).
