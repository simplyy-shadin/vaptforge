# Architecture

## Design goals

VAPTForge is organized around four principles: explicit authorization, scanner isolation, normalized data, and reproducible reporting.

### 1. Authorization before execution

The scope model is evaluated before a scanner process is launched. Exact hosts/IPs and CIDR ranges are supported. Hostname entries are exact-match by default; wildcard expansion is intentionally not automatic.

### 2. Scanner adapters

Each scanner implements a small interface and returns `Finding` objects. Raw command execution is centralized so scanner modules do not need shell interpolation.

### 3. Parser separation

Scanner adapters execute tools; parser modules interpret machine-readable outputs. This keeps parsing testable without requiring the external scanner to be installed.

### 4. Common finding model

A common Pydantic model separates VAPT workflow logic from scanner-specific output. It supports severity, lifecycle status, evidence, CVEs, CWEs, OWASP mappings, references, remediation, and metadata.

## Data flow

```text
CLI/API
  |
  v
AuthorizedScope.require_authorized()
  |
  v
Scanner Adapter
  |
  +--> Command Runner (shell=False, timeout)
  |
  v
Machine-readable output
  |
  v
Parser
  |
  v
Finding[]
  |
  v
Correlation Engine
  |
  +--> JSON export
  +--> Markdown/HTML/PDF reporting (Markdown implemented in v0.1)
  +--> Persistence/retest engine (planned)
```

## Security decisions

- No `shell=True` execution.
- No target scan without a supplied scope file.
- Disruptive Nuclei categories are excluded by default.
- Scanner findings default to `DISCOVERED`, not `VERIFIED`.
- Raw evidence can be stored separately from the normalized finding representation.
- Local training applications bind to `127.0.0.1` by default.
