# Architecture

## Design goals

VAPTForge is organized around five principles:

1. **Authorization before execution** — a scanner never receives a target until scope validation passes.
2. **Safe orchestration** — external programs receive structured argument lists and run without a shell.
3. **Parser isolation** — tool execution and output interpretation are separate modules.
4. **Normalized evidence** — all scanners return the same Finding model.
5. **Conservative classification** — discovery output remains DISCOVERED/POTENTIAL until validated.

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
  +--> Python-native HTTP/TLS analysis
  |
  +--> Command Runner (shell=False, timeout)
           |
           v
      External scanner
           |
           v
   machine-readable output
           |
           v
         Parser
           |
           +-------------------+
                               |
                               v
                           Finding[]
                               |
                               v
                    Correlation Engine
                               |
                 +-------------+-------------+
                 v                           v
             JSON export                Markdown report
```

## Scanner layer

### Python-native

- `HttpSecurityScanner` performs a normal GET plus an OPTIONS request with a synthetic Origin.
- `TlsSecurityScanner` performs an authorized TLS handshake against HTTPS targets.

### External adapters

- Nmap -> XML parser
- Nuclei -> JSONL parser
- Nikto -> JSON parser
- ffuf -> JSON parser
- httpx -> JSONL parser

Raw text scraping is avoided where the tool provides a structured format.

## Correlation

A deterministic fingerprint handles exact duplicate observations. When CVEs are present, the correlation key uses CVE + host + port so different scanners can contribute evidence to one technical finding.

Correlation preserves unique:

- sources
- evidence
- CVEs/CWEs/OWASP mappings
- references
- tags

It also keeps the highest observed severity and strongest lifecycle state.

## Safety decisions

- no `shell=True`
- no scan without a supplied scope file
- exact hostname scope rather than automatic wildcard expansion
- DoS/fuzz/bruteforce Nuclei categories excluded by default
- ffuf request-rate/concurrency/runtime bounds
- training applications bound to loopback
- no automatic VERIFIED status from scanner output
- defensive XML parsing through `defusedxml`
- TLS certificate verification enabled before fallback inspection

## Planned persistence boundary

v0.3 will add a repository/service layer between normalized findings and output. That layer will own assessment IDs, assets, evidence attachments, lifecycle transitions, validation notes, and retest history.
