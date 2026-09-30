# Deep Assessment Engine (v0.9)

VAPTForge Deep mode is the native attack-surface and vulnerability-candidate analysis layer for explicitly authorized web targets.

It is designed to go beyond tool orchestration while keeping assessment behavior bounded and reviewable.

## What Deep mode does

The `deep` profile combines the normal VAPTForge scanner stack with the built-in `deep-web` scanner:

- bounded same-origin crawling
- reachable-page inventory
- HTML form inventory
- GET parameter discovery
- benign reflected-input analysis for potential XSS sinks
- single-quote differential analysis for database error behavior
- finding confidence metadata
- correlation with Nuclei, ffuf, Nmap, httpx, HTTP/TLS, and Nikto when available

The native deep scanner does not require an external binary.

## Safety boundaries

Deep mode still requires an explicit `AuthorizedScope`. Scope is checked before crawling and before active parameter requests.

The native engine intentionally does **not**:

- brute-force credentials
- submit POST forms
- run destructive HTTP methods
- use time-delay SQL payloads
- dump database contents
- execute commands
- upload files
- exploit a discovered condition
- crawl to another origin
- automatically mark a finding VERIFIED

Crawling is bounded to 40 pages and depth 2 by default. Active analysis is bounded to 30 discovered GET parameters. Paths associated with logout, deletion, revocation, or similar state-changing actions are skipped.

## Confidence and lifecycle

Deep findings use confidence separately from lifecycle status.

Examples:

- `Status: POTENTIAL, Confidence: MEDIUM` — a benign HTML-special-character marker was reflected verbatim and needs manual browser/context validation.
- `Status: POTENTIAL, Confidence: HIGH` — a database-specific error signature appeared only after a quote mutation.
- `Status: DISCOVERED, Confidence: HIGH` — factual attack-surface inventory collected by the crawler.

Confidence is evidence strength. Status remains the analyst workflow:

`DISCOVERED -> POTENTIAL -> VERIFIED -> REMEDIATED -> RETESTED`

A scanner observation is never automatically promoted to VERIFIED.

## Run it

Guided mode:

```bash
vaptforge start
```

Choose **Deep** after selecting the authorized scope and target.

Manual queue:

```bash
vaptforge queue-assessment http://127.0.0.1:3000 \
  --scope config/scope.example.json \
  --profile deep \
  --db data/vaptforge.db
```

Direct scanner selection:

```bash
vaptforge scan http://127.0.0.1:3000 \
  --scope config/scope.example.json \
  --scanners http,tls,deep-web,httpx,nmap,nuclei,ffuf \
  --db data/vaptforge.db
```

Optional scanners that are unavailable are visibly skipped in guided mode. The native `deep-web` engine remains available because it is implemented in Python inside VAPTForge.

## Interpreting native findings

### Potential reflected XSS sink

VAPTForge sends a unique benign marker that contains HTML-special characters. A finding is created only when that exact marker is reflected verbatim in an HTML response and was absent from the baseline.

This demonstrates unsafe-looking reflection, not browser script execution. Manual context validation is still required.

### Potential SQL injection error behavior

VAPTForge compares a baseline GET response with a request where one discovered parameter receives a single quote. A finding is created only when a database-specific error signature appears in the mutated response and was absent from the baseline.

No UNION queries, time delays, data extraction, authentication bypass, or database enumeration are attempted.

## Why this architecture

The goal is to make VAPTForge useful to a penetration tester without hiding important judgment behind automation:

1. discover the attack surface
2. collect bounded evidence
3. create clearly labeled vulnerability candidates
4. correlate with external scanner evidence
5. let the analyst validate
6. preserve evidence and confidence
7. retest after remediation

This keeps the tool useful for real assessment workflow while making false-positive handling and analyst responsibility explicit.
