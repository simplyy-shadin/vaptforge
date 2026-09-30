# Deep Assessment Engine (v0.9)

VAPTForge Deep mode is the native attack-surface and vulnerability-candidate analysis layer for explicitly authorized web targets.

It is designed to go beyond tool orchestration while keeping assessment behavior bounded, reviewable, and analyst-controlled.

## What Deep mode does

The `deep` profile combines the normal VAPTForge scanner stack with the built-in `deep-web` scanner:

- bounded same-origin crawling
- reachable-page inventory
- HTML form inventory
- GET parameter discovery
- static same-origin JavaScript bundle analysis for API-like routes and query parameters
- environment-backed authenticated sessions
- optional session verification
- analyst-directed same-origin crawl seeds
- benign reflected-input analysis for potential XSS sinks
- single-quote differential analysis for database error behavior
- finding confidence metadata
- correlation with Nuclei, ffuf, Nmap, httpx, HTTP/TLS, and Nikto when available

The native Deep scanner does not require an external binary.

## Safety boundaries

Deep mode still requires an explicit `AuthorizedScope`. Scope is checked before crawling, session verification, crawl seeds, and active parameter requests.

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

Crawling is bounded to 40 pages and depth 2 by default. JavaScript analysis is bounded to 12 same-origin scripts, 1 MB per script, and 100 extracted API-like endpoints. JavaScript is never executed. Active analysis is bounded to 30 discovered GET parameters. Paths associated with logout, deletion, revocation, or similar state-changing actions are skipped.

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

Optional scanners that are unavailable are visibly skipped in guided mode. The native `deep-web` engine remains available because it is implemented in Python inside VAPTForge.

## Interpreting native findings

### Potential reflected XSS sink

VAPTForge sends a unique benign marker that contains HTML-special characters. A finding is created only when that exact marker is reflected verbatim in an HTML response and was absent from the baseline.

This demonstrates unsafe-looking reflection, not browser script execution. Manual context validation is still required.

### Potential SQL injection error behavior

VAPTForge compares a baseline GET response with a request where one discovered parameter receives a single quote. A finding is created only when a database-specific error signature appears in the mutated response and was absent from the baseline.

No UNION queries, time delays, data extraction, authentication bypass, or database enumeration are attempted.

## Authenticated Deep scanning

Deep mode can reuse an already-authorized application session without storing raw session values in VAPTForge persistence.

A scope stores only environment-variable names plus non-secret verification and crawl metadata:

```json
{
  "assessment_name": "Authenticated Lab",
  "authorization_reference": "Owned lab",
  "targets": [{"value": "127.0.0.1"}],
  "session": {
    "cookie_env": "VAPTFORGE_SESSION_COOKIE",
    "verify_url": "http://127.0.0.1:4280/index.php",
    "verify_status": 200,
    "success_contains": "Authenticated Area"
  },
  "crawl_seeds": [
    "/authenticated/search/",
    "/authenticated/profile/"
  ]
}
```

Set the actual secret only in the process environment:

```powershell
$env:VAPTFORGE_SESSION_COOKIE="<authorized-session-cookie>"
python -m vaptforge.cli session-check --scope config/scope.authenticated.example.json
```

The worker inherits the launcher environment. Scope JSON and SQLite job state contain the environment-variable name, not its value.

When `verify_url` is configured, VAPTForge performs a same-origin verification request before crawling. It checks the expected status and, when supplied, the success marker. A failed verification stops the native Deep scan instead of silently scanning the login page.

`crawl_seeds` let the analyst direct the crawler toward known in-scope authenticated areas. Seeds are resolved against the assessment target and must remain same-origin and authorized. Cross-origin or state-changing seeds are rejected.

Authorization-header and custom-header references are also supported through `authorization_env` and `headers_env`. Missing configured variables fail closed. Do not place raw cookies, bearer tokens, API keys, or CSRF tokens directly in scope files.

## Why this architecture

The goal is to make VAPTForge useful to a penetration tester without hiding important judgment behind automation:

1. discover the attack surface
2. verify authenticated state when configured
3. seed known in-scope application areas
4. collect bounded evidence
5. create clearly labeled vulnerability candidates
6. correlate with external scanner evidence
7. let the analyst validate
8. preserve evidence and confidence
9. retest after remediation

This keeps the tool useful for real assessment workflow while making false-positive handling and analyst responsibility explicit.
