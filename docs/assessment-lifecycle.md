# Assessment Lifecycle

VAPTForge v0.3 adds persistent assessment state so discovery, validation, remediation, and retesting can be tracked as one workflow.

## SQLite model

```text
Assessment
  |
  +-- Assets
  |
  +-- Findings
        |
        +-- Evidence
        +-- Validation Notes
        +-- Status History
```

The database intentionally stores both normalized finding JSON and relational fields used for workflow operations. This keeps the original scanner-normalized representation available while enabling queries and audit history.

## Creating a persistent assessment

Add `--db` to a normal scan:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nuclei   --db data/vaptforge.db   --output reports/initial.md
```

If `--assessment-id` is omitted, a new assessment UUID is created from the scope metadata. Reuse that ID on later scans to update matching findings.

## Reviewing assessments

```bash
vaptforge assessment-list --db data/vaptforge.db
vaptforge finding-list <ASSESSMENT_ID> --db data/vaptforge.db
```

## Validation workflow

Findings begin as DISCOVERED or POTENTIAL depending on the source/check. Transition them only after review:

```bash
vaptforge finding-transition <FINDING_ID> potential   --db data/vaptforge.db   --note "Scanner result reviewed; manual reproduction required."

vaptforge finding-transition <FINDING_ID> verified   --db data/vaptforge.db   --note "Reproduced in the authorized local lab."
```

Allowed transitions are explicit and stored in `status_history`.

## Manual notes and evidence

```bash
vaptforge finding-note <FINDING_ID>   --db data/vaptforge.db   --note "Behavior confirmed only when authenticated."

vaptforge finding-evidence <FINDING_ID>   --db data/vaptforge.db   --source manual   --summary "Validation screenshot"   --attachment evidence/VF-001.png
```

VAPTForge stores attachment paths/metadata rather than copying arbitrary evidence files into the database. Public reports should use sanitized evidence.

## CVSS

The v0.3 risk module implements CVSS v3.1 base-score calculation. Nuclei CVSS vectors/scores are normalized when present. CVSS is a technical severity input; it does not replace assessment context or business-impact review.

Example:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
```

## OWASP enrichment

A small curated CWE-to-OWASP Top 10 (2021) mapping enriches known CWE findings. The mapping is intentionally conservative: unsupported or ambiguous CWEs are left unmapped rather than guessed.
