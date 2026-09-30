# Retesting and Delta Analysis

VAPTForge v0.4 compares two persisted assessments by the same correlation model used during normal finding deduplication.

## Retest states

- **FIXED** - present in the baseline assessment and absent from the retest.
- **PERSISTENT** - present in both assessments with materially equivalent normalized evidence.
- **CHANGED** - present in both assessments but severity, status, CVSS, mappings, or evidence changed.
- **NEW** - absent from the baseline and present in the retest.

## Comparable-assessment requirement

A missing finding is only meaningful as "fixed" when the baseline and retest used a comparable scope and scanner/check profile. If a scanner was omitted from the retest, its missing findings must not be interpreted as remediation proof.

## Workflow

1. Run and persist the initial authorized assessment.
2. Manually validate reportable findings.
3. Apply remediation.
4. Run a new assessment using the same scope and comparable scanners.
5. Compare the two assessment IDs.

```bash
vaptforge retest <BASELINE_ID> <RETEST_ID>   --db data/vaptforge.db   --output reports/retest.md
```

The retest report summarizes fixed, persistent, changed, and new findings.

## Report formats

Normal scans can now emit four formats from one normalized result set:

```bash
vaptforge scan http://127.0.0.1:3000   --scope config/scope.example.json   --scanners http,httpx,nuclei   --output reports/assessment.md   --json-output reports/assessment.json   --html-output reports/assessment.html   --pdf-output reports/assessment.pdf
```

HTML content is escaped before rendering. PDF content is escaped before being passed into ReportLab Paragraph markup.
