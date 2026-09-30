# VAPT Methodology

VAPTForge follows an assessment lifecycle rather than treating vulnerability scanning as the finished product.

## 1. Authorization and scope

Document the assessment name, permission reference, in-scope assets, exclusions, testing window, and prohibited actions. VAPTForge currently enforces the in-scope target list at execution time.

## 2. Reconnaissance and enumeration

Identify reachable services and relevant application surfaces using non-destructive discovery. Record protocol, port, service, product, and version evidence where available.

## 3. Vulnerability discovery

Run selected scanners and custom checks. Prefer machine-readable outputs so results can be normalized and independently reviewed.

## 4. Triage and correlation

Combine duplicate or overlapping scanner observations into one finding record. Preserve evidence and scanner provenance.

## 5. Manual validation

A scanner result remains `DISCOVERED` or `POTENTIAL` until the tester has enough evidence to confirm it. Findings that cannot be reproduced can be marked `FALSE_POSITIVE`.

## 6. Risk classification

Use technical severity together with context such as exposure, exploitability, asset value, and realistic impact. CVSS support is planned; scanner-provided severity is currently retained as an input, not treated as a final business-risk verdict.

## 7. Reporting

Each report should clearly describe affected assets, evidence, impact, remediation, and validation status. Sensitive raw evidence should be sanitized before a report is shared publicly.

## 8. Remediation and retesting

After remediation, rerun the relevant checks and compare finding fingerprints and evidence. The planned retest engine will track fixed, persistent, new, and changed findings.
