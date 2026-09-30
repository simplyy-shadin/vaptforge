# VAPT Methodology

VAPTForge follows an assessment lifecycle rather than treating vulnerability scanning as the finished product.

## 1. Authorization and scope

Document the assessment name, permission reference, in-scope assets, exclusions, testing window, and prohibited actions. VAPTForge enforces the in-scope target list before execution.

## 2. Reconnaissance

Use service and HTTP discovery to understand the exposed surface. In v0.2 this can include Nmap and httpx metadata.

## 3. Configuration assessment

Python-native checks review:

- HTTP response security headers
- sensitive cookie attributes
- CORS origin handling
- TRACE exposure
- TLS validation, expiry, protocol and cipher observations

These findings remain DISCOVERED or POTENTIAL until reviewed.

## 4. Vulnerability discovery

Selected tools can extend coverage:

- Nuclei for template-based checks
- Nikto for web-server observations
- ffuf for controlled content discovery

Tool output is normalized instead of copied directly into the final report.

## 5. Triage and correlation

Combine duplicate or overlapping scanner observations while preserving scanner provenance and evidence. CVE matches on the same host/port can be correlated across tools.

## 6. Manual validation

A scanner result is not proof of exploitability. Review the affected endpoint, evidence, preconditions, version information, and application behavior before promoting a finding to VERIFIED. Unreproducible observations can be marked FALSE_POSITIVE.

## 7. Risk classification

Technical severity is an input, not a substitute for context. Consider exposure, prerequisites, asset importance, data sensitivity, realistic impact, and compensating controls. CVSS support is planned for v0.3.

## 8. Reporting

For each reportable issue capture:

- affected asset and location
- description
- evidence
- severity
- CWE/OWASP/CVE mappings where defensible
- remediation guidance
- validation status

Sanitize sensitive evidence before publishing example reports.

## 9. Remediation and retesting

After remediation, rerun only the relevant authorized checks, compare the normalized finding/evidence state, and classify findings as fixed, persistent, changed, or new. Automated retest comparison is planned for v0.4.
