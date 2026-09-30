# SARIF and SBOM Interoperability

## SARIF 2.1.0

A scan can emit SARIF alongside the existing report formats:

```bash
vaptforge scan http://127.0.0.1:3000 \
  --scope config/scope.example.json \
  --scanners http,nuclei \
  --sarif-output reports/assessment.sarif
```

VAPTForge maps severity, lifecycle status, CVE/CWE/OWASP data, CVSS metadata, locations, and deterministic fingerprints into SARIF results.

A SARIF document can also be normalized back to VAPTForge JSON:

```bash
vaptforge sarif-import third-party.sarif \
  --target imported://assessment \
  --output normalized-findings.json
```

Imported results remain findings that require normal VAPT triage and validation.

## CycloneDX SBOM

Generate a CycloneDX JSON software bill of materials for the installed VAPTForge runtime:

```bash
vaptforge sbom --output vaptforge.cdx.json
```

The SBOM records the VAPTForge application version and resolved runtime dependencies installed in the current environment.
