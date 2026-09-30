from __future__ import annotations

from vaptforge.models.finding import Finding

CWE_TO_OWASP_2021: dict[str, str] = {
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-295": "A02:2021 Cryptographic Failures",
    "CWE-326": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-614": "A07:2021 Identification and Authentication Failures",
    "CWE-693": "A05:2021 Security Misconfiguration",
    "CWE-749": "A05:2021 Security Misconfiguration",
    "CWE-942": "A05:2021 Security Misconfiguration",
    "CWE-1004": "A07:2021 Identification and Authentication Failures",
    "CWE-1275": "A07:2021 Identification and Authentication Failures",
}


def enrich_owasp(finding: Finding) -> Finding:
    enriched = finding.model_copy(deep=True)
    mappings = {
        CWE_TO_OWASP_2021[cwe]
        for cwe in enriched.cwes
        if cwe in CWE_TO_OWASP_2021
    }
    enriched.owasp = sorted(set(enriched.owasp) | mappings)
    return enriched
