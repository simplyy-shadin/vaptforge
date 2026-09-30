# Security Policy

## Intended use

VAPTForge is intended only for systems the tester owns or is explicitly authorized to assess. Do not use the project to scan third-party systems without permission.

## Safe defaults

- Targets must match the supplied scope file.
- Scanner processes are invoked without a shell.
- Nuclei excludes DoS, fuzzing, and brute-force tagged templates in the default adapter.
- ffuf uses a small bundled wordlist with bounded request rate, concurrency, and runtime.
- The bundled vulnerable applications listen on loopback by default.
- Findings begin as DISCOVERED or POTENTIAL and require validation before VERIFIED status.
- Nmap XML is parsed with defusedxml.
- TLS certificate verification is attempted before fallback metadata inspection.

## External tools

VAPTForge does not vendor Nmap, Nuclei, Nikto, ffuf, or ProjectDiscovery httpx. Install and update those tools from their official sources. Their behavior, templates, and signatures can change independently of VAPTForge.

## Reporting a vulnerability in VAPTForge

Use a private GitHub security advisory when possible. Avoid publishing exploit details for an unfixed vulnerability in VAPTForge itself.
