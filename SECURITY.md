# Security Policy

## Intended use

VAPTForge is intended only for systems the tester owns or is explicitly authorized to assess. Do not use the project to scan third-party systems without permission.

## Safe defaults

- Targets must match the supplied scope file.
- Scanner processes are invoked without a shell.
- Nuclei excludes DoS, fuzzing, and brute-force tagged templates in the default adapter.
- The bundled vulnerable applications listen on loopback by default.
- Findings begin as scanner observations and require validation before being treated as confirmed vulnerabilities.

## Reporting a vulnerability in VAPTForge

Open a private GitHub security advisory when the repository is hosted on GitHub. Avoid publishing exploit details for an unfixed vulnerability in VAPTForge itself.
