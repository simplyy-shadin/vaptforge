# Contributing

Contributions should preserve VAPTForge's authorized-testing model and safe defaults.

1. Create a feature branch.
2. Add or update tests for behavior changes.
3. Run `ruff check .` and `pytest`.
4. Prefer machine-readable scanner output and dedicated parsers.
5. Do not introduce `shell=True` or string-built command execution.
6. New scanners must call scope validation before execution.
7. Avoid destructive or denial-of-service defaults.
