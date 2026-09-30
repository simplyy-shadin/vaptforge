## Summary

Describe what this change does and why it belongs in VAPTForge.

## Security / authorization impact

- [ ] Scope enforcement is preserved.
- [ ] No unauthenticated or implicit scan behavior was added.
- [ ] External commands use structured arguments and never `shell=True`.
- [ ] Scanner findings are not automatically treated as VERIFIED.
- [ ] Potentially disruptive behavior is bounded or explicitly opt-in.

## Validation

- [ ] `ruff check .`
- [ ] `pytest`
- [ ] Documentation updated where behavior changed.
- [ ] New parser/scanner behavior has fixtures or tests.

## Notes

Include any compatibility, migration, evidence-handling, or report-format considerations.
