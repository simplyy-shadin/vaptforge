# Scanner Extensibility

VAPTForge v0.6 introduces a small plugin contract for adding scanners without editing the core scanner registry.

## Contract

A scanner plugin must implement the `Scanner` interface:

```python
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner


class ExampleScanner(Scanner):
    name = "example"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        return []
```

The authorization check is part of the plugin contract. External scanners should return normalized `Finding` objects and must not bypass the supplied scope.

## Packaging

Register an external scanner through a Python package entry point:

```toml
[project.entry-points."vaptforge.scanners"]
example = "example_plugin.scanner:ExampleScanner"
```

VAPTForge accepts a `Scanner` instance, a `Scanner` subclass, or a zero-argument factory returning a scanner.

Use:

```bash
vaptforge scanner-list
```

to inspect all discovered built-in and external scanners.

## Collision protection

External plugins cannot silently replace built-in scanners or another scanner with the same name. Name collisions fail closed with a plugin error.
