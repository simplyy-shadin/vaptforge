from __future__ import annotations

from collections import Counter

from vaptforge.models.finding import Finding
from vaptforge.retest.engine import RetestResult


def finding_metrics(findings: list[Finding]) -> dict[str, object]:
    severity = Counter(item.severity.label() for item in findings)
    status = Counter(item.status.value for item in findings)
    return {
        "total": len(findings),
        "severity": dict(sorted(severity.items())),
        "status": dict(sorted(status.items())),
    }


def retest_metrics(results: list[RetestResult]) -> dict[str, int]:
    counts = Counter(result.state.value for result in results)
    return {
        "fixed": counts.get("fixed", 0),
        "persistent": counts.get("persistent", 0),
        "changed": counts.get("changed", 0),
        "new": counts.get("new", 0),
        "total": len(results),
    }
