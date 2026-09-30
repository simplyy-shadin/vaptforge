from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from vaptforge.correlation.engine import correlation_key
from vaptforge.models.finding import Finding


class RetestState(StrEnum):
    FIXED = "fixed"
    PERSISTENT = "persistent"
    CHANGED = "changed"
    NEW = "new"


class RetestResult(BaseModel):
    state: RetestState
    key: str
    before: Finding | None = None
    after: Finding | None = None


def _materially_changed(before: Finding, after: Finding) -> bool:
    before_evidence = {(item.source, item.summary) for item in before.evidence}
    after_evidence = {(item.source, item.summary) for item in after.evidence}
    return any(
        [
            before.severity != after.severity,
            before.status != after.status,
            before.cvss_score != after.cvss_score,
            before.cvss_vector != after.cvss_vector,
            set(before.cves) != set(after.cves),
            set(before.cwes) != set(after.cwes),
            before_evidence != after_evidence,
        ]
    )


def compare_findings(
    before_findings: list[Finding],
    after_findings: list[Finding],
) -> list[RetestResult]:
    before = {correlation_key(finding): finding for finding in before_findings}
    after = {correlation_key(finding): finding for finding in after_findings}
    results: list[RetestResult] = []

    for key in sorted(before.keys() | after.keys()):
        old = before.get(key)
        new = after.get(key)
        if old is not None and new is None:
            results.append(
                RetestResult(
                    state=RetestState.FIXED,
                    key=key,
                    before=old,
                )
            )
        elif old is None and new is not None:
            results.append(
                RetestResult(
                    state=RetestState.NEW,
                    key=key,
                    after=new,
                )
            )
        elif old is not None and new is not None:
            state = (
                RetestState.CHANGED
                if _materially_changed(old, new)
                else RetestState.PERSISTENT
            )
            results.append(
                RetestResult(
                    state=state,
                    key=key,
                    before=old,
                    after=new,
                )
            )

    return results
