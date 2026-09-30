from vaptforge.models.finding import AssetRef, Finding, Severity
from vaptforge.retest.engine import RetestState, compare_findings


def make_finding(title: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        asset=AssetRef(target="127.0.0.1", host="127.0.0.1", port=80),
        source="unit-test",
        location="127.0.0.1:80",
    )


def test_retest_classifies_fixed_new_persistent_and_changed() -> None:
    fixed = make_finding("Fixed issue")
    persistent_before = make_finding("Persistent issue")
    changed_before = make_finding("Changed issue", Severity.LOW)

    persistent_after = make_finding("Persistent issue")
    changed_after = make_finding("Changed issue", Severity.HIGH)
    new = make_finding("New issue")

    results = compare_findings(
        [fixed, persistent_before, changed_before],
        [persistent_after, changed_after, new],
    )
    states = {result.state for result in results}

    assert RetestState.FIXED in states
    assert RetestState.NEW in states
    assert RetestState.PERSISTENT in states
    assert RetestState.CHANGED in states
