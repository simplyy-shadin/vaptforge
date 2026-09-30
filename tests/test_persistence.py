from pathlib import Path

import pytest

from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity
from vaptforge.persistence.store import AssessmentStore, InvalidStatusTransition


def sample_finding() -> Finding:
    return Finding(
        title="Example finding",
        severity=Severity.MEDIUM,
        asset=AssetRef(
            target="http://127.0.0.1:3000",
            host="127.0.0.1",
            port=3000,
            protocol="http",
            service="http",
        ),
        source="unit-test",
        cwes=["CWE-693"],
        evidence=[Evidence(source="unit-test", summary="initial evidence")],
    )


def test_assessment_store_persists_finding_and_lifecycle(tmp_path: Path) -> None:
    database = tmp_path / "vaptforge.db"
    with AssessmentStore(database) as store:
        assessment = store.create_assessment(
            name="Local lab",
            authorization_reference="Owned lab",
            target="http://127.0.0.1:3000",
        )
        finding_id = store.save_finding(assessment.id, sample_finding())

        stored = store.get_finding(finding_id)
        assert stored is not None
        assert stored.finding.title == "Example finding"

        store.transition_finding(
            finding_id,
            FindingStatus.POTENTIAL,
            note="Scanner observation reviewed.",
        )
        store.transition_finding(
            finding_id,
            FindingStatus.VERIFIED,
            note="Reproduced in the authorized lab.",
        )
        store.add_evidence(
            finding_id,
            Evidence(
                source="manual",
                summary="Validation screenshot",
                attachment_path="evidence/VF-001.png",
            ),
        )

        updated = store.get_finding(finding_id)
        assert updated is not None
        assert updated.finding.status == FindingStatus.VERIFIED
        assert updated.finding.evidence[-1].attachment_path == "evidence/VF-001.png"
        assert len(store.status_history(finding_id)) == 2
        assert len(store.list_validation_notes(finding_id)) == 2


def test_invalid_status_transition_is_rejected(tmp_path: Path) -> None:
    with AssessmentStore(tmp_path / "vaptforge.db") as store:
        assessment = store.create_assessment(
            name="Local lab",
            authorization_reference="Owned lab",
            target="127.0.0.1",
        )
        finding_id = store.save_finding(assessment.id, sample_finding())

        with pytest.raises(InvalidStatusTransition):
            store.transition_finding(finding_id, FindingStatus.RETESTED)
