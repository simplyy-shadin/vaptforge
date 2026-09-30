from pathlib import Path

from fastapi.testclient import TestClient

from vaptforge.api.main import create_app
from vaptforge.models.finding import AssetRef, Finding, FindingStatus, Severity
from vaptforge.persistence.store import AssessmentStore
from vaptforge.retest.engine import compare_findings


def seed_database(path: Path) -> tuple[str, str, str]:
    with AssessmentStore(path) as store:
        first = store.create_assessment(
            name="Baseline",
            authorization_reference="Owned lab",
            target="http://127.0.0.1:3000",
        )
        second = store.create_assessment(
            name="Retest",
            authorization_reference="Owned lab",
            target="http://127.0.0.1:3000",
        )
        finding = Finding(
            title="Example issue",
            severity=Severity.MEDIUM,
            asset=AssetRef(target="http://127.0.0.1:3000", host="127.0.0.1"),
            source="unit-test",
        )
        finding_id = store.save_finding(first.id, finding)
        store.save_finding(second.id, finding)
        results = compare_findings(
            [item.finding for item in store.list_findings(first.id)],
            [item.finding for item in store.list_findings(second.id)],
        )
        store.save_retest(first.id, second.id, results)
    return first.id, second.id, finding_id


def test_dashboard_and_assessment_api(tmp_path: Path) -> None:
    database = tmp_path / "vaptforge.db"
    first, _, _ = seed_database(database)
    client = TestClient(create_app(database_path=database, api_key="secret"))

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Baseline" in dashboard.text

    detail = client.get(f"/api/assessments/{first}")
    assert detail.status_code == 200
    assert detail.json()["metrics"]["total"] == 1

    filtered = client.get(
        f"/api/assessments/{first}/findings",
        params={"severity": "MEDIUM", "status": "discovered"},
    )
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1


def test_api_mutations_require_configured_key(tmp_path: Path) -> None:
    database = tmp_path / "vaptforge.db"
    _, _, finding_id = seed_database(database)
    client = TestClient(create_app(database_path=database, api_key="secret"))

    denied = client.post(
        f"/api/findings/{finding_id}/transition",
        json={"status": "potential", "note": "reviewed"},
    )
    assert denied.status_code == 401

    allowed = client.post(
        f"/api/findings/{finding_id}/transition",
        headers={"X-VAPTForge-API-Key": "secret"},
        json={"status": "potential", "note": "reviewed"},
    )
    assert allowed.status_code == 200

    detail = client.get(f"/api/findings/{finding_id}")
    assert detail.json()["finding"]["finding"]["status"] == FindingStatus.POTENTIAL


def test_api_mutations_are_disabled_without_key(tmp_path: Path) -> None:
    database = tmp_path / "vaptforge.db"
    _, _, finding_id = seed_database(database)
    client = TestClient(create_app(database_path=database, api_key=None))

    response = client.post(
        f"/api/findings/{finding_id}/notes",
        json={"note": "test"},
    )
    assert response.status_code == 403


def test_report_exports_and_retest_history(tmp_path: Path) -> None:
    database = tmp_path / "vaptforge.db"
    first, second, _ = seed_database(database)
    client = TestClient(create_app(database_path=database, api_key="secret"))

    html = client.get(f"/api/assessments/{first}/report/html")
    assert html.status_code == 200
    assert "VAPT Assessment Report" in html.text

    pdf = client.get(f"/api/assessments/{first}/report/pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")

    compare = client.get(f"/api/retests/compare/{first}/{second}")
    assert compare.status_code == 200
    assert len(compare.json()["results"]) == 1

    history = client.get("/api/retests")
    assert history.status_code == 200
    assert len(history.json()) == 1
