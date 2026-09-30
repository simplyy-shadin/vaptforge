import pytest

from vaptforge.risk.cvss import CvssVectorError, score_cvss_v31


def test_cvss_v31_critical_vector_scores_98() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert score_cvss_v31(vector) == 9.8


def test_cvss_v31_zero_impact_scores_zero() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert score_cvss_v31(vector) == 0.0


def test_cvss_rejects_incomplete_vector() -> None:
    with pytest.raises(CvssVectorError):
        score_cvss_v31("CVSS:3.1/AV:N/AC:L")
