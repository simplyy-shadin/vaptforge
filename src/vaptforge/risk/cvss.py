from __future__ import annotations

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


class CvssVectorError(ValueError):
    pass


def _round_up_1(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def parse_cvss_v31(vector: str) -> dict[str, str]:
    normalized = vector.strip()
    if normalized.startswith("CVSS:3.1/"):
        normalized = normalized.removeprefix("CVSS:3.1/")
    elif normalized.startswith("CVSS:3.0/"):
        normalized = normalized.removeprefix("CVSS:3.0/")

    metrics: dict[str, str] = {}
    for segment in normalized.split("/"):
        if ":" not in segment:
            raise CvssVectorError(f"Invalid CVSS metric segment: {segment}")
        key, value = segment.split(":", maxsplit=1)
        metrics[key.upper()] = value.upper()

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = sorted(required - set(metrics))
    if missing:
        raise CvssVectorError(f"Missing CVSS metrics: {', '.join(missing)}")
    return metrics


def score_cvss_v31(vector: str) -> float:
    metrics = parse_cvss_v31(vector)
    scope_changed = metrics["S"] == "C"
    if metrics["S"] not in {"U", "C"}:
        raise CvssVectorError("Scope must be U or C")

    try:
        attack_vector = AV[metrics["AV"]]
        attack_complexity = AC[metrics["AC"]]
        privileges = (
            PR_CHANGED[metrics["PR"]]
            if scope_changed
            else PR_UNCHANGED[metrics["PR"]]
        )
        user_interaction = UI[metrics["UI"]]
        confidentiality = CIA[metrics["C"]]
        integrity = CIA[metrics["I"]]
        availability = CIA[metrics["A"]]
    except KeyError as exc:
        raise CvssVectorError(f"Unsupported CVSS metric value: {exc.args[0]}") from exc

    impact_subscore = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope_changed:
        impact = (
            7.52 * (impact_subscore - 0.029)
            - 3.25 * ((impact_subscore - 0.02) ** 15)
        )
    else:
        impact = 6.42 * impact_subscore

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * attack_vector
        * attack_complexity
        * privileges
        * user_interaction
    )
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _round_up_1(base)
