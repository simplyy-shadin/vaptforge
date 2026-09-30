from __future__ import annotations

from vaptforge.reporting.metrics import retest_metrics
from vaptforge.retest.engine import RetestResult


def render_retest_markdown(
    before_assessment: str,
    after_assessment: str,
    results: list[RetestResult],
) -> str:
    metrics = retest_metrics(results)
    lines = [
        "# VAPT Retest Report",
        "",
        f"**Before assessment:** `{before_assessment}`  ",
        f"**After assessment:** `{after_assessment}`",
        "",
        "## Delta Summary",
        "",
        "| State | Count |",
        "|---|---:|",
        f"| Fixed | {metrics['fixed']} |",
        f"| Persistent | {metrics['persistent']} |",
        f"| Changed | {metrics['changed']} |",
        f"| New | {metrics['new']} |",
        "",
        "## Findings",
        "",
    ]

    for result in results:
        finding = result.after or result.before
        if finding is None:
            continue
        lines.extend(
            [
                f"### {result.state.value.upper()}: {finding.title}",
                "",
                f"- **Severity:** {finding.severity.label()}",
                f"- **Asset:** `{finding.asset.host or finding.asset.target}`",
                f"- **Correlation key:** `{result.key}`",
                "",
            ]
        )
    return "\n".join(lines)
