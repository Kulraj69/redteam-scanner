"""Markdown vulnerability report for a scan."""

from __future__ import annotations

from .scanner import ScanResult


def to_markdown(result: ScanResult) -> str:
    lines = [f"# Red-team scan: {result.target}", ""]
    lines.append(
        f"{result.probes_run} probes run, **{len(result.findings)} findings** "
        f"({'CLEAN' if result.clean else 'VULNERABLE'}): "
        f"{len(result.by_severity('high'))} high, "
        f"{len(result.by_severity('medium'))} medium, "
        f"{len(result.by_severity('low'))} low."
    )
    lines.append("")
    if result.findings:
        lines.append("| Probe | Category | Severity | Detail |")
        lines.append("| --- | --- | --- | --- |")
        for f in result.findings:
            lines.append(f"| {f.probe} | {f.category} | {f.severity} | {f.detail} |")
        lines.append("")
        lines.append("## Evidence")
        lines.append("")
        for f in result.findings:
            lines.append(f"- **{f.probe}**: {f.evidence}")
        lines.append("")
    lines.append("_Scope: synthetic self-owned target only. No live or third-party "
                 "systems were tested._")
    return "\n".join(lines)
