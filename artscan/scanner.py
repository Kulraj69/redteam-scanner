"""Scanner: run the probe corpus against a target and collect findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from .probes import PROBES, Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)  # list[Finding]
    probes_run: int = 0

    @property
    def clean(self) -> bool:
        return not self.findings

    def by_severity(self, sev: str) -> list:
        return [f for f in self.findings if f.severity == sev]


REQUIRED_INTERFACE = ("handle_user", "handle_tool_result", "request_tool", "burst")


def scan(target) -> ScanResult:
    """Probe a target agent.

    Scope rule: artscan contains no network code at all. A target is an
    in-process object the caller owns, implementing handle_user,
    handle_tool_result, request_tool and burst. That is a design property of
    the package (there is nothing here that could reach a live system), not
    a runtime guarantee about what a caller might wrap.
    """
    missing = [m for m in REQUIRED_INTERFACE if not callable(getattr(target, m, None))]
    if missing:
        raise TypeError(f"target does not implement the probe interface: {missing}")
    findings = []
    for probe in PROBES:
        f = probe(target)
        if f is not None:
            findings.append(f)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.probe))
    return ScanResult(target=target.name, findings=findings, probes_run=len(PROBES))
