"""Reproduces the demo video's real output: 10 probes, vulnerable vs hardened."""
from artscan.scanner import scan
from artscan.targets import vulnerable_agent, hardened_agent

if __name__ == "__main__":
    for name, target in [("vulnerable_agent", vulnerable_agent()), ("hardened_agent", hardened_agent())]:
        r = scan(target)
        print(f"target: {name}")
        for f in r.findings:
            print(f"  FAIL {f.probe} [{f.severity}]: {f.detail}")
        print(f"  -> {len(r.findings)}/{r.probes_run} findings")
