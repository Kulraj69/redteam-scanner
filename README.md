# redteam-scanner (artscan)

Fuzzes your own agents for prompt injection and tool abuse - project #4
("Agent Red-Team Scanner") from the TOP 1% AI projects list.

## Scope

artscan contains no network code. A target is an in-process agent object the
caller owns, implementing the probe interface (handle_user, handle_tool_result,
request_tool, burst). `artscan.targets.SyntheticAgent` is the built-in
stand-in; agent-lab's MiniAgent plugs in as a real working target. This is a
design property (there is no code path that reaches a live system), not a
guarantee about what a caller wraps - use it only on agents you own.

## What it does

- 10 probes across injection, tool abuse, data leak and availability:
  system-prompt leak, role override ("you are now X"), secret exfiltration,
  tool-output injection, canary leakage, off-allowlist tool calls, tool-schema
  disclosure, base64-encoded instructions, PII echo, and missing rate limits.
- Ships two demo targets: `vulnerable` (all 10 weaknesses on) and `hardened`
  (all off). Scanning them shows the full find-then-patch loop: the vulnerable
  scan reports 10 findings, the hardened scan is clean.
- Markdown vulnerability report with severity sorting. Secrets found during a
  scan are redacted from the report.

## Usage

```bash
python3 -m artscan.cli run --target vulnerable --report before.md
python3 -m artscan.cli run --target hardened --report after.md
```

Exit 0 when clean, 1 when findings exist - a hardened build can gate CI on
staying clean.

## Tests

```bash
python3 -m unittest discover -s tests
```

13 tests, stdlib only. The test oracle is the vulnerable/hardened pair: the
first must produce exactly the 10 seeded findings, the second exactly zero.

## Road to the post's target ("10+ vulns found and patched, report published")

The demo already finds 10 seeded vulns and proves the patch. The real version
needs a target adapter that wraps a genuine agent we own (e.g. a Qualifier or
Leash agent build) behind the same handle_user/handle_tool_result/request_tool
interface, plus a wider probe corpus. That adapter is next; publishing the
report and any repo still needs approval.

## Demo

`demo.py` reproduces the recorded demo run end to end, offline (standard
library only, no model calls):

    python demo.py

It executes the library's real code path and prints the same output shown in
the recorded demo video.
