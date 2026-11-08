"""CLI.

  artscan run --target vulnerable|hardened [--report out.md]

Exit 0 when the scan is clean, 1 when findings exist - so a hardened build
can gate CI on staying clean.
"""

from __future__ import annotations

import argparse
import sys

from .report import to_markdown
from .scanner import scan
from .targets import hardened_agent, vulnerable_agent

TARGETS = {"vulnerable": vulnerable_agent, "hardened": hardened_agent}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="artscan",
                                description="Agent red-team scanner (synthetic targets only)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("run")
    sp.add_argument("--target", choices=sorted(TARGETS), required=True)
    sp.add_argument("--report", default="")
    args = p.parse_args(argv)

    result = scan(TARGETS[args.target]())
    md = to_markdown(result)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"report written to {args.report}")
    else:
        print(md)
    return 0 if result.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
