"""Command-line interface for STIXGEN.

Subcommand:
  build   classify IOCs from a file (or stdin) and emit a STIX 2.1 bundle

Formats: table (human), json (STIX bundle, for pipelines), html (shareable UI).

Exit codes:
  0  ran, no valid IOCs found (nothing to report)
  1  usage / read error
  2  valid IOCs found ("findings") — non-zero so CI/pipelines can branch
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    parse_iocs,
    build_bundle,
    summarize,
    render_html,
    STIXGenError,
)

_SEV_GLYPH = {"high": "!!", "medium": "! ", "low": "  ", "unknown": "??"}


def _read_input(path: Optional[str]) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise STIXGenError(f"cannot read {path}: {exc}") from exc


def _render_table(iocs, summary, producer, bundle_id) -> str:
    lines = []
    lines.append(f"STIXGEN {TOOL_VERSION} — producer={producer}")
    lines.append(f"bundle: {bundle_id}")
    lines.append("")
    width = max((len(i.value) for i in iocs), default=5)
    width = min(width, 60)
    lines.append(f"  {'SEV':<4} {'TYPE':<13} {'VALUE':<{width}}  NOTE")
    lines.append("  " + "-" * (4 + 13 + width + 8))
    order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    for ioc in sorted(iocs, key=lambda i: order.get(i.severity, 9)):
        g = _SEV_GLYPH.get(ioc.severity, "  ")
        val = ioc.value if len(ioc.value) <= width else ioc.value[: width - 1] + "…"
        lines.append(f"{g} {ioc.severity:<4} {ioc.kind:<13} {val:<{width}}  {ioc.note}")
    lines.append("")
    sev = summary["by_severity"]
    lines.append(
        f"  total={summary['total']}  valid={summary['valid']}  "
        f"invalid={summary['invalid']}  "
        f"[high={sev['high']} medium={sev['medium']} low={sev['low']}]"
    )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Build STIX 2.1 bundles from a list of IOCs/observables "
                    "(defensive intel sharing).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="classify IOCs and emit a STIX 2.1 bundle")
    b.add_argument("input", nargs="?", default="-",
                   help="IOC file (one per line, '#' comments); '-' = stdin")
    b.add_argument("--format", choices=["table", "json", "html"],
                   default="table", help="output format (default: table)")
    b.add_argument("--producer", default="STIXGEN",
                   help="identity name for the producing organization")
    b.add_argument("--label", action="append", default=[],
                   help="label to attach to each indicator (repeatable)")
    b.add_argument("-o", "--output", help="write report/bundle to this file")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd is None:
        parser.print_help()
        return 1

    if args.cmd == "build":
        try:
            text = _read_input(args.input)
        except STIXGenError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        iocs = parse_iocs(text)
        summary = summarize(iocs)
        bundle = build_bundle(iocs, producer=args.producer, labels=args.label)
        bundle_id = bundle["id"]

        if args.format == "json":
            out = json.dumps(bundle, indent=2)
        elif args.format == "html":
            out = render_html(iocs, summary, args.producer, bundle_id)
        else:
            out = _render_table(iocs, summary, args.producer, bundle_id)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(out)
            except OSError as exc:
                print(f"error: cannot write {args.output}: {exc}",
                      file=sys.stderr)
                return 1
            print(f"wrote {args.format} report -> {args.output} "
                  f"({summary['valid']} STIX objects)", file=sys.stderr)
        else:
            print(out)

        # non-zero exit when there are findings (valid IOCs)
        return 2 if summary["valid"] > 0 else 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
