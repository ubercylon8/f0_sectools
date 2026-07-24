"""CLI: generate a persona posture report (Markdown + optional PDF, en/es).

Re-gathers findings deterministically via report_gather (no MCP round-trip),
parses the agent-authored narrative, builds the report, writes <out>.md and
optionally <out>.pdf. Local-only; nothing leaves the host."""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
from datetime import UTC, datetime
from pathlib import Path

import report_gather
from f0_sectools_core.reports import build_report, to_pdf
from f0_sectools_core.reports.pdf import ReportsPdfUnavailable

_PERSONAS = ("ciso", "threat-hunter", "detection-engineer", "security-engineer")
_LANGS = ("en", "es")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a persona security posture report.")
    p.add_argument("--persona", required=True, choices=_PERSONAS)
    p.add_argument("--lang", default="en", choices=_LANGS)
    p.add_argument(
        "--narrative", required=True, type=Path,
        help="Agent-authored narrative Markdown file.",
    )
    p.add_argument("--window-hours", type=int, default=168)
    p.add_argument("--tenant-label", default="the organization")
    p.add_argument(
        "--out", required=True, type=Path,
        help="Output basepath (writes <out>.md, <out>.pdf).",
    )
    p.add_argument("--pdf", action="store_true")
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()
    narrative = args.narrative.read_text(encoding="utf-8")
    findings, meta = await report_gather.gather(args.persona, args.window_hours)
    meta = dataclasses.replace(
        meta,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        tenant_label=args.tenant_label,
    )
    out = build_report(args.persona, args.lang, narrative, findings, meta)
    md_path = args.out.with_suffix(".md")
    md_path.write_text(out.markdown, encoding="utf-8")
    print(f"wrote {md_path}")
    if args.pdf:
        try:
            pdf = to_pdf(out.html)
        except ReportsPdfUnavailable as e:
            print(f"PDF skipped: {e}")
        else:
            pdf_path = args.out.with_suffix(".pdf")
            pdf_path.write_bytes(pdf)
            print(f"wrote {pdf_path}")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
