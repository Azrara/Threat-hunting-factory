"""Run the collector from the command line, for cron or a systemd timer.

    python -m app.ai.collector --once
"""

from __future__ import annotations

import argparse
import logging
import sys

from ...database import init_db
from ..config import ai_settings
from .schedule import run_now


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true",
                        help="run one collection now and exit (the only mode)")
    parser.add_argument("--quiet", action="store_true", help="only report the outcome")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    init_db()
    record = run_now("cli", ai_settings)
    # Every counter is read defensively: a run that failed before its first commit
    # still has to print a line rather than raise on the way out.
    def count(name: str) -> int:
        return getattr(record, name, 0) or 0

    print(
        f"{record.status}: {count('sources_polled')} sources, {count('articles_fetched')} articles "
        f"read, {count('articles_relevant')} relevant, {count('candidates_created')} candidates "
        f"proposed, {count('duplicates_merged')} duplicates, {count('model_calls')} model calls, "
        f"{count('duration_ms') / 1000:.1f}s"
    )
    for warning in record.warnings or []:
        print(f"  warning: {warning}")
    if record.rotated_feeds or []:
        print(f"  feeds that rotated since the last run: {', '.join(record.rotated_feeds)}")
    if record.error:
        print(f"  error: {record.error.strip().splitlines()[-1]}")
    return 0 if record.status == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
