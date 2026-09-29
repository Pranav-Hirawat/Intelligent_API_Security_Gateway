"""
Entry point:  python -m iasg

    --once      run a single cycle and exit
    --dry-run   decide everything, write no policy
    --interval  seconds between cycles
"""

from __future__ import annotations

import argparse
from dataclasses import replace

from iasg.config import Settings
from iasg.runner import Runner, report


def main() -> None:
    parser = argparse.ArgumentParser(prog="iasg", description="IASG decision engine")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="write no policy keys")
    parser.add_argument("--interval", type=int, help="seconds between cycles")
    args = parser.parse_args()

    settings = Settings.from_env()

    # Settings is frozen, so overrides make a modified copy rather than mutating.
    if args.dry_run:
        settings = replace(settings, dry_run=True)
    if args.interval:
        settings = replace(settings, interval_seconds=args.interval)

    runner = Runner(settings)
    if args.once:
        report(runner.cycle())
    else:
        runner.run_forever()


if __name__ == "__main__":
    main()
