"""Command-line entry point for the dedicated mayfly GKI builder."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

from mayfly_builder import MayflyBuilder, PROFILE_SPECS, SOURCE_SPECS


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mayfly 专用、失败即停的 raw Image 构建入口")
    parser.add_argument("--source", required=True, choices=tuple(SOURCE_SPECS))
    parser.add_argument("--profile", required=True, choices=tuple(PROFILE_SPECS))
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/mayfly-gki"))
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    mayfly = MayflyBuilder(
        args.source,
        args.profile,
        args.workspace,
        args.artifacts,
        jobs=args.jobs,
    )
    result = mayfly.dry_run() if args.dry_run else mayfly.build()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
