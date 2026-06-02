from __future__ import annotations

import argparse
import logging

from .config import default_scrape_settings


def _hours_arg(value: str) -> float:
    try:
        hours = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hours value: {value!r}") from exc
    if hours < 1:
        raise argparse.ArgumentTypeError("hours must be at least 1")
    return hours


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Scrape vulnerability catalogs into MongoDB.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    sync_parser = subparsers.add_parser(
        "sync",
        help="Periodically sync all scrapers to MongoDB.",
    )
    sync_parser.add_argument(
        "hours",
        type=_hours_arg,
        help="Hours between sync cycles (minimum 1).",
    )

    subparsers.add_parser(
        "tui",
        help="Interactive scrape: choose scraper and amount, sync to MongoDB.",
    )
    return parser


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        raise SystemExit(2)

    _configure_logging()

    if args.command == "sync":
        from .sync import run_periodic_sync

        try:
            settings = default_scrape_settings().normalized()
        except ValueError as exc:
            parser.error(str(exc))
        run_periodic_sync(args.hours, settings)
        return

    if args.command == "tui":
        from .scrape_tui import run_scrape_tui

        run_scrape_tui()
        return

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
