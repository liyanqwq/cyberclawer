import pytest

from avd_scraper.cli import build_parser, main


def test_cli_without_subcommand_has_no_command() -> None:
    parser = build_parser()
    args = parser.parse_args([])

    assert args.command is None


def test_cli_parses_sync_hours() -> None:
    parser = build_parser()
    args = parser.parse_args(["sync", "3"])

    assert args.command == "sync"
    assert args.hours == 3.0


def test_cli_rejects_sync_hours_below_one() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["sync", "0.5"])


def test_cli_parses_tui_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["tui"])

    assert args.command == "tui"


def test_cli_rejects_removed_flags() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--limit", "5"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-sync"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--mongo-filter-tui"])


def test_main_without_subcommand_exits() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])

    assert exc.value.code == 2


def test_main_tui_dispatches(monkeypatch) -> None:
    called = {"tui": False}

    def fake_tui() -> None:
        called["tui"] = True

    monkeypatch.setattr("avd_scraper.scrape_tui.run_scrape_tui", fake_tui)

    main(["tui"])

    assert called["tui"]


def test_main_sync_dispatches(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_periodic(hours: float, settings) -> None:
        captured["hours"] = hours
        captured["settings"] = settings

    monkeypatch.setattr("avd_scraper.sync.run_periodic_sync", fake_periodic)

    main(["sync", "3"])

    assert captured["hours"] == 3.0
    assert captured["settings"].mongo_enabled is True
    assert captured["settings"].browser_fallback is False
