from __future__ import annotations

import asyncio

import pytest

from avd_scraper.config import default_scrape_settings
from avd_scraper.providers import AVDProvider
from avd_scraper.sync import run_sync_cycle


def test_run_sync_cycle_calls_each_provider(monkeypatch) -> None:
    calls: list[str] = []
    collections: list[str | None] = []
    browser_fallbacks: list[bool] = []

    class FakeScraper:
        def __init__(self, settings, *, provider=None) -> None:
            self.provider = provider or AVDProvider()
            self.settings = settings.normalized()

        async def run(self):
            calls.append(self.provider.key)
            collections.append(self.settings.mongo_collection)
            browser_fallbacks.append(self.settings.browser_fallback)
            return {
                "vulnerabilities": [{"details": {self.provider.key: {}}}],
                "mongo_sync": {
                    "inserted": 1,
                    "overwritten": 0,
                    "skipped": 0,
                    "conflicts": 0,
                },
            }

    def fake_asyncio_run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    monkeypatch.setattr("avd_scraper.sync.AVDScraper", FakeScraper)
    monkeypatch.setattr("avd_scraper.sync.asyncio.run", fake_asyncio_run)

    run_sync_cycle(default_scrape_settings())

    assert calls == ["avd", "hkcert", "cve"]
    assert collections == ["vulnerabilities", "hkcert", "cve"]
    assert browser_fallbacks == [True, False, False]
