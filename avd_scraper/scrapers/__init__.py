from __future__ import annotations

from typing import Any, Protocol

from avd_scraper.models import ListPage
from avd_scraper.scrapers.avd import AVDProvider
from avd_scraper.scrapers.hkcert import HKCERTProvider


class ScraperProvider(Protocol):
    key: str
    source_url: str
    default_mongo_collection: str
    browser_fallback: bool

    def list_url(self, page: int) -> str: ...

    def detail_url(self, identity_display: str) -> str: ...

    def parse_list(self, html: str, *, page: int) -> ListPage: ...

    def parse_detail(self, html: str) -> Any: ...


PROVIDERS: dict[str, type[ScraperProvider]] = {
    "avd": AVDProvider,
    "hkcert": HKCERTProvider,
}


def provider_keys() -> tuple[str, ...]:
    return tuple(PROVIDERS.keys())


def get_provider(key: str) -> ScraperProvider:
    factory = PROVIDERS.get(key)
    if factory is None:
        choices = ", ".join(sorted(PROVIDERS))
        raise KeyError(f"unknown provider {key!r}; choose one of: {choices}")
    return factory()


def all_providers() -> list[ScraperProvider]:
    return [factory() for factory in PROVIDERS.values()]
