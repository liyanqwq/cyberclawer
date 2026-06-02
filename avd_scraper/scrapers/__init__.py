from __future__ import annotations

from typing import Any, Literal, Protocol

from avd_scraper.models import ListPage
from avd_scraper.scrapers.avd import AVDProvider
from avd_scraper.scrapers.cve import CVEProvider
from avd_scraper.scrapers.hkcert import HKCERTProvider
from avd_scraper.scrapers.zeroday import ZeroDayProvider


class ScraperProvider(Protocol):
    key: str
    source_url: str
    default_mongo_collection: str
    browser_fallback: bool
    content_type: Literal["html", "json"]
    default_request_delay: float
    stop_on_first_known: bool

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str: ...

    def detail_url(self, identity_display: str) -> str: ...

    def parse_list(self, content: Any, *, page: int) -> ListPage: ...

    def parse_detail(self, content: Any) -> Any: ...


PROVIDERS: dict[str, type[ScraperProvider]] = {
    "avd": AVDProvider,
    "hkcert": HKCERTProvider,
    "cve": CVEProvider,
    "zeroday": ZeroDayProvider,
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
