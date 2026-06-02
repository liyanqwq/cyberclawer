from __future__ import annotations

import asyncio
import logging
import time

from .config import ScraperSettings
from .providers import all_providers
from .runner import AVDScraper

logger = logging.getLogger(__name__)


def run_sync_cycle(settings: ScraperSettings) -> None:
    for provider in all_providers():
        provider_settings = settings.for_provider(
            provider.key,
            default_collection=provider.default_mongo_collection,
            browser_fallback=provider.browser_fallback,
        )
        normalized = provider_settings.normalized()
        logger.info(
            "Starting MongoDB sync for provider %s collection %s",
            provider.key,
            normalized.mongo_collection,
        )
        output = asyncio.run(AVDScraper(provider_settings, provider=provider).run())
        vulnerabilities = output.get("vulnerabilities", [])
        completed = sum(
            1
            for item in vulnerabilities
            if isinstance(item.get("details"), dict)
            and isinstance(item["details"].get(provider.key), dict)
        )
        logger.info(
            "Provider %s: fetched %s records (%s with details, limit=%s)",
            provider.key,
            len(vulnerabilities),
            completed,
            normalized.limit,
        )
        mongo = output.get("mongo_sync")
        if mongo:
            logger.info(
                "Provider %s MongoDB sync: inserted=%s overwritten=%s skipped=%s conflicts=%s",
                provider.key,
                mongo["inserted"],
                mongo["overwritten"],
                mongo["skipped"],
                mongo["conflicts"],
            )


def run_periodic_sync(hours: float, settings: ScraperSettings) -> None:
    interval_seconds = hours * 3600
    logger.info("Periodic sync every %s hour(s)", hours)
    try:
        while True:
            logger.info("Sync cycle starting")
            run_sync_cycle(settings)
            logger.info("Sync cycle complete; sleeping for %s hour(s)", hours)
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logger.info("Periodic sync stopped")
