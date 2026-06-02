from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .browser import BrowserHTMLFetcher
from .client import AVDClient, FetchError
from .config import ScraperSettings
from .cve_backfill import backfill_missing_cves
from .models import ListEntry
from .mongo import (
    MongoClientFactory,
    MongoSyncResult,
    collection_from_settings,
    existing_identity_keys,
    sync_records_to_collection,
)
from .providers import AVDProvider, ScraperProvider
from .scrapers.cve.config import MAX_DATE_WINDOW_DAYS

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class Checkpoint:
    completed_identity_keys: set[str] = field(default_factory=set)
    last_list_page: int = 0
    total_pages: int | None = None
    total_records: int | None = None
    failed: dict[str, dict[str, Any]] = field(default_factory=dict)
    nvd_last_mod_start: str | None = None
    nvd_last_mod_end: str | None = None
    nvd_start_index: int = 0

    @classmethod
    def load(cls, path: Path) -> "Checkpoint":
        if not path.exists():
            return cls()

        data = json.loads(path.read_text(encoding="utf-8"))
        failed_items = data.get("failed", [])
        failed = {
            item["identity"]: item
            for item in failed_items
            if isinstance(item, dict) and item.get("identity")
        }
        return cls(
            completed_identity_keys=set(
                data.get("completed_identity_keys", data.get("completed_avd_ids", []))
            ),
            last_list_page=int(data.get("last_list_page", 0)),
            total_pages=data.get("total_pages"),
            total_records=data.get("total_records"),
            failed=failed,
            nvd_last_mod_start=data.get("nvd_last_mod_start"),
            nvd_last_mod_end=data.get("nvd_last_mod_end"),
            nvd_start_index=int(data.get("nvd_start_index", 0)),
        )

    def save(self, path: Path) -> None:
        payload = {
            "updated_at": datetime.now(UTC).isoformat(),
            "completed_identity_keys": sorted(self.completed_identity_keys),
            "last_list_page": self.last_list_page,
            "total_pages": self.total_pages,
            "total_records": self.total_records,
            "nvd_last_mod_start": self.nvd_last_mod_start,
            "nvd_last_mod_end": self.nvd_last_mod_end,
            "nvd_start_index": self.nvd_start_index,
            "failed": sorted(self.failed.values(), key=lambda item: item.get("identity", "")),
        }
        _write_json_atomic(path, payload)


class AVDScraper:
    def __init__(
        self,
        settings: ScraperSettings,
        *,
        progress_callback: ProgressCallback | None = None,
        mongo_client_factory: MongoClientFactory | None = None,
        provider: ScraperProvider | None = None,
    ) -> None:
        self.progress_callback = progress_callback
        self.mongo_client_factory = mongo_client_factory
        self.provider = provider or AVDProvider()
        self.settings = settings.for_provider(
            self.provider.key,
            default_collection=self.provider.default_mongo_collection,
            browser_fallback=self.provider.browser_fallback,
            default_request_delay=getattr(self.provider, "default_request_delay", None),
        ).normalized()
        self.checkpoint = Checkpoint()
        self.records_by_id: dict[str, dict[str, Any]] = {}
        self.list_order: list[str] = []
        self.selected_ids: list[str] = []
        self.selection_finalized = False
        self.detail_fetch_count = 0
        self.mongo_result = MongoSyncResult()

    async def run(self) -> dict[str, Any]:
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)

        if self.settings.resume:
            self.checkpoint = Checkpoint.load(self.settings.checkpoint_file)
            self.records_by_id, self.list_order = _load_existing_output(self.settings.output_file)

        browser_fetcher = (
            BrowserHTMLFetcher(
                headless=self.settings.browser_headless,
                timeout_ms=self.settings.browser_timeout_ms,
                chrome_executable=self.settings.chrome_executable,
            )
            if self.settings.browser_fallback
            else None
        )

        self._emit(phase="starting")
        if browser_fetcher is None:
            async with AVDClient(
                delay=self.settings.request_delay,
                retries=self.settings.retries,
                timeout=self.settings.timeout,
            ) as client:
                return await self._run_with_client(client)

        async with browser_fetcher:
            async with AVDClient(
                delay=self.settings.request_delay,
                retries=self.settings.retries,
                timeout=self.settings.timeout,
                browser_fetcher=browser_fetcher,
            ) as client:
                return await self._run_with_client(client)

    async def _run_with_client(self, client: AVDClient) -> dict[str, Any]:
        self._ensure_provider_checkpoint()
        if self.settings.mongo_enabled:
            return await self._run_mongo_update_with_client(client)

        await self._scrape_matching_records(client)
        output = self._build_output()
        _write_json_atomic(self.settings.output_file, output)
        self.checkpoint.save(self.settings.checkpoint_file)
        self._emit(phase="completed")
        return output

    async def _run_mongo_update_with_client(self, client: AVDClient) -> dict[str, Any]:
        mongo_client, collection = collection_from_settings(
            self.settings,
            client_factory=self.mongo_client_factory,
        )
        try:
            known_ids = existing_identity_keys(collection)
            await self._scrape_newest_records(client, known_ids=known_ids)
            output = self._build_output()
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="mongo")
            scraped_at = output["scraped_at"]
            self.mongo_result = sync_records_to_collection(
                output["vulnerabilities"],
                self.settings,
                collection,
                scraped_at=scraped_at,
                source={"provider": self.provider.key, "url": self.provider.source_url},
            )
            output["mongo_sync"] = self.mongo_result.to_dict()
            if self.provider.key != "cve":
                backfill_result = await backfill_missing_cves(
                    output["vulnerabilities"],
                    self.settings,
                    mongo_client,
                    scraped_at=scraped_at,
                )
                if (
                    backfill_result.inserted
                    or backfill_result.overwritten
                    or backfill_result.skipped
                    or backfill_result.conflicts
                    or backfill_result.errors
                ):
                    output["cve_backfill"] = backfill_result.to_dict()
            self._emit(phase="mongo-complete", mongo_sync=output["mongo_sync"])
            self._emit(phase="completed")
            return output
        finally:
            close = getattr(mongo_client, "close", None)
            if close is not None:
                close()

    async def _scrape_newest_records(self, client: AVDClient, *, known_ids: set[str]) -> None:
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if self.settings.max_pages is not None and page > self.settings.max_pages:
                break
            if total_pages is not None and page > total_pages:
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching newest-update list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure("LIST", url, exc, phase="list")
                break

            if not list_page.entries:
                if self._empty_nvd_window_complete(list_page):
                    self._complete_nvd_window()
                    break
                self._record_failure(f"LIST-PAGE-{page}", url, "No rows parsed", phase="list")
                break

            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            page_ids = [entry.key for entry in list_page.entries]
            all_known_on_page = (
                self.provider.key != "cve"
                and bool(page_ids)
                and all(identity in known_ids for identity in page_ids)
            )
            candidates = self._newest_update_targets_for_page(
                list_page.entries,
                known_ids=known_ids,
                selected_count=len(selected_ids),
            )
            await self._fetch_details_for_page(client, candidates, len(selected_ids))

            for entry in candidates:
                if entry.key in selected_ids:
                    continue
                record = self.records_by_id.get(entry.key)
                if record:
                    selected_ids.append(entry.key)
                    if len(selected_ids) >= self.settings.limit:
                        break

            self.selected_ids = selected_ids.copy()
            self._advance_nvd_checkpoint(list_page)
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if self._nvd_window_page_complete(list_page):
                self._complete_nvd_window()
                self.checkpoint.save(self.settings.checkpoint_file)
                break
            if all_known_on_page:
                break
            page += 1

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    def _should_refresh_existing_before_stop(self) -> bool:
        return self.settings.mongo_conflict == "overwrite" or (
            self.settings.mongo_conflict == "prompt" and self.settings.mongo_interactive
        )

    def _newest_update_targets_for_page(
        self,
        entries: list[ListEntry],
        *,
        known_ids: set[str],
        selected_count: int,
    ) -> list[ListEntry]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []
        refresh_existing = self._should_refresh_existing_before_stop()
        for entry in entries:
            if remaining <= 0:
                break
            if self.provider.key != "cve" and entry.key in known_ids and not refresh_existing:
                continue
            targets.append(entry)
            remaining -= 1
        return targets

    async def _scrape_matching_records(self, client: AVDClient) -> None:
        page = 1
        total_pages: int | None = None
        selected_ids: list[str] = []

        while len(selected_ids) < self.settings.limit:
            if self.settings.max_pages is not None and page > self.settings.max_pages:
                break
            if total_pages is not None and page > total_pages:
                break

            url = self.provider.list_url(page, checkpoint=self.checkpoint)
            logger.info("Fetching list page %s", page)
            self._emit(phase="list", page=page)
            try:
                list_page = await self._fetch_list_page(client, url, page)
            except FetchError as exc:
                self._record_failure("LIST", url, exc, phase="list")
                break

            if not list_page.entries:
                if self._empty_nvd_window_complete(list_page):
                    self._complete_nvd_window()
                    break
                self._record_failure(f"LIST-PAGE-{page}", url, "No rows parsed", phase="list")
                break

            self._merge_list_entries(list_page.entries)
            self.checkpoint.last_list_page = page
            if list_page.total_pages is not None:
                total_pages = list_page.total_pages
                self.checkpoint.total_pages = list_page.total_pages
            if list_page.total_records is not None:
                self.checkpoint.total_records = list_page.total_records

            await self._fetch_details_for_page(client, list_page.entries, len(selected_ids))

            for entry in list_page.entries:
                if entry.key in selected_ids:
                    continue
                record = self.records_by_id.get(entry.key)
                if record:
                    selected_ids.append(entry.key)
                    if len(selected_ids) >= self.settings.limit:
                        break

            self.selected_ids = selected_ids.copy()
            self._advance_nvd_checkpoint(list_page)
            _write_json_atomic(self.settings.output_file, self._build_output())
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="page-complete", page=page)
            if self._nvd_window_page_complete(list_page):
                self._complete_nvd_window()
                self.checkpoint.save(self.settings.checkpoint_file)
                break
            page += 1

        self.selected_ids = selected_ids[: self.settings.limit]
        self.selection_finalized = True

    async def _fetch_details_for_page(
        self,
        client: AVDClient,
        entries: list[ListEntry],
        selected_count: int,
    ) -> None:
        if self.settings.list_only:
            return

        targets = self._detail_targets_for_page(entries, selected_count)
        if not targets:
            logger.info("No detail pages to fetch for this page.")
            return

        semaphore = asyncio.Semaphore(max(1, self.settings.concurrency))

        async def scrape_one(entry: ListEntry) -> None:
            async with semaphore:
                await self._scrape_detail(client, entry)

        await asyncio.gather(*(scrape_one(entry) for entry in targets))

    async def _fetch_list_page(self, client: AVDClient, url: str, page: int) -> Any:
        if getattr(self.provider, "content_type", "html") == "json":
            result = await client.get_json(url, headers=self._provider_request_headers())
            return self.provider.parse_list(result.data, page=page)

        result = await client.get_html(url)
        return self.provider.parse_list(result.html, page=page)

    def _provider_request_headers(self) -> dict[str, str]:
        request_headers = getattr(self.provider, "request_headers", None)
        if request_headers is None:
            return {}
        return dict(request_headers())

    def _ensure_provider_checkpoint(self) -> None:
        if self.provider.key != "cve":
            return
        if self.checkpoint.nvd_last_mod_start and self.checkpoint.nvd_last_mod_end:
            return

        now = datetime.now(UTC)
        if self.checkpoint.nvd_last_mod_start:
            start = _parse_nvd_datetime(self.checkpoint.nvd_last_mod_start)
            max_end = start + timedelta(days=MAX_DATE_WINDOW_DAYS)
            end = min(now, max_end)
        else:
            start = now - timedelta(days=MAX_DATE_WINDOW_DAYS)
            end = now

        self.checkpoint.nvd_last_mod_start = _format_nvd_datetime(start)
        self.checkpoint.nvd_last_mod_end = _format_nvd_datetime(end)
        self.checkpoint.nvd_start_index = max(0, self.checkpoint.nvd_start_index)

    def _advance_nvd_checkpoint(self, list_page: Any) -> None:
        if self.provider.key != "cve":
            return
        start_index = list_page.start_index if list_page.start_index is not None else self.checkpoint.nvd_start_index
        page_size = list_page.results_per_page or len(list_page.entries)
        self.checkpoint.nvd_start_index = max(self.checkpoint.nvd_start_index, start_index + page_size)

    def _nvd_window_page_complete(self, list_page: Any) -> bool:
        if self.provider.key != "cve" or list_page.total_records is None:
            return False
        return self.checkpoint.nvd_start_index >= list_page.total_records

    def _empty_nvd_window_complete(self, list_page: Any) -> bool:
        return self.provider.key == "cve" and (list_page.total_records or 0) == 0

    def _complete_nvd_window(self) -> None:
        if self.provider.key != "cve":
            return
        self.checkpoint.nvd_last_mod_start = self.checkpoint.nvd_last_mod_end
        self.checkpoint.nvd_last_mod_end = None
        self.checkpoint.nvd_start_index = 0

    def _detail_targets_for_page(
        self,
        entries: list[ListEntry],
        selected_count: int,
    ) -> list[ListEntry]:
        remaining = self.settings.limit - selected_count
        targets: list[ListEntry] = []

        for entry in entries:
            if remaining <= 0:
                break

            if not self._has_detail(entry.key):
                if self.settings.max_details is not None and self.detail_fetch_count >= self.settings.max_details:
                    break
                targets.append(entry)
                self.detail_fetch_count += 1
            remaining -= 1

        return targets

    async def _scrape_detail(self, client: AVDClient, entry: ListEntry) -> None:
        url = self.provider.detail_url(entry.display_id)
        logger.info("Fetching detail %s", entry.key)
        self._emit(phase="detail", identity=entry.key, type=entry.identity.type, code=entry.identity.code)
        try:
            if getattr(self.provider, "content_type", "html") == "json":
                result = await client.get_json(url, headers=self._provider_request_headers())
                detail = self.provider.parse_detail(result.data).to_dict()
            else:
                result = await client.get_html(url)
                detail = self.provider.parse_detail(result.html).to_dict()
            self.records_by_id[entry.key] = entry.to_record(detail, detail_url=url)
            self.checkpoint.completed_identity_keys.add(entry.key)
            self.checkpoint.failed.pop(entry.key, None)
        except Exception as exc:
            self.records_by_id[entry.key] = entry.to_record(None, detail_url=url)
            self._record_failure(entry, url, exc, phase="detail")
        finally:
            self.checkpoint.save(self.settings.checkpoint_file)
            self._emit(phase="detail-complete", identity=entry.key, type=entry.identity.type, code=entry.identity.code)

    def _merge_list_entries(self, entries: list[ListEntry]) -> None:
        for entry in entries:
            if entry.key not in self.list_order:
                self.list_order.append(entry.key)
            existing_detail = self.records_by_id.get(entry.key, {}).get("details", {}).get(entry.provider)
            detail_url = self.provider.detail_url(entry.display_id)
            self.records_by_id[entry.key] = entry.to_record(existing_detail, detail_url=detail_url)

    def _build_output(self) -> dict[str, Any]:
        if self.selected_ids or self.selection_finalized:
            ordered_ids = self.selected_ids
        else:
            ordered_ids = [
                identity
                for identity in self.list_order
                if identity in self.records_by_id
            ][: self.settings.limit]
        vulnerabilities = [
            self.records_by_id[identity]
            for identity in ordered_ids[: self.settings.limit]
            if identity in self.records_by_id
        ]
        return {
            "scraped_at": datetime.now(UTC).isoformat(),
            "source": {"provider": self.provider.key, "url": self.provider.source_url},
            "total": self.checkpoint.total_records or len(self.list_order),
            "result_count": len(vulnerabilities),
            "raw_limit": self.settings.limit,
            "vulnerabilities": vulnerabilities,
        }

    def _has_detail(self, identity: str) -> bool:
        details = self.records_by_id.get(identity, {}).get("details")
        detail = details.get(self.provider.key) if isinstance(details, dict) else None
        return isinstance(detail, dict)

    def _record_failure(self, identity: str | ListEntry, url: str, error: object, *, phase: str) -> None:
        if isinstance(identity, ListEntry):
            identity_key = identity.key
            id_type = identity.identity.type
            code = identity.identity.code
        else:
            identity_key = identity
            id_type, _, code = identity.partition(":")
        message = str(error)
        logger.warning("%s failed for %s: %s", phase, identity_key, message)
        self.checkpoint.failed[identity_key] = {
            "identity": identity_key,
            "type": id_type,
            "code": code,
            "phase": phase,
            "url": url,
            "error": message,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        self._emit(phase=f"{phase}-failed", identity=identity_key, type=id_type, code=code, error=message)

    def _emit(self, **event: Any) -> None:
        if self.progress_callback is None:
            return
        payload = {
            "selected_count": len(self.selected_ids),
            "completed_count": len(self.checkpoint.completed_identity_keys),
            "failed_count": len(self.checkpoint.failed),
            **event,
        }
        self.progress_callback(payload)


def _load_existing_output(path: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not path.exists():
        return {}, []

    data = json.loads(path.read_text(encoding="utf-8"))
    records: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for record in data.get("vulnerabilities", []):
        identity = _record_identity(record)
        if identity:
            records[identity] = record
            order.append(identity)
    return records, order


def _record_identity(record: dict[str, Any]) -> str | None:
    id_type = record.get("type")
    code = record.get("code")
    if id_type and code:
        return f"{str(id_type).lower()}:{code}"
    return None


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    tmp_path.replace(path)


def _format_nvd_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_nvd_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
