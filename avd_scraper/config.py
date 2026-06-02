from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any


BASE_URL = "https://avd.aliyun.com"
LIST_URL = f"{BASE_URL}/high-risk/list"
DETAIL_URL = f"{BASE_URL}/detail"
SOURCE_URL = LIST_URL

DEFAULT_DATA_DIR = Path("data")
DEFAULT_OUTPUT_FILE = DEFAULT_DATA_DIR / "high_risk_vulns.json"
DEFAULT_CHECKPOINT_FILE = DEFAULT_DATA_DIR / "checkpoint.json"
DEFAULT_MONGO_FILTERED_OUTPUT_FILE = DEFAULT_DATA_DIR / "mongo_filtered_vulns.json"
MAX_RESULT_LIMIT = 1000
DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_MONGO_DATABASE = "avd"
DEFAULT_MONGO_COLLECTION = "vulnerabilities"
DEFAULT_MONGO_COLLECTIONS = {
    "avd": DEFAULT_MONGO_COLLECTION,
    "hkcert": "hkcert",
    "cve": "cve",
    "zeroday": "zeroday",
}
DEFAULT_MONGO_CONFIG_FILE = Path("mongodb.toml")
MONGO_CONFLICT_MODES = {"prompt", "skip", "overwrite"}

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


def default_chrome_executable() -> str | None:
    env_path = os.getenv("AVD_CHROME_PATH")
    if env_path:
        return env_path

    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


@dataclass(slots=True)
class ScraperSettings:
    max_pages: int | None = None
    max_details: int | None = None
    limit: int = MAX_RESULT_LIMIT
    include_cve: bool = True
    include_non_cve: bool = True
    attribute_filters: tuple[tuple[str, str], ...] = ()
    sync_enabled: bool = False
    mongo_enabled: bool = False
    mongo_uri: str | None = None
    mongo_database: str | None = None
    mongo_collection: str | None = None
    mongo_config_file: Path | None = DEFAULT_MONGO_CONFIG_FILE
    mongo_conflict: str | None = None
    mongo_interactive: bool = False
    resume: bool = False
    list_only: bool = False
    request_delay: float = 1.0
    concurrency: int = 3
    retries: int = 3
    timeout: float = 30.0
    data_dir: Path = DEFAULT_DATA_DIR
    output_file: Path = DEFAULT_OUTPUT_FILE
    checkpoint_file: Path = DEFAULT_CHECKPOINT_FILE
    browser_fallback: bool = False
    browser_headless: bool = True
    browser_timeout_ms: int = 30_000
    chrome_executable: str | None = None

    def for_provider(
        self,
        provider_key: str,
        *,
        default_collection: str | None = None,
        browser_fallback: bool | None = None,
        default_request_delay: float | None = None,
    ) -> "ScraperSettings":
        mongo_collection = self.mongo_collection
        if mongo_collection is None and os.getenv("AVD_MONGO_COLLECTION") is None:
            mongo_collection = mongo_collection_for_provider(
                provider_key,
                self.mongo_config_file,
                default=default_collection,
            )
        request_delay = self.request_delay
        if default_request_delay is not None and self.request_delay == 1.0:
            request_delay = default_request_delay
        return replace(
            self,
            mongo_collection=mongo_collection,
            browser_fallback=self.browser_fallback if browser_fallback is None else browser_fallback,
            request_delay=request_delay,
        )

    def normalized(self) -> "ScraperSettings":
        data_dir = Path(self.data_dir)
        output_file = Path(self.output_file)
        checkpoint_file = Path(self.checkpoint_file)

        if output_file == DEFAULT_OUTPUT_FILE:
            output_file = data_dir / DEFAULT_OUTPUT_FILE.name
        if checkpoint_file == DEFAULT_CHECKPOINT_FILE:
            checkpoint_file = data_dir / DEFAULT_CHECKPOINT_FILE.name

        chrome_executable = self.chrome_executable
        if self.browser_fallback and not chrome_executable:
            chrome_executable = default_chrome_executable()

        if not 1 <= self.limit <= MAX_RESULT_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
        if not self.include_cve and not self.include_non_cve:
            raise ValueError("at least one of include_cve/include_non_cve must be true")
        mongo_config = load_mongo_config(self.mongo_config_file)
        mongo_conflict = self.mongo_conflict or _optional_config_str(mongo_config, "conflict") or "prompt"

        if mongo_conflict not in MONGO_CONFLICT_MODES:
            choices = ", ".join(sorted(MONGO_CONFLICT_MODES))
            raise ValueError(f"mongo_conflict must be one of: {choices}")

        attribute_filters = tuple((str(field), str(value)) for field, value in self.attribute_filters)
        mongo_uri = (
            self.mongo_uri
            or os.getenv("AVD_MONGO_URI")
            or _optional_config_str(mongo_config, "uri")
            or DEFAULT_MONGO_URI
        )
        mongo_database = (
            self.mongo_database
            or os.getenv("AVD_MONGO_DB")
            or _optional_config_str(mongo_config, "database")
            or DEFAULT_MONGO_DATABASE
        )
        mongo_collection = (
            self.mongo_collection
            or os.getenv("AVD_MONGO_COLLECTION")
            or _optional_config_str(mongo_config, "collection")
            or DEFAULT_MONGO_COLLECTION
        )

        return ScraperSettings(
            max_pages=self.max_pages,
            max_details=self.max_details,
            limit=self.limit,
            include_cve=self.include_cve,
            include_non_cve=self.include_non_cve,
            attribute_filters=attribute_filters,
            sync_enabled=self.sync_enabled,
            mongo_enabled=self.mongo_enabled,
            mongo_uri=mongo_uri,
            mongo_database=mongo_database,
            mongo_collection=mongo_collection,
            mongo_config_file=self.mongo_config_file,
            mongo_conflict=mongo_conflict,
            mongo_interactive=self.mongo_interactive,
            resume=self.resume,
            list_only=self.list_only,
            request_delay=self.request_delay,
            concurrency=self.concurrency,
            retries=self.retries,
            timeout=self.timeout,
            data_dir=data_dir,
            output_file=output_file,
            checkpoint_file=checkpoint_file,
            browser_fallback=self.browser_fallback,
            browser_headless=self.browser_headless,
            browser_timeout_ms=self.browser_timeout_ms,
            chrome_executable=chrome_executable,
        )


def load_mongo_config(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {}

    config_path = Path(path)
    if not config_path.exists():
        return {}

    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    mongo = data.get("mongodb", data)
    if not isinstance(mongo, dict):
        raise ValueError(f"{config_path} must contain a MongoDB config table")
    return mongo


def mongo_collections_from_config(path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE) -> dict[str, str]:
    config = load_mongo_config(path)
    configured = config.get("collections", {})
    collections = dict(DEFAULT_MONGO_COLLECTIONS)
    if isinstance(configured, dict):
        collections.update(
            {
                str(provider).strip(): str(collection).strip()
                for provider, collection in configured.items()
                if str(provider).strip() and str(collection).strip()
            }
        )
    return collections


def mongo_collection_for_provider(
    provider_key: str,
    path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
    *,
    default: str | None = None,
) -> str:
    collections = mongo_collections_from_config(path)
    return collections.get(provider_key, default or DEFAULT_MONGO_COLLECTION)


def provider_for_mongo_collection(
    collection_name: str,
    path: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
) -> str | None:
    for provider_key, configured_collection in mongo_collections_from_config(path).items():
        if configured_collection == collection_name:
            return provider_key
    return None


def default_scrape_settings(*, limit: int = MAX_RESULT_LIMIT, mongo_enabled: bool = True) -> ScraperSettings:
    return ScraperSettings(
        limit=limit,
        mongo_enabled=mongo_enabled,
        mongo_config_file=DEFAULT_MONGO_CONFIG_FILE,
        browser_fallback=False,
        mongo_interactive=False,
    )


def mongo_filtered_output_file(data_dir: Path, collection: str) -> Path:
    safe_collection = collection.strip().replace("/", "_") or "records"
    default_name = DEFAULT_MONGO_FILTERED_OUTPUT_FILE.name
    if safe_collection == DEFAULT_MONGO_COLLECTION:
        return Path(data_dir) / default_name
    return Path(data_dir) / f"mongo_filtered_{safe_collection}.json"


def resolve_mongo_export_path(data_dir: Path, name: str, *, default_name: str) -> Path:
    cleaned = Path(name.strip() or default_name).name
    if not cleaned:
        cleaned = default_name
    if not cleaned.lower().endswith(".json"):
        cleaned = f"{cleaned}.json"
    return Path(data_dir) / cleaned


def _optional_config_str(config: dict[str, Any], key: str) -> str | None:
    value = config.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None
