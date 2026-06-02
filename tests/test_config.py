import pytest

from avd_scraper.config import (
    MAX_RESULT_LIMIT,
    ScraperSettings,
    default_scrape_settings,
    load_mongo_config,
    mongo_collection_for_provider,
    mongo_collections_from_config,
    resolve_mongo_export_path,
)


def test_load_mongo_config_reads_mongodb_table(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        conflict = "overwrite"
        """,
        encoding="utf-8",
    )

    config = load_mongo_config(config_file)

    assert config["uri"] == "mongodb://config.test:27017"
    assert config["database"] == "config_db"
    assert config["collection"] == "config_collection"
    assert config["conflict"] == "overwrite"


def test_scraper_settings_use_mongo_config_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AVD_MONGO_URI", raising=False)
    monkeypatch.delenv("AVD_MONGO_DB", raising=False)
    monkeypatch.delenv("AVD_MONGO_COLLECTION", raising=False)
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        conflict = "skip"
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).normalized()

    assert settings.mongo_uri == "mongodb://config.test:27017"
    assert settings.mongo_database == "config_db"
    assert settings.mongo_collection == "config_collection"
    assert settings.mongo_conflict == "skip"


def test_environment_values_override_mongo_config_file(tmp_path, monkeypatch) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "config_db"
        collection = "config_collection"
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("AVD_MONGO_URI", "mongodb://env.test:27017")
    monkeypatch.setenv("AVD_MONGO_DB", "env_db")
    monkeypatch.setenv("AVD_MONGO_COLLECTION", "env_collection")

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).normalized()

    assert settings.mongo_uri == "mongodb://env.test:27017"
    assert settings.mongo_database == "env_db"
    assert settings.mongo_collection == "env_collection"


def test_default_scrape_settings_enables_mongo_without_provider_browser_default() -> None:
    settings = default_scrape_settings(limit=25).normalized()

    assert settings.limit == 25
    assert settings.mongo_enabled
    assert not settings.browser_fallback
    assert settings.limit <= MAX_RESULT_LIMIT


def test_mongo_collection_for_provider_uses_collections_table(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        uri = "mongodb://config.test:27017"
        database = "avd"
        collection = "vulnerabilities"

        [mongodb.collections]
        avd = "vulnerabilities"
        hkcert = "hkcert"
        """,
        encoding="utf-8",
    )

    assert mongo_collections_from_config(config_file) == {
        "avd": "vulnerabilities",
        "hkcert": "hkcert",
        "cve": "cve",
    }
    assert mongo_collection_for_provider("hkcert", config_file) == "hkcert"


def test_scraper_settings_for_provider_sets_collection(tmp_path) -> None:
    config_file = tmp_path / "mongodb.toml"
    config_file.write_text(
        """
        [mongodb]
        database = "avd"

        [mongodb.collections]
        hkcert = "hkcert"
        """,
        encoding="utf-8",
    )

    settings = ScraperSettings(mongo_enabled=True, mongo_config_file=config_file).for_provider("hkcert").normalized()

    assert settings.mongo_collection == "hkcert"


def test_resolve_mongo_export_path_normalizes_name(tmp_path) -> None:
    path = resolve_mongo_export_path(tmp_path, "my-export", default_name="default.json")

    assert path == tmp_path / "my-export.json"


def test_resolve_mongo_export_path_uses_default_for_blank_name(tmp_path) -> None:
    path = resolve_mongo_export_path(tmp_path, "   ", default_name="mongo_filtered_vulns.json")

    assert path == tmp_path / "mongo_filtered_vulns.json"


def test_resolve_mongo_export_path_ignores_directory_components(tmp_path) -> None:
    path = resolve_mongo_export_path(tmp_path, "../outside.json", default_name="default.json")

    assert path == tmp_path / "outside.json"
