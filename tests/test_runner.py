import asyncio
import copy
from urllib.parse import parse_qs, urlparse

from avd_scraper.client import FetchResult
from avd_scraper.config import ScraperSettings
from avd_scraper.runner import AVDScraper


def test_limit_counts_raw_results(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=2,
        include_cve=True,
        include_non_cve=False,
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(AVDScraper(settings)._run_with_client(client))

    assert identities(output["vulnerabilities"]) == [
        "AVD:2026-10001",
        "AVD:2026-10002",
    ]
    assert output["result_count"] == 2
    assert output["raw_limit"] == 2
    assert client.list_pages_seen == [1]


def test_deprecated_attribute_filters_do_not_filter_scrape_results(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=2,
        include_cve=True,
        include_non_cve=True,
        attribute_filters=(("details.avd.cve_id", "CVE-2026-10003"),),
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(AVDScraper(settings)._run_with_client(client))

    assert identities(output["vulnerabilities"]) == [
        "AVD:2026-10001",
        "AVD:2026-10002",
    ]
    assert "filters" not in output
    assert client.list_pages_seen == [1]


def test_raw_limit_fetches_detail_only_for_limited_rows(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        include_cve=True,
        include_non_cve=True,
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(AVDScraper(settings)._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["AVD:2026-10001"]
    assert client.list_pages_seen == [1]


def test_mongo_update_empty_collection_fetches_newest_up_to_limit(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=3,
        mongo_enabled=True,
        mongo_conflict="overwrite",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        AVDScraper(settings, mongo_client_factory=fake_mongo_factory(collection))._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == [
        "AVD:2026-10001",
        "AVD:2026-10002",
        "AVD:2026-10003",
    ]
    assert set(collection.documents) == {
        "AVD:2026-10001",
        "AVD:2026-10002",
        "AVD:2026-10003",
    }
    assert output["mongo_sync"]["inserted"] == 3
    assert not settings.output_file.exists()
    assert client.list_pages_seen == [1, 2]


def test_mongo_update_stops_when_newest_page_already_known(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "AVD:2026-10001": {"_id": "AVD:2026-10001", "type": "AVD", "code": "2026-10001"},
            "AVD:2026-10002": {"_id": "AVD:2026-10002", "type": "AVD", "code": "2026-10002"},
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        AVDScraper(settings, mongo_client_factory=fake_mongo_factory(collection))._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert output["mongo_sync"]["inserted"] == 0
    assert not settings.output_file.exists()
    assert client.list_pages_seen == [1]


def test_mongo_update_mixed_page_syncs_new_records_then_stops_on_known_page(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "AVD:2026-10002": {"_id": "AVD:2026-10002", "type": "AVD", "code": "2026-10002"},
            "AVD:2026-10003": {"_id": "AVD:2026-10003", "type": "AVD", "code": "2026-10003"},
            "AVD:2026-10004": {"_id": "AVD:2026-10004", "type": "AVD", "code": "2026-10004"},
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        AVDScraper(settings, mongo_client_factory=fake_mongo_factory(collection))._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["AVD:2026-10001"]
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {
        "AVD:2026-10001",
        "AVD:2026-10002",
        "AVD:2026-10003",
        "AVD:2026-10004",
    }
    assert client.list_pages_seen == [1, 2]


def test_non_mongo_scrape_still_writes_json(tmp_path) -> None:
    client = FakeClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "high_risk_vulns.json",
        checkpoint_file=tmp_path / "checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    asyncio.run(AVDScraper(settings)._run_with_client(client))

    assert settings.output_file.exists()


class FakeClient:
    def __init__(self) -> None:
        self.list_pages_seen: list[int] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path.endswith("/high-risk/list"):
            page = int(parse_qs(parsed.query)["page"][0])
            self.list_pages_seen.append(page)
            return FetchResult(html=list_page_html(page), status_code=200, url=url)

        avd_id = parse_qs(parsed.query)["id"][0]
        return FetchResult(html=detail_html(avd_id), status_code=200, url=url)


def list_page_html(page: int) -> str:
    rows = {
        1: [
            ("AVD-2026-10001", "Product RCE (CVE-2026-10001)", "CWE-78"),
            ("AVD-2026-10002", "Supply chain poisoning event", "未定义"),
        ],
        2: [
            ("AVD-2026-10003", "Kernel bug", "CWE-120"),
            ("AVD-2026-10004", "Another event", "未定义"),
        ],
    }[page]
    body = "\n".join(
        f"""
        <tr>
          <td><a href="/detail?id={avd_id}">{avd_id}</a></td>
          <td>{title}</td>
          <td>{vuln_type}</td>
          <td>2026-01-0{index}</td>
          <td>CVE PoC</td>
        </tr>
        """
        for index, (avd_id, title, vuln_type) in enumerate(rows, start=1)
    )
    return f"""
    <table>
      <tr><th>AVD编号</th><th>漏洞名称</th><th>漏洞类型</th><th>披露时间</th><th>漏洞状态</th></tr>
      {body}
    </table>
    <div>第 {page} 页 / 2 页 • 总计 4 条记录</div>
    """


def detail_html(avd_id: str) -> str:
    cve_by_id = {
        "AVD-2026-10001": "CVE-2026-10001",
        "AVD-2026-10003": "CVE-2026-10003",
    }
    title = f"Detail {cve_by_id[avd_id]}" if avd_id in cve_by_id else "Detail without CVE"
    return f"""
    <span class="header__title__text">{title}</span>
    <span class="badge btn-primary">高危</span>
    <div class="text-detail">description {avd_id}</div>
    """


def fake_mongo_factory(collection: "FakeMongoCollection"):
    def create_client(uri: str) -> "FakeMongoClient":
        return FakeMongoClient(collection)

    return create_client


def identities(records: list[dict]) -> list[str]:
    return [f"{record['type']}:{record['code']}" for record in records]


class FakeMongoClient:
    def __init__(self, collection: "FakeMongoCollection") -> None:
        self.collection = collection
        self.closed = False

    def __getitem__(self, name: str) -> "FakeMongoDatabase":
        return FakeMongoDatabase(self.collection)

    def close(self) -> None:
        self.closed = True


class FakeMongoDatabase:
    def __init__(self, collection: "FakeMongoCollection") -> None:
        self.collection = collection

    def __getitem__(self, name: str) -> "FakeMongoCollection":
        return self.collection


class FakeMongoCollection:
    def __init__(self, documents: dict[str, dict] | None = None) -> None:
        self.documents = copy.deepcopy(documents or {})
        self.indexes: list[tuple[str, bool]] = []

    def create_index(self, field: str, unique: bool = False) -> None:
        self.indexes.append((field, unique))

    def find(self, query: dict | None = None, projection: dict | None = None):
        query = query or {}
        if query:
            return []
        return [copy.deepcopy(document) for document in self.documents.values()]

    def find_one(self, query: dict) -> dict | None:
        document = self.documents.get(query["_id"])
        return copy.deepcopy(document) if document is not None else None

    def insert_one(self, document: dict) -> None:
        self.documents[document["_id"]] = copy.deepcopy(document)

    def replace_one(self, query: dict, document: dict, *, upsert: bool = False) -> None:
        self.documents[query["_id"]] = copy.deepcopy(document)
