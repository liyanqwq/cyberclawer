import asyncio
import copy
from urllib.parse import parse_qs, urlparse

import pytest

from avd_scraper.client import FetchResult
from avd_scraper.config import ScraperSettings
from avd_scraper.mongo import MongoSyncResult
from avd_scraper.runner import AVDScraper
from avd_scraper.scrapers.cisco import CiscoProvider
from avd_scraper.scrapers.cve import CVEProvider
from avd_scraper.scrapers.govcert import GovCERTProvider
from avd_scraper.scrapers.zeroday import ZeroDayProvider


@pytest.fixture(autouse=True)
def disable_cve_backfill(monkeypatch) -> None:
    async def fake_backfill(*args, **kwargs) -> MongoSyncResult:
        return MongoSyncResult()

    monkeypatch.setattr("avd_scraper.runner.backfill_missing_cves", fake_backfill)


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
        "avd:2026-10001",
        "avd:2026-10002",
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
        "avd:2026-10001",
        "avd:2026-10002",
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

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
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
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
    ]
    assert set(collection.documents) == {
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
    }
    assert output["mongo_sync"]["inserted"] == 3
    assert not settings.output_file.exists()
    assert client.list_pages_seen == [1, 2]


def test_mongo_update_stops_when_newest_page_already_known(tmp_path) -> None:
    client = FakeClient()
    collection = FakeMongoCollection(
        {
            "avd:2026-10001": {"_id": "avd:2026-10001", "type": "avd", "code": "2026-10001"},
            "avd:2026-10002": {"_id": "avd:2026-10002", "type": "avd", "code": "2026-10002"},
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
            "avd:2026-10002": {"_id": "avd:2026-10002", "type": "avd", "code": "2026-10002"},
            "avd:2026-10003": {"_id": "avd:2026-10003", "type": "avd", "code": "2026-10003"},
            "avd:2026-10004": {"_id": "avd:2026-10004", "type": "avd", "code": "2026-10004"},
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

    assert identities(output["vulnerabilities"]) == ["avd:2026-10001"]
    assert output["mongo_sync"]["inserted"] == 1
    assert set(collection.documents) == {
        "avd:2026-10001",
        "avd:2026-10002",
        "avd:2026-10003",
        "avd:2026-10004",
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


def test_cve_json_provider_embeds_detail_and_advances_checkpoint(tmp_path) -> None:
    client = FakeCVEClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cves.json",
        checkpoint_file=tmp_path / "cve_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    scraper = AVDScraper(settings, provider=CVEProvider())
    output = asyncio.run(scraper._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["cve:2024-3094"]
    record = output["vulnerabilities"][0]
    assert record["cve_code"] is None
    assert record["details"]["cve"]["cve_id"] == "CVE-2024-3094"
    assert scraper.checkpoint.nvd_start_index == 1
    assert scraper.checkpoint.nvd_last_mod_end is not None
    assert "startIndex=0" in client.urls_seen[0]


def test_zeroday_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeZeroDayClient()
    collection = FakeMongoCollection(
        {
            "zeroday:1102": {
                "_id": "zeroday:1102",
                "type": "zeroday",
                "code": "1102",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "zeroday.json",
        checkpoint_file=tmp_path / "zeroday_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        AVDScraper(
            settings,
            provider=ZeroDayProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["zeroday:1104", "zeroday:1103"]
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"zeroday:1104", "zeroday:1103", "zeroday:1102"}
    assert client.detail_ids_seen == ["1104", "1103"]


def test_govcert_mongo_sync_stops_at_first_known_record(tmp_path) -> None:
    client = FakeGovCERTClient()
    collection = FakeMongoCollection(
        {
            "govcert:1892": {
                "_id": "govcert:1892",
                "type": "govcert",
                "code": "1892",
            },
        }
    )
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "govcert.json",
        checkpoint_file=tmp_path / "govcert_checkpoint.json",
        limit=5,
        mongo_enabled=True,
        mongo_conflict="skip",
        request_delay=0,
        retries=0,
        concurrency=2,
    )

    output = asyncio.run(
        AVDScraper(
            settings,
            provider=GovCERTProvider(),
            mongo_client_factory=fake_mongo_factory(collection),
        )._run_with_client(client)
    )

    assert identities(output["vulnerabilities"]) == ["govcert:1894", "govcert:1893"]
    assert output["vulnerabilities"][0]["cve_code"] == "2026-1894"
    assert output["mongo_sync"]["inserted"] == 2
    assert set(collection.documents) == {"govcert:1894", "govcert:1893", "govcert:1892"}
    assert client.detail_ids_seen == ["1894", "1893"]


def test_cisco_json_provider_uses_bearer_header_and_embeds_detail(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CISCO_OPENVULN_TOKEN", "token-123")
    client = FakeCiscoClient()
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cisco.json",
        checkpoint_file=tmp_path / "cisco_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(AVDScraper(settings, provider=CiscoProvider())._run_with_client(client))

    assert identities(output["vulnerabilities"]) == ["cisco:cisco-sa-foo-123"]
    record = output["vulnerabilities"][0]
    assert record["cve_code"] == "2026-12345"
    assert record["details"]["cisco"]["advisory_id"] == "cisco-sa-foo-123"
    assert client.headers_seen == [
        {"Accept": "application/json", "Authorization": "Bearer token-123"},
    ]


def test_cisco_json_provider_missing_auth_fails_before_fetch(tmp_path, monkeypatch) -> None:
    for name in (
        "CISCO_OPENVULN_TOKEN",
        "CISCO_OPENVULN_CLIENT_ID",
        "CISCO_OPENVULN_CLIENT_SECRET",
        "CISCO_CLIENT_ID",
        "CISCO_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    client = FakeNoCallJSONClient()
    events: list[dict] = []
    settings = ScraperSettings(
        data_dir=tmp_path,
        output_file=tmp_path / "cisco.json",
        checkpoint_file=tmp_path / "cisco_checkpoint.json",
        limit=1,
        request_delay=0,
        retries=0,
        concurrency=1,
    )

    output = asyncio.run(
        AVDScraper(
            settings,
            provider=CiscoProvider(),
            progress_callback=events.append,
        )._run_with_client(client)
    )

    assert output["vulnerabilities"] == []
    assert not client.called
    assert any(
        event["phase"] == "list-failed" and "requires authentication" in event["error"]
        for event in events
    )


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


class FakeCVEClient:
    def __init__(self) -> None:
        self.urls_seen: list[str] = []

    async def get_json(self, url: str, *, headers=None):
        self.urls_seen.append(url)
        return FakeJSONResult(
            {
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 2,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-3094",
                            "published": "2024-03-29T17:15:21.150",
                            "lastModified": "2025-08-19T01:15:57.407",
                            "vulnStatus": "Modified",
                            "descriptions": [{"lang": "en", "value": "xz backdoor"}],
                            "metrics": {},
                            "weaknesses": [],
                            "references": [],
                            "configurations": [],
                        }
                    }
                ],
            },
            url,
        )


class FakeZeroDayClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path == "/database/":
            return FetchResult(html=zeroday_list_html(), status_code=200, url=url)

        code = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        self.detail_ids_seen.append(code)
        return FetchResult(html=zeroday_detail_html(code), status_code=200, url=url)


class FakeGovCERTClient:
    def __init__(self) -> None:
        self.detail_ids_seen: list[str] = []

    async def get_html(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        if parsed.path == "/en/alerts.php":
            return FetchResult(html=govcert_list_html(), status_code=200, url=url)

        code = parse_qs(parsed.query)["id"][0]
        self.detail_ids_seen.append(code)
        return FetchResult(html=govcert_detail_html(code), status_code=200, url=url)


class FakeCiscoClient:
    def __init__(self) -> None:
        self.headers_seen: list[dict | None] = []

    async def get_json(self, url: str, *, headers=None):
        self.headers_seen.append(dict(headers or {}))
        parsed = urlparse(url)
        if parsed.path.endswith("/all"):
            return FakeJSONResult(
                {
                    "advisories": [
                        {
                            "advisoryId": "cisco-sa-foo-123",
                            "advisoryTitle": "Cisco Product Remote Code Execution Vulnerability",
                            "cves": "CVE-2026-12345",
                            "firstPublished": "2026-05-20T15:00:00",
                            "status": "Final",
                            "sir": "Critical",
                        }
                    ],
                    "paging": {"count": 1, "next": "NA", "prev": "NA"},
                },
                url,
            )
        return FakeJSONResult(
            {
                "advisories": [
                    {
                        "advisoryId": "cisco-sa-foo-123",
                        "advisoryTitle": "Cisco Product Remote Code Execution Vulnerability",
                        "cves": "CVE-2026-12345",
                        "firstPublished": "2026-05-20T15:00:00",
                        "status": "Final",
                        "sir": "Critical",
                    }
                ]
            },
            url,
        )


class FakeNoCallJSONClient:
    def __init__(self) -> None:
        self.called = False

    async def get_json(self, url: str, *, headers=None):
        self.called = True
        raise AssertionError("missing provider auth should prevent JSON fetch")


class FakeJSONResult:
    def __init__(self, data: dict, url: str) -> None:
        self.data = data
        self.status_code = 200
        self.url = url


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


def zeroday_list_html() -> str:
    rows = [
        ("1104", "Newest remote code execution", "CVE-2026-1104", "Remote code execution", "2026-06-04"),
        ("1103", "Next privilege escalation", "CVE-2026-1103", "Privilege escalation", "2026-06-03"),
        ("1102", "Known authentication bypass", "CVE-2026-1102", "Authentication bypass", "2026-06-02"),
        ("1101", "Older unknown issue", "CVE-2026-1101", "Path traversal", "2026-06-01"),
    ]
    body = "\n".join(
        f"""
        <div class="issue" id="item_{index}">
          <h3 class="issue-title">
            <a href="/database/{code}/">{title}<br><span class="issue-code">{cve_id}</span></a>
          </h3>
          <div class="description">
            <p class="desc-title">{vuln_type}</p>
            <p>Summary for {code}</p>
          </div>
          <div class="issue-status">
            <div class="discavered"><time>{date}</time></div>
            <div class="patched"><time>{date}</time></div>
          </div>
          <div class="spec"><strong>Product {code}</strong></div>
        </div>
        """
        for index, (code, title, cve_id, vuln_type, date) in enumerate(rows)
    )
    return f"""
    <div id="last_vulnerabilities">
      <p>Zero-day vulnerabilities discovered: 4</p>
      <div id="issuew_wrap">{body}</div>
    </div>
    """


def zeroday_detail_html(code: str) -> str:
    return f"""
    <div id="last_vulnerabilities">
      <div class="issue">
        <h3 class="issue-title">Weakness {code}<br><span class="issue-code">CVE-2026-{code}</span></h3>
        <div class="issue-status">
          <div class="discavered"><time>2026-06-01</time></div>
          <div class="patched"><time>2026-06-01</time></div>
        </div>
        <div class="description">
          <p><b>Advisory</b>: <a href="https://example.test/advisory/{code}">Advisory {code}</a></p>
          <p><b>Vulnerable component:</b> Product {code}</p>
          <p><b>CVE-ID</b>: CVE-2026-{code}</p>
          <p><b>CVSSv3 score</b>: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</p>
          <p><b>CWE-ID</b>: CWE-78 - OS Command Injection</p>
          <p><b>Description</b>:</p>
          <p>Detail for {code}</p>
        </div>
      </div>
    </div>
    """


def govcert_list_html() -> str:
    rows = [
        ("1894", "High Threat Security Alert (A26-06-01): Vulnerability in Linux Kernel", "01-June-2026"),
        ("1893", "Security Alert (A26-05-48): Multiple Vulnerabilities in Microsoft Edge", "29-May-2026"),
        ("1892", "Security Alert (A26-05-47): Multiple Vulnerabilities in Google Chrome", "29-May-2026"),
        ("1891", "High Threat Security Alert (A26-05-46): Multiple Vulnerabilities in Oracle Products", "29-May-2026"),
    ]
    body = "\n".join(
        f"""
        <div class="view-row">
          <div class="view-col-1">
            <span class="label label-primary">{date}</span>
            <a href="alerts_detail.php?id={code}">{title}</a>
          </div>
        </div>
        """
        for code, title, date in rows
    )
    return f"""
    <span class="total_page">1</span>
    <div class="view-table">{body}</div>
    """


def govcert_detail_html(code: str) -> str:
    return f"""
    <h1 id="doc_title">Security Alert (A26-06-01): Test Alert {code}</h1>
    <p class="text-content">Published on: 01 June 2026</p>
    <div class="noneditable">
      <h4>Description:</h4>
      <p>Detail for CVE-2026-{code}</p>
      <h4>Affected Systems:</h4>
      <ul><li>Product {code}</li></ul>
      <h4>Impact:</h4>
      <p>Remote code execution.</p>
      <h4>Recommendation:</h4>
      <p>Patch now.</p>
      <h4>More Information:</h4>
      <ul><li>https://example.test/advisory/{code}</li></ul>
    </div>
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
