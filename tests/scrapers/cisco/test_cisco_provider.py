import asyncio

import pytest

from avd_scraper.providers import CiscoProvider, get_provider, provider_keys
from avd_scraper.scrapers.cisco import CiscoAuthError


def test_cisco_provider_urls_headers_and_registry(monkeypatch) -> None:
    monkeypatch.setenv("CISCO_OPENVULN_TOKEN", "secret-token")
    provider = CiscoProvider()

    assert "cisco" in provider_keys()
    assert get_provider("cisco").key == "cisco"
    assert provider.list_url(1) == "https://apix.cisco.com/security/advisories/v2/all?pageIndex=1&pageSize=100"
    assert provider.list_url(3) == "https://apix.cisco.com/security/advisories/v2/all?pageIndex=3&pageSize=100"
    assert (
        provider.detail_url("CISCO-cisco-sa-foo-123")
        == "https://apix.cisco.com/security/advisories/v2/advisory/cisco-sa-foo-123"
    )
    assert provider.request_headers() == {
        "Accept": "application/json",
        "Authorization": "Bearer secret-token",
    }
    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer secret-token",
    }
    assert provider.default_mongo_collection == "cisco"
    assert not provider.browser_fallback
    assert not provider.stop_on_first_known


def test_cisco_provider_fetches_and_caches_oauth_token(monkeypatch) -> None:
    monkeypatch.delenv("CISCO_OPENVULN_TOKEN", raising=False)
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_ID", "client-id")
    monkeypatch.setenv("CISCO_OPENVULN_CLIENT_SECRET", "client-secret")
    calls: list[tuple[str, str]] = []

    async def fake_fetch(self, client_id: str, client_secret: str) -> dict[str, object]:
        calls.append((client_id, client_secret))
        return {"access_token": "oauth-token", "expires_in": 3600}

    monkeypatch.setattr(CiscoProvider, "_fetch_access_token", fake_fetch)
    provider = CiscoProvider()

    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer oauth-token",
    }
    assert asyncio.run(provider.async_request_headers()) == {
        "Accept": "application/json",
        "Authorization": "Bearer oauth-token",
    }
    assert calls == [("client-id", "client-secret")]


def test_cisco_provider_missing_credentials_fails_before_api_request(monkeypatch) -> None:
    for name in (
        "CISCO_OPENVULN_TOKEN",
        "CISCO_OPENVULN_CLIENT_ID",
        "CISCO_OPENVULN_CLIENT_SECRET",
        "CISCO_CLIENT_ID",
        "CISCO_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(CiscoAuthError, match="requires authentication"):
        asyncio.run(CiscoProvider().async_request_headers())
