import asyncio

import httpx
import pytest

from avd_scraper.client import AVDClient, FetchError


def test_get_json_does_not_retry_non_retryable_4xx() -> None:
    async def run() -> int:
        fake_client = FakeHTTPClient(status_code=403)
        client = AVDClient(delay=0, retries=3, timeout=1)
        await client._client.aclose()
        client._client = fake_client
        try:
            with pytest.raises(FetchError, match="403"):
                await client.get_json("https://example.test/api")
        finally:
            await client.aclose()
        return fake_client.calls

    assert asyncio.run(run()) == 1


class FakeHTTPClient:
    def __init__(self, *, status_code: int) -> None:
        self.status_code = status_code
        self.calls = 0

    async def get(self, url: str, *, headers=None):
        self.calls += 1
        return httpx.Response(
            self.status_code,
            request=httpx.Request("GET", url),
            json={"error": "forbidden"},
        )

    async def aclose(self) -> None:
        return None
