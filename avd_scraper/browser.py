from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .config import BASE_URL, DEFAULT_USER_AGENT


@dataclass(slots=True)
class BrowserFetchResult:
    html: str
    url: str
    status_code: int | None
    cookies: list[dict[str, Any]]


class BrowserHTMLFetcher:
    def __init__(
        self,
        *,
        headless: bool = True,
        timeout_ms: int = 30_000,
        chrome_executable: str | None = None,
    ) -> None:
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.chrome_executable = chrome_executable
        self._playwright = None
        self._browser = None
        self._context = None

    async def __aenter__(self) -> "BrowserHTMLFetcher":
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed. Install with `pip install -e .[browser]` "
                "or run without --browser-fallback."
            ) from exc

        self._playwright = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        if self.chrome_executable:
            launch_kwargs["executable_path"] = self.chrome_executable

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        self._context = await self._browser.new_context(
            user_agent=DEFAULT_USER_AGENT,
            locale="zh-CN",
            viewport={"width": 1440, "height": 1100},
            extra_http_headers={"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._context is not None:
            await self._context.close()
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def fetch(self, url: str) -> BrowserFetchResult:
        if self._context is None:
            raise RuntimeError("BrowserHTMLFetcher must be used as an async context manager.")

        page = await self._context.new_page()
        response = None
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            await self._wait_for_real_content(page)
            html = await page.content()
            cookies = await self._context.cookies(BASE_URL)
            return BrowserFetchResult(
                html=html,
                url=page.url,
                status_code=response.status if response else None,
                cookies=cookies,
            )
        finally:
            await page.close()

    async def _wait_for_real_content(self, page) -> None:
        deadline = asyncio.get_running_loop().time() + (self.timeout_ms / 1000)
        last_html = ""

        while asyncio.get_running_loop().time() < deadline:
            try:
                ready = await page.evaluate(
                    """() => {
                        const body = document.body ? document.body.innerText : "";
                        return Boolean(
                            document.querySelector("table") ||
                            document.querySelector("span.header__title__text") ||
                            body.includes("AVD-") ||
                            body.includes("漏洞名称")
                        );
                    }"""
                )
                if ready:
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5_000)
                    except Exception:
                        pass
                    return
            except Exception:
                pass

            current_html = await page.content()
            if current_html != last_html:
                last_html = current_html
            await asyncio.sleep(0.5)

        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
