"""Privacy-conscious, low-impact monitoring for URLs listed in a sitemap."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
from collections import Counter, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
USER_AGENT = "Sitemap-Status-Monitor/2.0"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
MAX_SITEMAP_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SITEMAP_BYTES = 64 * 1024 * 1024
MAX_SITEMAPS = 200
MAX_PAGE_URLS = 50_000

Resolver = Callable[[str], Awaitable[set[str]]]


class MonitorError(RuntimeError):
    """Raised when the monitor cannot complete a trustworthy check."""


class UnsafeUrlError(MonitorError):
    """Raised when a URL could reach an unintended destination."""


@dataclass(frozen=True, slots=True)
class SitemapDocument:
    """URLs extracted from one sitemap document."""

    page_urls: tuple[str, ...]
    child_sitemaps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of checking one public URL."""

    url: str
    status_code: int | None
    category: str
    elapsed_ms: int
    attempts: int


@dataclass(frozen=True, slots=True)
class Changes:
    """Differences between current and previous monitor runs."""

    new_or_changed: tuple[CheckResult, ...]
    recovered: tuple[str, ...]
    current_failures: tuple[CheckResult, ...]


class RateLimiter:
    """Global rate limiter shared by sitemap and page requests."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 1 / requests_per_second if requests_per_second > 0 else 0
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        """Wait until another request is allowed."""
        if self._interval == 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_allowed - now)
            if delay:
                await asyncio.sleep(delay)
            self._next_allowed = max(now, self._next_allowed) + self._interval


async def _resolve_host(host: str) -> set[str]:
    def resolve() -> set[str]:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return {str(record[4][0]).split("%", 1)[0] for record in records}

    try:
        return await asyncio.to_thread(resolve)
    except socket.gaierror as exc:
        raise UnsafeUrlError("hostname could not be resolved") from exc


class PublicHostGuard:
    """Allow only HTTPS URLs on one domain whose DNS addresses are public."""

    def __init__(self, allowed_domain: str, *, resolver: Resolver | None = None) -> None:
        domain = allowed_domain.strip().lower().rstrip(".")
        if not domain or "/" in domain or ":" in domain:
            raise ValueError("ALLOWED_DOMAIN is invalid")
        self._domain = domain
        self._resolver = resolver or _resolve_host
        self._validated_hosts: set[str] = set()
        self._lock = asyncio.Lock()

    def allows_name(self, url: str) -> bool:
        """Return whether a URL has the required scheme, host, and port."""
        return self._name_rejection_reason(url) is None

    def _name_rejection_reason(self, url: str) -> str | None:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            port = parsed.port
        except (UnicodeError, ValueError):
            return "URL syntax could not be parsed"
        if parsed.scheme != "https":
            return "URL scheme is not HTTPS"
        if parsed.username is not None or parsed.password is not None:
            return "URL contains credentials"
        if port not in {None, 443}:
            return "URL port is not 443"
        if not host:
            return "URL hostname is missing"
        if host != self._domain and not host.endswith(f".{self._domain}"):
            return "URL hostname does not match the allowed domain"
        return None

    async def validate(self, url: str) -> None:
        """Reject unsafe URL syntax and hosts resolving to non-public addresses."""
        rejection_reason = self._name_rejection_reason(url)
        if rejection_reason:
            raise UnsafeUrlError(rejection_reason)
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        async with self._lock:
            if host in self._validated_hosts:
                return
            addresses = await self._resolver(host)
            if not addresses:
                raise UnsafeUrlError("hostname has no address")
            try:
                is_public = all(ipaddress.ip_address(address).is_global for address in addresses)
            except ValueError as exc:
                raise UnsafeUrlError("hostname returned an invalid address") from exc
            if not is_public:
                raise UnsafeUrlError("hostname must resolve only to a public address")
            self._validated_hosts.add(host)


def _unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _bounded_gzip_decompress(payload: bytes, max_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=BytesIO(payload)) as compressed:
            result = compressed.read(max_bytes + 1)
    except (OSError, EOFError) as exc:
        raise MonitorError("sitemap gzip is invalid") from exc
    if len(result) > max_bytes:
        raise MonitorError("sitemap exceeded the decompressed size limit")
    return result


def parse_sitemap(payload: bytes, *, max_bytes: int = MAX_SITEMAP_BYTES) -> SitemapDocument:
    """Safely parse a regular or gzip-compressed sitemap."""
    if len(payload) > max_bytes:
        raise MonitorError("sitemap exceeded the compressed size limit")
    if payload.startswith(b"\x1f\x8b"):
        payload = _bounded_gzip_decompress(payload, max_bytes)

    try:
        root = ElementTree.fromstring(payload)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise MonitorError("sitemap contains unsafe or invalid XML") from exc

    root_name = _local_name(root.tag)
    if root_name not in {"urlset", "sitemapindex"}:
        raise MonitorError("sitemap has an unsupported root element")

    locations: list[str] = []
    expected_parent = "url" if root_name == "urlset" else "sitemap"
    for parent in root:
        if _local_name(parent.tag) != expected_parent:
            continue
        for child in parent:
            if _local_name(child.tag) == "loc" and child.text:
                location = child.text.strip()
                if location:
                    locations.append(location)
                break
    if root_name == "urlset":
        return SitemapDocument(_unique(locations), ())
    return SitemapDocument((), _unique(locations))


async def _read_raw_limited(response: httpx.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in response.aiter_raw():
            size += len(chunk)
            if size > max_bytes:
                raise MonitorError("response exceeded the configured size limit")
            chunks.append(chunk)
    except httpx.StreamConsumed:
        # Mock transports and preloaded responses may already hold bounded content.
        if len(response.content) > max_bytes:
            raise MonitorError("response exceeded the configured size limit") from None
        return response.content
    return b"".join(chunks)


async def _fetch_sitemap(
    client: httpx.AsyncClient,
    url: str,
    *,
    guard: PublicHostGuard,
    limiter: RateLimiter,
) -> bytes:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        await guard.validate(current)
        await limiter.wait()
        async with client.stream("GET", current) as response:
            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("Location")
                if not location:
                    raise MonitorError("redirect was missing a destination")
                current = urljoin(str(response.url), location)
                continue
            if not 200 <= response.status_code < 300:
                raise MonitorError("sitemap returned a non-success status")
            return await _read_raw_limited(response, MAX_SITEMAP_BYTES)
    raise MonitorError("redirect limit exceeded")


async def discover_urls(
    client: httpx.AsyncClient,
    sitemap_url: str,
    *,
    guard: PublicHostGuard,
    limiter: RateLimiter | None = None,
    max_depth: int = 5,
) -> list[str]:
    """Recursively fetch validated sitemap documents and return page URLs."""
    rate_limiter = limiter or RateLimiter(0)
    try:
        await guard.validate(sitemap_url)
    except UnsafeUrlError as exc:
        raise MonitorError(f"root sitemap URL is not allowed: {exc}") from exc

    queue: deque[tuple[str, int]] = deque([(sitemap_url, 0)])
    seen_sitemaps: set[str] = set()
    page_urls: dict[str, None] = {}
    total_bytes = 0

    while queue:
        current_url, depth = queue.popleft()
        if current_url in seen_sitemaps:
            continue
        if depth > max_depth or len(seen_sitemaps) >= MAX_SITEMAPS:
            raise MonitorError("sitemap structure exceeded the configured limit")
        seen_sitemaps.add(current_url)

        try:
            payload = await _fetch_sitemap(
                client,
                current_url,
                guard=guard,
                limiter=rate_limiter,
            )
            total_bytes += len(payload)
            if total_bytes > MAX_TOTAL_SITEMAP_BYTES:
                raise MonitorError("all sitemaps exceeded the cumulative size limit")
            document = parse_sitemap(payload)
        except (httpx.HTTPError, MonitorError) as exc:
            if current_url == sitemap_url:
                raise MonitorError("root sitemap could not be read") from exc
            page_urls[current_url] = None
            print("Skipped one unreadable child sitemap")
            continue

        for page_url in document.page_urls:
            if guard.allows_name(page_url):
                page_urls[page_url] = None
                if len(page_urls) > MAX_PAGE_URLS:
                    raise MonitorError("page URL count exceeded the configured limit")
        for child_url in document.child_sitemaps:
            if guard.allows_name(child_url):
                queue.append((child_url, depth + 1))

    if not page_urls:
        raise MonitorError("sitemap contained no allowed page URLs")
    return list(page_urls)


def classify_result(status_code: int | None, error: str | None) -> str:
    """Classify availability without treating slowness alone as downtime."""
    if error:
        return error
    if status_code is None:
        return "network_error"
    if 200 <= status_code < 400:
        return "ok"
    if status_code in {404, 410}:
        return "not_found"
    if status_code in {401, 403}:
        return "blocked"
    if status_code == 429:
        return "rate_limited"
    if 500 <= status_code < 600:
        return "server_error"
    return "http_error"


def _http_error_category(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    message = str(exc).lower()
    if isinstance(exc, httpx.ConnectError) and (
        isinstance(exc.__cause__, ssl.SSLError)
        or "certificate" in message
        or "ssl" in message
        or "tls" in message
    ):
        return "tls_error"
    return "network_error"


async def _page_status(
    client: httpx.AsyncClient,
    url: str,
    *,
    guard: PublicHostGuard,
    limiter: RateLimiter,
) -> tuple[int | None, str | None]:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        await guard.validate(current)
        await limiter.wait()
        async with client.stream("GET", current, headers={"Range": "bytes=0-4095"}) as response:
            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("Location")
                if not location:
                    return response.status_code, "unsafe_redirect"
                current = urljoin(str(response.url), location)
                continue
            try:
                async for _chunk in response.aiter_raw():
                    break
            except httpx.StreamConsumed:
                pass
            return response.status_code, None
    return None, "unsafe_redirect"


async def check_url(
    client: httpx.AsyncClient,
    url: str,
    *,
    guard: PublicHostGuard,
    limiter: RateLimiter | None = None,
    retry_delays: tuple[float, ...] = (2.0, 5.0),
) -> CheckResult:
    """Check one URL with bounded reads and retry transient failures."""
    started = time.perf_counter()
    rate_limiter = limiter or RateLimiter(0)
    status_code: int | None = None
    error: str | None = None
    attempts = 0
    retryable = {
        "not_found",
        "rate_limited",
        "server_error",
        "timeout",
        "tls_error",
        "network_error",
    }

    for attempt in range(len(retry_delays) + 1):
        attempts = attempt + 1
        try:
            status_code, error = await _page_status(
                client,
                url,
                guard=guard,
                limiter=rate_limiter,
            )
        except UnsafeUrlError:
            status_code, error = None, "unsafe_redirect"
        except httpx.HTTPError as exc:
            status_code, error = None, _http_error_category(exc)

        category = classify_result(status_code, error)
        if category not in retryable or attempt >= len(retry_delays):
            break
        await asyncio.sleep(retry_delays[attempt])

    return CheckResult(
        url=url,
        status_code=status_code,
        category=classify_result(status_code, error),
        elapsed_ms=round((time.perf_counter() - started) * 1_000),
        attempts=attempts,
    )


def _url_id(url: str, hmac_key: str) -> str:
    return hmac.new(hmac_key.encode(), url.encode(), hashlib.sha256).hexdigest()


def load_previous_state(path: Path) -> dict[str, str]:
    """Load opaque URL identifiers and categories from cache."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict) or raw.get("version") != 1:
        return {}
    entries = raw.get("entries")
    if not isinstance(entries, dict):
        return {}
    return {
        identifier: category
        for identifier, category in entries.items()
        if isinstance(identifier, str)
        and len(identifier) == 64
        and isinstance(category, str)
    }


def save_state(results: list[CheckResult], *, path: Path, hmac_key: str) -> None:
    """Save state without storing recoverable URLs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "version": 1,
        "entries": {_url_id(result.url, hmac_key): result.category for result in results},
    }
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")


def compute_changes(
    current: list[CheckResult],
    previous: dict[str, str],
    *,
    hmac_key: str,
) -> Changes:
    """Compute changes by comparing opaque URL identifiers."""
    failures = tuple(result for result in current if result.category != "ok")
    new_or_changed = tuple(
        result
        for result in failures
        if previous.get(_url_id(result.url, hmac_key)) != result.category
    )
    recovered = tuple(
        result.url
        for result in current
        if result.category == "ok"
        and previous.get(_url_id(result.url, hmac_key), "ok") != "ok"
    )
    return Changes(new_or_changed, recovered, failures)


def _result_label(result: CheckResult) -> str:
    detail = str(result.status_code) if result.status_code else result.category
    return f"• {detail}: {result.url}"


def build_notification(*, total: int, changes: Changes, initial_run: bool) -> str:
    """Build a private LINE message with actionable URLs."""
    if initial_run and not changes.current_failures:
        return (
            "✅ Sitemap Monitor เริ่มทำงานแล้ว\n"
            f"ตรวจทั้งหมด {total:,} URL\n"
            "ไม่พบ URL ที่มีปัญหา"
        )

    lines = [
        "🚨 Sitemap Status Monitor",
        f"ตรวจทั้งหมด {total:,} URL",
        f"ปัญหาปัจจุบัน {len(changes.current_failures):,} URL",
        f"ปัญหาใหม่/เปลี่ยนแปลง {len(changes.new_or_changed):,} URL",
        f"กลับมาปกติ {len(changes.recovered):,} URL",
    ]
    display_results = changes.new_or_changed
    if initial_run and not display_results:
        display_results = changes.current_failures
    if display_results:
        lines.append("")
        lines.extend(_result_label(result) for result in display_results[:20])
        if len(display_results) > 20:
            lines.append(f"…แสดง 20 จาก {len(display_results):,} URL")
    if changes.recovered:
        lines.extend(("", "กลับมาปกติ:"))
        lines.extend(f"• {url}" for url in changes.recovered[:10])
        if len(changes.recovered) > 10:
            lines.append(f"…แสดง 10 จาก {len(changes.recovered):,} URL")
    return "\n".join(lines)[:5_000]


async def send_line_message(
    client: httpx.AsyncClient,
    *,
    access_token: str,
    user_id: str,
    message: str,
) -> None:
    """Push one text message to the configured LINE user."""
    response = await client.post(
        LINE_PUSH_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        json={"to": user_id, "messages": [{"type": "text", "text": message}]},
    )
    if not 200 <= response.status_code < 300:
        raise MonitorError(f"LINE Messaging API returned HTTP {response.status_code}")


async def _check_all_urls(
    client: httpx.AsyncClient,
    urls: list[str],
    *,
    guard: PublicHostGuard,
    concurrency: int,
    limiter: RateLimiter,
) -> list[CheckResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded_check(url: str) -> CheckResult:
        async with semaphore:
            return await check_url(client, url, guard=guard, limiter=limiter)

    tasks = [asyncio.create_task(guarded_check(url)) for url in urls]
    results: list[CheckResult] = []
    for completed, task in enumerate(asyncio.as_completed(tasks), start=1):
        results.append(await task)
        if completed % 100 == 0 or completed == len(tasks):
            print(f"Checked {completed:,}/{len(tasks):,} URLs")
    return sorted(results, key=lambda result: result.url)


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise MonitorError("required configuration is missing")
    return value


async def run_monitor() -> int:
    """Discover URLs, check them, store opaque state, and notify LINE."""
    sitemap_url = _required_env("SITEMAP_URL")
    allowed_domain = _required_env("ALLOWED_DOMAIN")
    line_token = _required_env("LINE_CHANNEL_ACCESS_TOKEN")
    line_user_id = _required_env("LINE_USER_ID")
    state_hmac_key = _required_env("STATE_HMAC_KEY")
    if len(state_hmac_key) < 32:
        raise MonitorError("state protection key is too short")

    concurrency = min(max(int(os.getenv("MONITOR_CONCURRENCY", "4")), 1), 8)
    requests_per_second = min(
        max(float(os.getenv("MONITOR_REQUESTS_PER_SECOND", "2")), 0.1),
        5.0,
    )
    state_path = Path(os.getenv("MONITOR_STATE_PATH", ".state/status.json"))
    guard = PublicHostGuard(allowed_domain)
    limiter = RateLimiter(requests_per_second)
    timeout = httpx.Timeout(connect=15, read=20, write=15, pool=15)
    limits = httpx.Limits(
        max_connections=max(concurrency, 4),
        max_keepalive_connections=max(concurrency, 4),
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        follow_redirects=False,
    ) as client:
        urls = await discover_urls(
            client,
            sitemap_url,
            guard=guard,
            limiter=limiter,
        )
        print(f"Discovered {len(urls):,} unique URLs")
        previous = load_previous_state(state_path)
        results = await _check_all_urls(
            client,
            urls,
            guard=guard,
            concurrency=concurrency,
            limiter=limiter,
        )
        changes = compute_changes(results, previous, hmac_key=state_hmac_key)
        save_state(results, path=state_path, hmac_key=state_hmac_key)

        counts = Counter(result.category for result in results)
        print(f"Result categories: {dict(sorted(counts.items()))}")
        should_notify = not previous or bool(changes.new_or_changed or changes.recovered)
        if should_notify:
            await send_line_message(
                client,
                access_token=line_token,
                user_id=line_user_id,
                message=build_notification(
                    total=len(results),
                    changes=changes,
                    initial_run=not previous,
                ),
            )
            print("Private notification sent")
        else:
            print("No status changes; duplicate notification suppressed")
    return 0


async def _notify_monitor_failure() -> None:
    token = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
    user_id = os.getenv("LINE_USER_ID", "")
    if not token or not user_id:
        return
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            await send_line_message(
                client,
                access_token=token,
                user_id=user_id,
                message="⚠️ Sitemap Monitor ทำงานไม่สำเร็จ กรุณาตรวจสอบระบบ",
            )
    except (httpx.HTTPError, MonitorError):
        print("Failure notification could not be sent", file=sys.stderr)


async def async_main() -> int:
    """CLI entry point with a best-effort private failure alert."""
    try:
        return await run_monitor()
    except (MonitorError, httpx.HTTPError, OSError, ValueError) as exc:
        if isinstance(exc, MonitorError):
            safe_reason = str(exc)
        elif isinstance(exc, httpx.HTTPError):
            safe_reason = "network request failed"
        elif isinstance(exc, OSError):
            safe_reason = "local state I/O failed"
        else:
            safe_reason = "numeric configuration is invalid"
        print(f"Monitor failed: {safe_reason}", file=sys.stderr)
        await _notify_monitor_failure()
        return 2


def main() -> int:
    """Run the async monitor from a synchronous entry point."""
    return asyncio.run(async_main())


if __name__ == "__main__":
    raise SystemExit(main())
