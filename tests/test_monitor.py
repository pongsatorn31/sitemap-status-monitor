from __future__ import annotations

import asyncio
import gzip
import json
from pathlib import Path

import httpx
import pytest

import monitor as monitor_module
from monitor import (
    CheckResult,
    MonitorError,
    PublicHostGuard,
    RateLimiter,
    UnsafeUrlError,
    async_main,
    build_notification,
    check_url,
    classify_result,
    compute_changes,
    discover_urls,
    load_previous_state,
    parse_sitemap,
    save_state,
    send_line_message,
)

URLSET = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.example.com/one</loc></url>
  <url><loc>https://www.example.com/two</loc></url>
</urlset>
"""

INDEX = b"""<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://www.example.com/products.xml</loc></sitemap>
  <sitemap><loc>https://foreign.invalid/private.xml</loc></sitemap>
</sitemapindex>
"""


async def public_resolver(_: str) -> set[str]:
    return {"8.8.8.8"}


async def private_resolver(_: str) -> set[str]:
    return {"127.0.0.1"}


def test_guard_requires_same_domain_https_default_port_and_public_dns() -> None:
    guard = PublicHostGuard("example.com", resolver=public_resolver)
    asyncio.run(guard.validate("https://www.example.com/page"))

    for unsafe in (
        "http://www.example.com/page",
        "https://evil-example.com/page",
        "https://user@example.com/page",
        "https://www.example.com:8443/page",
    ):
        with pytest.raises(UnsafeUrlError):
            asyncio.run(guard.validate(unsafe))

    private_guard = PublicHostGuard("example.com", resolver=private_resolver)
    with pytest.raises(UnsafeUrlError, match="public address"):
        asyncio.run(private_guard.validate("https://www.example.com/page"))


def test_parse_sitemap_and_bound_gzip_expansion() -> None:
    document = parse_sitemap(URLSET, max_bytes=1024)
    assert document.page_urls == (
        "https://www.example.com/one",
        "https://www.example.com/two",
    )

    bomb = gzip.compress(b"<urlset>" + b" " * 10_000 + b"</urlset>")
    with pytest.raises(MonitorError, match="decompressed size limit"):
        parse_sitemap(bomb, max_bytes=512)


def test_parse_sitemap_rejects_entities_and_invalid_xml() -> None:
    entity_xml = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><urlset>&e;</urlset>'
    with pytest.raises(MonitorError, match="unsafe or invalid XML"):
        parse_sitemap(entity_xml)

    with pytest.raises(MonitorError, match="unsafe or invalid XML"):
        parse_sitemap(b"<urlset>")


def test_discovery_follows_only_validated_redirects_and_hides_foreign_urls() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        responses = {
            "https://example.com/start.xml": httpx.Response(
                302,
                headers={"Location": "https://www.example.com/index.xml"},
            ),
            "https://www.example.com/index.xml": httpx.Response(200, content=INDEX),
            "https://www.example.com/products.xml": httpx.Response(200, content=URLSET),
        }
        return responses.get(str(request.url), httpx.Response(404))

    async def run() -> list[str]:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await discover_urls(client, "https://example.com/start.xml", guard=guard)

    assert asyncio.run(run()) == [
        "https://www.example.com/one",
        "https://www.example.com/two",
    ]


def test_redirect_to_private_or_foreign_target_is_rejected() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://127.0.0.1/admin"})

    async def run() -> None:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await discover_urls(client, "https://example.com/start.xml", guard=guard)

    with pytest.raises(MonitorError, match="root sitemap could not be read"):
        asyncio.run(run())


def test_check_url_retries_failure_and_does_not_log_url(capsys: pytest.CaptureFixture[str]) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503 if calls == 1 else 200, content=b"ok")

    async def run() -> CheckResult:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await check_url(
                client,
                "https://www.example.com/secret-path",
                guard=guard,
                retry_delays=(0,),
            )

    result = asyncio.run(run())
    assert result.category == "ok"
    assert result.attempts == 2
    assert "secret-path" not in capsys.readouterr().out


def test_hmac_state_contains_no_urls_and_supports_changes(tmp_path: Path) -> None:
    key = "test-state-key-with-enough-randomness"
    first = [
        CheckResult("https://example.com/a", 404, "not_found", 10, 1),
        CheckResult("https://example.com/b", 200, "ok", 5, 1),
    ]
    path = tmp_path / "state.json"
    save_state(first, path=path, hmac_key=key)

    raw = path.read_text(encoding="utf-8")
    assert "example.com" not in raw
    previous = load_previous_state(path)
    assert len(previous) == 2

    second = [
        CheckResult("https://example.com/a", 200, "ok", 7, 1),
        CheckResult("https://example.com/b", 503, "server_error", 8, 1),
    ]
    changes = compute_changes(second, previous, hmac_key=key)
    assert changes.recovered == ("https://example.com/a",)
    assert [item.url for item in changes.new_or_changed] == ["https://example.com/b"]


def test_notification_has_private_details_but_no_public_run_link() -> None:
    failure = CheckResult("https://example.com/private", 404, "not_found", 10, 1)
    changes = compute_changes([failure], {}, hmac_key="key")
    message = build_notification(total=1, changes=changes, initial_run=True)
    assert "https://example.com/private" in message
    assert "github.com" not in message
    assert len(message) <= 5_000


def test_line_error_does_not_include_response_body() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="sensitive upstream detail")

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await send_line_message(
                client,
                access_token="fake-token",
                user_id="U" + "1" * 32,
                message="test",
            )

    with pytest.raises(MonitorError) as exc_info:
        asyncio.run(run())
    assert "HTTP 401" in str(exc_info.value)
    assert "sensitive" not in str(exc_info.value)


def test_load_corrupt_state_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps(["not", "a", "mapping"]), encoding="utf-8")
    assert load_previous_state(path) == {}


@pytest.mark.parametrize(
    ("status", "error", "category"),
    [
        (200, None, "ok"),
        (399, None, "ok"),
        (404, None, "not_found"),
        (410, None, "not_found"),
        (403, None, "blocked"),
        (429, None, "rate_limited"),
        (503, None, "server_error"),
        (418, None, "http_error"),
        (None, "timeout", "timeout"),
        (None, None, "network_error"),
    ],
)
def test_classify_result(status: int | None, error: str | None, category: str) -> None:
    assert classify_result(status, error) == category


def test_parse_index_invalid_gzip_unknown_root_and_compressed_limit() -> None:
    parsed = parse_sitemap(INDEX)
    assert parsed.child_sitemaps == (
        "https://www.example.com/products.xml",
        "https://foreign.invalid/private.xml",
    )

    with pytest.raises(MonitorError, match="gzip is invalid"):
        parse_sitemap(b"\x1f\x8bnot-gzip")
    with pytest.raises(MonitorError, match="unsupported root"):
        parse_sitemap(b"<rss />")
    with pytest.raises(MonitorError, match="compressed size limit"):
        parse_sitemap(b"x" * 11, max_bytes=10)


def test_guard_rejects_empty_domain_empty_dns_and_invalid_dns() -> None:
    with pytest.raises(ValueError):
        PublicHostGuard("bad/domain")

    async def empty(_: str) -> set[str]:
        return set()

    async def invalid(_: str) -> set[str]:
        return {"not-an-ip"}

    with pytest.raises(UnsafeUrlError, match="no address"):
        asyncio.run(PublicHostGuard("example.com", resolver=empty).validate("https://example.com"))
    with pytest.raises(UnsafeUrlError, match="invalid address"):
        asyncio.run(
            PublicHostGuard("example.com", resolver=invalid).validate("https://example.com")
        )


def test_discovery_skips_broken_child_and_rejects_empty_root() -> None:
    index = b"""<sitemapindex><sitemap><loc>https://example.com/missing.xml</loc></sitemap></sitemapindex>"""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("index.xml"):
            return httpx.Response(200, content=index)
        return httpx.Response(404)

    async def run() -> list[str]:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await discover_urls(client, "https://example.com/index.xml", guard=guard)

    assert asyncio.run(run()) == ["https://example.com/missing.xml"]

    async def empty_run() -> None:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"<urlset/>"))
        async with httpx.AsyncClient(transport=transport) as client:
            await discover_urls(client, "https://example.com/index.xml", guard=guard)

    with pytest.raises(MonitorError, match="no allowed page URLs"):
        asyncio.run(empty_run())


def test_check_url_handles_timeout_and_unsafe_redirect() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    async def timeout_run() -> CheckResult:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        async with httpx.AsyncClient(transport=httpx.MockTransport(timeout_handler)) as client:
            return await check_url(
                client,
                "https://example.com/slow",
                guard=guard,
                retry_delays=(0,),
            )

    timeout_result = asyncio.run(timeout_run())
    assert timeout_result.category == "timeout"
    assert timeout_result.attempts == 2

    async def redirect_run() -> CheckResult:
        guard = PublicHostGuard("example.com", resolver=public_resolver)
        transport = httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"Location": "http://example.com/private"})
        )
        async with httpx.AsyncClient(transport=transport) as client:
            return await check_url(client, "https://example.com/start", guard=guard)

    assert asyncio.run(redirect_run()).category == "unsafe_redirect"


def test_rate_limiter_disabled_returns_immediately() -> None:
    asyncio.run(RateLimiter(0).wait())


def test_state_filters_invalid_entries_and_notification_lists_recovery(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps({"version": 1, "entries": {"short": "ok", "a" * 64: 123}}),
        encoding="utf-8",
    )
    assert load_previous_state(state_path) == {}

    current = [CheckResult("https://example.com/recovered", 200, "ok", 1, 1)]
    key = "state-key"
    previous_path = tmp_path / "previous.json"
    save_state(
        [CheckResult("https://example.com/recovered", 503, "server_error", 1, 1)],
        path=previous_path,
        hmac_key=key,
    )
    changes = compute_changes(current, load_previous_state(previous_path), hmac_key=key)
    message = build_notification(total=1, changes=changes, initial_run=False)
    assert "กลับมาปกติ" in message
    assert "https://example.com/recovered" in message


def test_send_line_success() -> None:
    async def run() -> None:
        transport = httpx.MockTransport(lambda _: httpx.Response(200))
        async with httpx.AsyncClient(transport=transport) as client:
            await send_line_message(client, access_token="token", user_id="U1", message="ok")

    asyncio.run(run())


def test_run_monitor_is_private_and_deduplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    messages: list[str] = []
    original_client = httpx.AsyncClient

    async def resolve(_: str) -> set[str]:
        return {"8.8.8.8"}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com/sitemap.xml":
            return httpx.Response(200, content=URLSET)
        if url in {"https://www.example.com/one", "https://www.example.com/two"}:
            return httpx.Response(200, content=b"ok")
        if url == monitor_module.LINE_PUSH_URL:
            messages.append(json.loads(request.content)["messages"][0]["text"])
            return httpx.Response(200)
        return httpx.Response(404)

    def client_factory(**kwargs: object) -> httpx.AsyncClient:
        supported = {
            key: value
            for key, value in kwargs.items()
            if key in {"timeout", "limits", "headers", "follow_redirects"}
        }
        return original_client(transport=httpx.MockTransport(handler), **supported)

    monkeypatch.setattr(monitor_module, "_resolve_host", resolve)
    monkeypatch.setattr(monitor_module.httpx, "AsyncClient", client_factory)
    monkeypatch.setenv("SITEMAP_URL", "https://example.com/sitemap.xml")
    monkeypatch.setenv("ALLOWED_DOMAIN", "example.com")
    monkeypatch.setenv("LINE_CHANNEL_ACCESS_TOKEN", "fake")
    monkeypatch.setenv("LINE_USER_ID", "U" + "1" * 32)
    monkeypatch.setenv("STATE_HMAC_KEY", "x" * 32)
    monkeypatch.setenv("MONITOR_REQUESTS_PER_SECOND", "5")
    monkeypatch.setenv("MONITOR_STATE_PATH", str(tmp_path / "state.json"))

    assert asyncio.run(monitor_module.run_monitor()) == 0
    assert asyncio.run(monitor_module.run_monitor()) == 0
    assert len(messages) == 1
    assert "example.com" not in capsys.readouterr().out


def test_async_main_returns_failure_without_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    notified = False

    async def fail() -> int:
        raise MonitorError("private detail")

    async def notify() -> None:
        nonlocal notified
        notified = True

    monkeypatch.setattr(monitor_module, "run_monitor", fail)
    monkeypatch.setattr(monitor_module, "_notify_monitor_failure", notify)
    assert asyncio.run(async_main()) == 2
    assert notified
    assert "private detail" in capsys.readouterr().err
