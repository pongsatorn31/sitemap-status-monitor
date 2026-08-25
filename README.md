# Sitemap Status Monitor

A small external monitor that reads an XML sitemap, checks each same-domain URL,
and sends private LINE notifications when availability changes. It is designed
for scheduled GitHub Actions runs with low concurrency and rate limiting.

## Privacy model

- The target sitemap and domain are repository secrets, not source code.
- Public logs contain counts and categories, never target URLs.
- No URL report is uploaded as an artifact.
- Cached state contains only HMAC-SHA256 identifiers, not recoverable URLs.
- Detailed failed and recovered URLs are sent only through LINE.

Repository ownership and workflow timing remain public. This design hides the
configured target from ordinary repository visitors; it does not promise
anonymity against all forms of traffic analysis.

## Required repository secrets

| Secret | Purpose |
| --- | --- |
| `SITEMAP_URL` | HTTPS URL of the root sitemap |
| `ALLOWED_DOMAIN` | Root domain allowed for sitemap and page requests |
| `LINE_CHANNEL_ACCESS_TOKEN` | LINE Messaging API channel access token |
| `LINE_USER_ID` | LINE recipient user ID |
| `STATE_HMAC_KEY` | Random string of at least 32 characters |

The workflow runs every four hours. It follows redirects only when every hop
remains on same-domain HTTPS, resolves exclusively to public IP addresses, and
uses port 443. XML entities are disabled and sitemap sizes are bounded.

## Local verification

```shell
python -m pip install -e ".[dev]"
pytest --cov=monitor --cov-report=term-missing
ruff check .
mypy monitor.py
```

Never place real target URLs or credentials in source files, commits, issues,
workflow names, logs, or public artifacts.

