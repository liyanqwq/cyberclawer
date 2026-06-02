# Vulnerability Bulletin Scrapers

Terminal scrapers ingest vulnerability bulletins into MongoDB, and `mongodb-filter`
browses, reads, and exports filtered records from the same database. There is no web UI.

## Install

Use Python 3.11 or newer.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For Aliyun AVD environments that return a JavaScript signature challenge, install
the optional browser fallback:

```bash
pip install -e '.[browser]'
```

AVD sync uses browser fallback by default. HKCERT is server-rendered HTML and does
not use browser fallback.

## MongoDB Layout

All scrapers use one MongoDB database, with one collection per scraper.

| Scraper folder | MongoDB collection | Ingest CLI |
| --- | --- | --- |
| `avd_scraper/scrapers/avd/` | `vulnerabilities` | `python scrape.py tui` / `python scrape.py sync <hours>` |
| `avd_scraper/scrapers/hkcert/` | `hkcert` | same |

`mongodb.toml`:

```toml
[mongodb]
uri = "mongodb://localhost:27017"
database = "avd"
collection = "vulnerabilities"
conflict = "prompt"

[mongodb.collections]
avd = "vulnerabilities"
hkcert = "hkcert"
```

Precedence for connection settings is CLI flags, environment variables
(`AVD_MONGO_URI`, `AVD_MONGO_DB`, `AVD_MONGO_COLLECTION`), `mongodb.toml`, then
built-in defaults. The `[mongodb.collections]` table maps each scraper to its
collection inside database `avd`.

## Usage

Interactive scrape, choosing scraper and amount:

```bash
python scrape.py tui
```

Periodic sync for every registered scraper, in a foreground loop:

```bash
python scrape.py sync 3
```

Filter and browse records in MongoDB:

```bash
mongodb-filter
mongodb-filter --mongo-config mongodb.toml
mongodb-filter --mongo-collection hkcert
```

Without `--mongo-collection`, `mongodb-filter` opens a collection picker using
`[mongodb.collections]`. Filtering stays in the terminal: checkbox fields,
text-contains fields, paged result browsing, record read (Enter on a result), and
JSON export (`e` in the TUI — prompts for a filename under `data/`; if the file
already exists, choose replace or rename).

## Document Shape

Each document is keyed by unique `type` + `code`, with `_id` such as
`AVD:2026-42945` or `HKCERT:suse-linux-kernel-multiple-vulnerabilities_20260601`.
Common fields live at the top level:

- `type`, `code`, `title`, `disclosure_date`, `status`
- `source`
- `cross_refs`
- `details`

Provider-specific fields live under `details.<provider>`.

HKCERT detail fields include `intro`, `note`, `impact`, `systems_affected`,
`solutions`, `solution_links`, `vulnerability_identifiers`, `bulletin_source`,
`related_links`, `risk_level`, `release_date`, `last_update_date`, and `views`.
CVEs from HKCERT `vulnerability_identifiers` are also stored in top-level
`cross_refs` as `{ "type": "CVE", "code": "YYYY-NNNN" }`.

## Development

Scrapers live under:

```text
avd_scraper/scrapers/
  __init__.py
  avd/
  hkcert/
```

Each scraper owns its URL config, provider, filter fields, and parsers.

Run tests:

```bash
PYTHONPATH=. uv run pytest -q
```

## Operational Notes

These scrapers are for personal or research use. Aliyun AVD has no public API for
this catalog, so keep conservative request pacing and stop if the site returns
rate-limit or challenge responses persistently. HKCERT bulletin pages are public,
server-rendered HTML at [Security Bulletin](https://www.hkcert.org/security-bulletin).
