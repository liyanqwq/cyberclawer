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
not use browser fallback. CVE sync calls the NVD API directly.

## MongoDB Layout

All scrapers use one MongoDB database, with one collection per scraper.

| Scraper folder | MongoDB collection | Ingest CLI |
| --- | --- | --- |
| `avd_scraper/scrapers/avd/` | `vulnerabilities` | `python scrape.py tui` / `python scrape.py sync <hours>` |
| `avd_scraper/scrapers/hkcert/` | `hkcert` | same |
| `avd_scraper/scrapers/cve/` | `cve` | same |

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
cve = "cve"
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

Each document is keyed by unique lowercase scraper `type` + provider-native
`code`, with `_id` such as `avd:2026-42945`,
`hkcert:suse-linux-kernel-multiple-vulnerabilities_20260601`, or
`cve:2024-3094`. Common fields live at the top level:

- `type`, `code`, `cve_code`, `title`, `disclosure_date`, `status`
- `source`
- `details`

Provider-specific fields live under `details.<provider>`.

HKCERT detail fields include `intro`, `note`, `impact`, `systems_affected`,
`solutions`, `solution_links`, `vulnerability_identifiers`, `bulletin_source`,
`related_links`, `risk_level`, `release_date`, `last_update_date`, and `views`.
CVEs from AVD/HKCERT details are stored as top-level `cve_code` using the
normalized `YYYY-NNNN` form. Non-CVE bulletins use `cve_code = null`.

CVE master records use `type = "cve"`, `code = "YYYY-NNNN"`, `cve_code = null`,
and store the NVD payload under `details.cve`, including a `raw` copy for
forward compatibility.

Legacy documents that still have uppercase `type` or `cross_refs` should be
migrated before relying on filters:

```bash
PYTHONPATH=. python scripts/migrate_schema_v2.py
PYTHONPATH=. python scripts/migrate_schema_v2.py --apply
```

## Development

Scrapers live under:

```text
avd_scraper/scrapers/
  __init__.py
  avd/
  cve/
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

The CVE scraper uses the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).
Set `NVD_API_KEY` for production syncs. Without a key, NVD's public rate limit is
much lower; the CVE provider defaults to a six-second request delay and uses
120-day modified-date windows with NVD's 2,000-result page size. This product
uses data from the NVD API but is not endorsed or certified by the NVD.
