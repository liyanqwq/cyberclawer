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

AVD sync uses browser fallback by default. HKCERT, zero-day.cz, and GovCERT.HK
are server-rendered HTML and do not use browser fallback. CVE sync calls the NVD
API directly. Cisco PSIRT sync calls the OpenVuln API directly.

## MongoDB Layout

All scrapers use one MongoDB database, with one collection per scraper.

| Scraper folder | MongoDB collection | Ingest CLI |
| --- | --- | --- |
| `avd_scraper/scrapers/avd/` | `vulnerabilities` | `python scrape.py tui` / `python scrape.py sync <hours>` |
| `avd_scraper/scrapers/hkcert/` | `hkcert` | same |
| `avd_scraper/scrapers/cve/` | `cve` | same |
| `avd_scraper/scrapers/cisco/` | `cisco` | same |
| `avd_scraper/scrapers/zeroday/` | `zeroday` | same |
| `avd_scraper/scrapers/govcert/` | `govcert` | same |

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
cisco = "cisco"
zeroday = "zeroday"
govcert = "govcert"
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
zero-day.cz detail fields include `advisory`, `vulnerable_component`,
`cvss_v3_vector`, `cwe`, `description`, `patch_status`, and `reference_links`.
GovCERT.HK detail fields include `alert_code`, `alert_type`, `published_date`,
`description`, `affected_systems`, `impact`, `recommendation`,
`more_information_links`, `tags`, `cve_ids`, and `raw_sections`.
Cisco OpenVuln detail fields include `advisory_id`, `advisory_title`, `sir`,
`first_published`, `last_updated`, `cve_ids`, `bug_ids`, `cwe`,
`cvss_base_score`, `product_names`, `publication_url`, `summary`, and `raw`.
CVEs from AVD/HKCERT/zero-day.cz/GovCERT.HK/Cisco details are stored as top-level
`cve_code` using the normalized `YYYY-NNNN` form. Non-CVE bulletins use
`cve_code = null`.

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
  cisco/
  cve/
  govcert/
  hkcert/
  zeroday/
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
zero-day.cz records are scraped from [Zero-day Vulnerability Database](https://www.zero-day.cz/database/);
Mongo sync treats that feed as newest-first and stops once it reaches a stored
record to avoid historical backfill.
GovCERT.HK security alerts are scraped from [Security Alerts](https://www.govcert.gov.hk/en/alerts.php)
and use the same newest-first sync stop behavior.

The CVE scraper uses the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities).
Set `NVD_API_KEY` for production syncs. Without a key, NVD's public rate limit is
much lower; the CVE provider defaults to a six-second request delay and uses
120-day modified-date windows with NVD's 2,000-result page size. This product
uses data from the NVD API but is not endorsed or certified by the NVD.

The Cisco scraper uses the [PSIRT OpenVuln API](https://developer.cisco.com/docs/psirt/).
Cisco requires an access token for every OpenVuln API request. Set
`CISCO_OPENVULN_TOKEN` to use an existing Bearer token, or set
`CISCO_OPENVULN_CLIENT_ID` and `CISCO_OPENVULN_CLIENT_SECRET` so the scraper can
obtain and cache an OAuth client-credentials token from Cisco. The shorter
`CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET` names are also accepted.
# cyberclawer
