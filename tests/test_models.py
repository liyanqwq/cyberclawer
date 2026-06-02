import pytest

from avd_scraper.models import ListEntry, VulnerabilityId


def test_vulnerability_id_parses_type_and_code() -> None:
    identity = VulnerabilityId.parse("CVE-2026-42945")

    assert identity.type == "CVE"
    assert identity.code == "2026-42945"
    assert identity.key == "CVE:2026-42945"
    assert identity.display == "CVE-2026-42945"


def test_vulnerability_id_rejects_malformed_value() -> None:
    with pytest.raises(ValueError):
        VulnerabilityId.parse("2026-42945")


def test_list_entry_builds_cross_refs_from_vulnerability_identifiers() -> None:
    entry = ListEntry(
        identity=VulnerabilityId(type="HKCERT", code="android-multiple-vulnerabilities_20250601"),
        title="Android Multiple Vulnerabilities",
        vuln_type=None,
        disclosure_date="1 Jun 2025",
        status="NEW",
        provider="hkcert",
        source_url="https://www.hkcert.org/security-bulletin",
    )

    record = entry.to_record(
        {
            "vulnerability_identifiers": [
                {"cve_id": "CVE-2025-48595"},
                {"cve_id": "CVE-2025-48595"},
            ]
        },
        detail_url="https://www.hkcert.org/security-bulletin/android-multiple-vulnerabilities_20250601",
    )

    assert record["cross_refs"] == [{"type": "CVE", "code": "2025-48595"}]
    assert "hkcert" in record["details"]
