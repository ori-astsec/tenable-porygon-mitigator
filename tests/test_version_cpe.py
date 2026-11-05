import pytest

from porygon_mitigator.match.cpe import parse_cpe, products_match
from porygon_mitigator.match.version import compare_versions, in_range, upstream_version


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("8.9p1", "8.9", 1),
        ("8.9p1", "9.8", -1),
        ("2.0", "2.0rc1", 1),
        ("2.0rc1", "2.0beta2", 1),
        ("2.14.1", "2.15.0", -1),
        ("2.0", "2.0.0", 0),
        ("10.2.9-h1", "10.2.9", 1),
        ("10.2.9-h1", "10.2.10", -1),
        ("13.1-48.47", "13.1-49.15", -1),
        ("1:8.9p1", "9.0", 1),  # epoch wins
        ("10.0.19044.1706", "10.0.19044.1766", -1),
        ("1.0.1", "1.0rc1", 1),
    ],
)
def test_compare_versions(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


def test_upstream_version_strips_epoch_and_revision() -> None:
    assert upstream_version("1:8.9p1-3ubuntu0.10") == "8.9p1"
    assert upstream_version("2.14.1-1.el8") == "2.14.1"
    assert upstream_version("8.9p1") == "8.9p1"


def test_in_range() -> None:
    assert in_range("8.9p1", start_including="8.5", end_excluding="9.8") is True
    assert in_range("9.8p1", start_including="8.5", end_excluding="9.8") is False
    assert in_range("2.15.0", end_excluding="2.15.0") is False
    assert in_range("1.0", exact=["1.0", "1.1"]) is True
    assert in_range("1.0") is None


def test_parse_cpe_23_joins_update() -> None:
    cpe = parse_cpe("cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*")
    assert cpe is not None
    assert (cpe.vendor, cpe.product, cpe.full_version) == ("openbsd", "openssh", "8.9p1")


def test_parse_cpe_22() -> None:
    cpe = parse_cpe("cpe:/a:apache:log4j:2.14.1")
    assert cpe is not None and cpe.key == "apache:log4j" and cpe.version == "2.14.1"
    assert parse_cpe("not a cpe") is None


def test_products_match() -> None:
    assert products_match("windows_10_21h2", "Windows 10 21H2") == "exact"
    assert products_match("windows_11", "windows_11_21h2") == "prefix"
    assert products_match("office", "microsoft_office_professional_plus_2019") == "contains"
    assert products_match("office", "officejet") is None
