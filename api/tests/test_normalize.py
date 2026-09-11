"""Unit tests for entity normalization (Step 3c)."""

from curator.ingest.normalize import (
    is_ignorable_ip,
    is_machine_account,
    normalize_host,
    normalize_ip,
    normalize_path,
    normalize_process_uid,
    normalize_user,
)


def test_normalize_user():
    assert normalize_user("DMEVALS\\pbeesly") == "pbeesly"
    assert normalize_user("dschrute@DMEVALS.LOCAL") == "dschrute"
    assert normalize_user("dmevals.local\\mscott") == "mscott"
    assert normalize_user("DMEVALS\\wardog") == "wardog"
    assert normalize_user("UTICA$") == "utica$"
    assert normalize_user("DMEVALS\\UTICA$") == "utica$"
    assert normalize_user("-") is None
    assert normalize_user(None) is None


def test_is_machine_account():
    assert is_machine_account("UTICA$") is True
    assert is_machine_account("DMEVALS\\UTICA$") is True
    assert is_machine_account("pbeesly") is False
    assert is_machine_account("DMEVALS\\pbeesly") is False
    assert is_machine_account(None) is False


def test_normalize_host():
    assert normalize_host("UTICA.dmevals.local") == "UTICA"
    assert normalize_host("scranton.dmevals.local") == "SCRANTON"
    assert normalize_host("NEWYORK") == "NEWYORK"
    assert normalize_host("wec.internal.cloudapp.net") == "WEC"
    assert normalize_host(None) is None
    assert normalize_host("-") is None


def test_normalize_process_uid():
    assert (
        normalize_process_uid("{74328515-2C3C-5EAC-0000-00100D5D0B00}")
        == "74328515-2C3C-5EAC-0000-00100D5D0B00"
    )
    assert (
        normalize_process_uid("74328515-2c3c-5eac-0000-00100d5d0b00")
        == "74328515-2C3C-5EAC-0000-00100D5D0B00"
    )
    assert normalize_process_uid(None) is None


def test_normalize_path():
    assert (
        normalize_path(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\lsass.exe"
        )
        == "c:\\windows\\system32\\lsass.exe"
    )
    assert (
        normalize_path("C:\\Windows\\System32\\cmd.exe")
        == "c:\\windows\\system32\\cmd.exe"
    )
    assert normalize_path(None) is None


def test_normalize_and_filter_ip():
    assert normalize_ip("192.168.1.50") == "192.168.1.50"
    assert normalize_ip("10.0.1.4") == "10.0.1.4"
    assert normalize_ip("::ffff:10.0.1.4") == "10.0.1.4"

    # Excluded IPs
    assert is_ignorable_ip("0.0.0.0") is True
    assert is_ignorable_ip("127.0.0.1") is True
    assert is_ignorable_ip("::") is True
    assert is_ignorable_ip("::1") is True
    assert is_ignorable_ip("255.255.255.255") is True
    assert is_ignorable_ip("fe80::1") is True
    assert is_ignorable_ip("-") is True
    assert is_ignorable_ip(None) is True
    assert is_ignorable_ip("192.168.1.100") is False
