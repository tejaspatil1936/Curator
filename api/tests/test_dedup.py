"""Unit tests for alert deduplication (Step 3d)."""

from datetime import UTC, datetime

from curator.pipeline.dedup import (
    AlertRecord,
    compute_exact_dedup_key,
    deduplicate_alerts,
    minhash_jaccard,
    tokenize_command_line,
)


def test_exact_dedup_key():
    ts1 = datetime(2020, 5, 2, 3, 0, 15, tzinfo=UTC)
    ts2 = datetime(2020, 5, 2, 3, 0, 45, tzinfo=UTC)  # Same 60s bucket
    ts3 = datetime(2020, 5, 2, 3, 1, 15, tzinfo=UTC)  # Next bucket

    k1 = compute_exact_dedup_key("CUR-001", "UTICA", "pbeesly", "GUID-1", ts1)
    k2 = compute_exact_dedup_key("CUR-001", "UTICA", "pbeesly", "GUID-1", ts2)
    k3 = compute_exact_dedup_key("CUR-001", "UTICA", "pbeesly", "GUID-1", ts3)

    assert k1 == k2
    assert k1 != k3


def test_deduplicate_alerts_exact():
    t0 = datetime(2020, 5, 2, 3, 0, 10, tzinfo=UTC)
    t1 = datetime(2020, 5, 2, 3, 0, 30, tzinfo=UTC)

    a1 = AlertRecord(
        id=1,
        rule_id="CUR-003",
        host="UTICA",
        user_norm="pbeesly",
        process_uid="GUID-A",
        ts=t0,
        command_line="powershell.exe -enc AAAA",
    )
    a2 = AlertRecord(
        id=2,
        rule_id="CUR-003",
        host="UTICA",
        user_norm="pbeesly",
        process_uid="GUID-A",
        ts=t1,
        command_line="powershell.exe -enc AAAA",
    )

    result, dups = deduplicate_alerts([a1, a2])
    assert dups == 1
    assert result[0].is_duplicate is False
    assert result[1].is_duplicate is True
    assert result[1].canonical_id == 1


def test_deduplicate_alerts_minhash():
    t0 = datetime(2020, 5, 2, 3, 0, 0, tzinfo=UTC)
    t1 = datetime(2020, 5, 2, 3, 2, 0, tzinfo=UTC)  # 2 minutes later

    # Almost identical command line with minor parameter change
    cmd1 = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\script.ps1 -Target 10.0.1.5 -Port 8080 -Verbose"
    cmd2 = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\script.ps1 -Target 10.0.1.6 -Port 8080 -Verbose"

    a1 = AlertRecord(
        id=10,
        rule_id="CUR-003",
        host="SCRANTON",
        user_norm="dschrute",
        process_uid="GUID-1",
        ts=t0,
        command_line=cmd1,
    )
    a2 = AlertRecord(
        id=11,
        rule_id="CUR-003",
        host="SCRANTON",
        user_norm="dschrute",
        process_uid="GUID-2",  # Different process UID, but same rule, host, user
        ts=t1,
        command_line=cmd2,
    )

    result, dups = deduplicate_alerts([a1, a2])
    assert dups == 1
    assert result[1].is_duplicate is True
    assert result[1].canonical_id == 10
