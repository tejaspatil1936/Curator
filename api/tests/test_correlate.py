"""Unit tests for alert correlation and Union-Find (Step 3d)."""

from datetime import UTC, datetime

from curator.pipeline.correlate import AlertItem, DisjointSet, correlate_alerts


def test_disjoint_set():
    ds = DisjointSet()
    assert ds.find(1) == 1
    assert ds.find(2) == 2

    ds.union(1, 2)
    assert ds.find(1) == ds.find(2)

    ds.union(2, 3)
    assert ds.find(1) == ds.find(3)


def test_correlate_alerts_process_and_host():
    t0 = datetime(2020, 5, 2, 3, 0, 0, tzinfo=UTC)
    t1 = datetime(2020, 5, 2, 3, 5, 0, tzinfo=UTC)
    t2 = datetime(2020, 5, 2, 3, 10, 0, tzinfo=UTC)
    t_far = datetime(2020, 5, 2, 7, 0, 0, tzinfo=UTC)  # 4 hours later

    a1 = AlertItem(
        id=1,
        rule_id="CUR-001",
        severity="critical",
        ts=t0,
        host="UTICA",
        user_norm="pbeesly",
        process_uid="GUID-X",
    )
    a2 = AlertItem(
        id=2,
        rule_id="CUR-003",
        severity="high",
        ts=t1,
        host="UTICA",
        user_norm="pbeesly",
        process_uid="GUID-X",
    )
    a3 = AlertItem(
        id=3,
        rule_id="CUR-005",
        severity="critical",
        ts=t2,
        host="UTICA",
        user_norm="pbeesly",
        process_uid="GUID-Y",
    )
    a4 = AlertItem(
        id=4,
        rule_id="CUR-015",
        severity="low",
        ts=t_far,
        host="SCRANTON",
        user_norm="dschrute",
        process_uid="GUID-Z",
    )

    clusters = correlate_alerts([a1, a2, a3, a4], host_window_s=600)

    # a1, a2, a3 should be clustered into incident 1; a4 into incident 2
    assert len(clusters) == 2
    c1 = next(c for c in clusters if 1 in c.alert_ids)
    c2 = next(c for c in clusters if 4 in c.alert_ids)

    assert set(c1.alert_ids) == {1, 2, 3}
    assert c1.hosts == ["UTICA"]
    assert c1.users == ["pbeesly"]

    assert set(c2.alert_ids) == {4}
    assert c2.hosts == ["SCRANTON"]
    assert c2.users == ["dschrute"]
