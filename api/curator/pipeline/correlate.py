"""Correlation stage: Union-Find clustering over security alerts (system_design.md §6.1).

Connects non-duplicate alerts on normalized entity matches:
- Same host within CORRELATE_HOST_WINDOW_SECONDS
- Same normalized user within CORRELATE_USER_WINDOW_SECONDS (machine accounts excluded)
- Process lineage / GUID within CORRELATE_PROCESS_WINDOW_SECONDS
- Shared non-ignorable IP within CORRELATE_IP_WINDOW_SECONDS
- Shared file path / hash within CORRELATE_FILE_WINDOW_SECONDS

All windows are named constants from config.py.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from curator.config import (
    CORRELATE_FILE_WINDOW_SECONDS,
    CORRELATE_HOST_WINDOW_SECONDS,
    CORRELATE_IP_WINDOW_SECONDS,
    CORRELATE_PROCESS_WINDOW_SECONDS,
    CORRELATE_USER_WINDOW_SECONDS,
    MACHINE_ACCOUNT_JOIN_SECONDS,
)
from curator.ingest.normalize import (
    is_correlating_user,
    is_ignorable_ip,
    is_machine_account,
)


class DisjointSet:
    """Union-Find with path compression and rank optimization."""

    def __init__(self) -> None:
        self.parent: dict[int, int] = {}
        self.rank: dict[int, int] = {}

    def find(self, item: int) -> int:
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: int, b: int) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a == root_b:
            return
        if self.rank[root_a] < self.rank[root_b]:
            self.parent[root_a] = root_b
        elif self.rank[root_a] > self.rank[root_b]:
            self.parent[root_b] = root_a
        else:
            self.parent[root_b] = root_a
            self.rank[root_a] += 1


@dataclass
class AlertItem:
    id: int
    rule_id: str
    severity: str
    ts: datetime
    host: str | None
    user_norm: str | None
    process_uid: str | None
    file_path: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    is_duplicate: bool = False
    canonical_id: int | None = None
    command_line: str | None = None


@dataclass
class IncidentCluster:
    incident_id: int | None
    alert_ids: list[int] = field(default_factory=list)
    alerts: list[AlertItem] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    raw_alert_count: int = 0
    event_count: int = 0


def correlate_alerts(
    alerts: list[AlertItem],
    host_window_s: int = CORRELATE_HOST_WINDOW_SECONDS,
    user_window_s: int = CORRELATE_USER_WINDOW_SECONDS,
    process_window_s: int = CORRELATE_PROCESS_WINDOW_SECONDS,
    ip_window_s: int = CORRELATE_IP_WINDOW_SECONDS,
    file_window_s: int = CORRELATE_FILE_WINDOW_SECONDS,
    machine_account_window_s: int = MACHINE_ACCOUNT_JOIN_SECONDS,
) -> list[IncidentCluster]:
    """Correlate alerts into incident clusters using Union-Find.

    Only unique (canonical) alerts participate in the graph joins.
    Duplicate alerts are attached to their canonical alert's cluster.
    """
    if not alerts:
        return []

    uf = DisjointSet()
    canonical_alerts = [a for a in alerts if not a.is_duplicate]
    canonical_by_id = {a.id: a for a in canonical_alerts}

    for a in canonical_alerts:
        uf.find(a.id)

    # Sort canonical alerts chronologically for sliding-window joins
    sorted_alerts = sorted(canonical_alerts, key=lambda a: a.ts)
    n = len(sorted_alerts)

    max_window = max(
        host_window_s,
        user_window_s,
        process_window_s,
        ip_window_s,
        file_window_s,
        machine_account_window_s,
    )

    for i in range(n):
        a = sorted_alerts[i]
        t_a = a.ts.timestamp()

        for j in range(i + 1, n):
            b = sorted_alerts[j]
            t_b = b.ts.timestamp()
            dt = t_b - t_a
            if dt > max_window:
                break

            matched = False

            # 1. Process UID match (strongest signal)
            if (
                a.process_uid
                and b.process_uid
                and a.process_uid == b.process_uid
                and dt <= process_window_s
            ):
                matched = True

            # 2. Same normalized user (excluding machine and service accounts per 3.2c)
            elif (
                a.user_norm
                and b.user_norm
                and a.user_norm == b.user_norm
                and is_correlating_user(a.user_norm)
                and dt <= user_window_s
            ):
                matched = True

            # 2b. Machine account matching own host (§9a: WinRM wsmprovhost under newyork$ on NEWYORK)
            elif (
                dt <= machine_account_window_s
                and a.host
                and b.host
                and a.host.split(".")[0].lower() == b.host.split(".")[0].lower()
                and (
                    (is_machine_account(a.user_norm) and (a.user_norm or "").rstrip("$").lower() == a.host.split(".")[0].lower() and a.rule_id == "CUR-021")
                    or (is_machine_account(b.user_norm) and (b.user_norm or "").rstrip("$").lower() == b.host.split(".")[0].lower() and b.rule_id == "CUR-021")
                )
            ):
                matched = True

            # 3. Shared IP (excluding loopback/internal collectors)
            elif dt <= ip_window_s:
                ips_a = {
                    ip for ip in (a.src_ip, a.dst_ip) if not is_ignorable_ip(ip)
                }
                ips_b = {
                    ip for ip in (b.src_ip, b.dst_ip) if not is_ignorable_ip(ip)
                }
                if ips_a and ips_b and (ips_a & ips_b):
                    matched = True

            # 4. Shared file path
            elif (
                a.file_path
                and b.file_path
                and a.file_path == b.file_path
                and dt <= file_window_s
            ):
                matched = True

            # 5. Same host proximity
            elif a.host and b.host and a.host == b.host and dt <= host_window_s:
                matched = True

            if matched:
                uf.union(a.id, b.id)

    # Group canonical alerts by root cluster
    clusters_map: dict[int, list[AlertItem]] = defaultdict(list)
    for a in canonical_alerts:
        root = uf.find(a.id)
        clusters_map[root].append(a)

    # Map canonical_id -> root for duplicates
    canon_to_root = {a.id: uf.find(a.id) for a in canonical_alerts}

    # Also attach duplicates to their canonical cluster
    for d in alerts:
        if d.is_duplicate and d.canonical_id in canon_to_root:
            root = canon_to_root[d.canonical_id]
            clusters_map[root].append(d)

    # Convert to IncidentCluster list
    clusters: list[IncidentCluster] = []
    for root, cluster_alerts in clusters_map.items():
        sorted_ca = sorted(cluster_alerts, key=lambda a: a.ts)
        hosts = sorted(
            list({a.host for a in sorted_ca if a.host and a.host != "-"})
        )
        users = sorted(
            list(
                {
                    a.user_norm
                    for a in sorted_ca
                    if a.user_norm and not is_machine_account(a.user_norm)
                }
            )
        )
        raw_count = len(cluster_alerts)

        cluster = IncidentCluster(
            incident_id=None,
            alert_ids=[a.id for a in sorted_ca],
            alerts=sorted_ca,
            first_seen=sorted_ca[0].ts,
            last_seen=sorted_ca[-1].ts,
            hosts=hosts,
            users=users,
            raw_alert_count=raw_count,
            event_count=raw_count,  # Will be expanded by bounded evidence set in runner
        )
        clusters.append(cluster)

    # Sort clusters chronologically
    clusters.sort(key=lambda c: c.first_seen)
    return clusters
