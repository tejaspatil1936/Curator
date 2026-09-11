"""Entity and graph edge extraction (system_design.md §5.3 & §6.1).

Extracts:
- Entities: host, user, ip, process, file, hash
- Edges: executed, connected_to, authenticated_as, wrote, spawned
Tracks first_seen, last_seen, and event_ids per entity and edge.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from curator.ingest.normalize import (
    is_ignorable_ip,
    is_machine_account,
    normalize_host,
    normalize_ip,
    normalize_path,
    normalize_user,
)


def extract_entities_and_edges(
    incident_id: int,
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract entities and relationship edges from an incident's event set."""
    # (kind, value) -> dict(first_seen, last_seen, set of event_ids)
    entity_map: dict[tuple[str, str], dict[str, Any]] = {}

    # (src_key, dst_key, relation) -> set of event_ids
    edge_map: dict[tuple[tuple[str, str], tuple[str, str], str], set[int]] = (
        defaultdict(set)
    )

    for ev in events:
        eid = ev["id"]
        ts = ev["ts"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))

        ocsf = ev.get("ocsf") or {}
        unmapped = ocsf.get("unmapped") or {}

        host = normalize_host(
            ev.get("host")
            or (ocsf.get("device") or {}).get("hostname")
            or unmapped.get("Hostname")
        )
        user = normalize_user(
            ev.get("user_name")
            or (ocsf.get("actor", {}).get("user") or {}).get("name")
            or unmapped.get("User")
            or unmapped.get("SubjectUserName")
        )
        proc = normalize_path(
            ev.get("process_name")
            or (ocsf.get("process", {}).get("file") or {}).get("path")
            or unmapped.get("Image")
            or unmapped.get("NewProcessName")
        )
        parent = normalize_path(
            ev.get("parent_process")
            or (
                ocsf.get("process", {}).get("parent_process", {}).get("file")
                or {}
            ).get("path")
            or unmapped.get("ParentImage")
        )
        file_path = normalize_path(
            ev.get("file_path")
            or (ocsf.get("file") or {}).get("path")
            or unmapped.get("TargetFilename")
        )
        dst_ip = normalize_ip(
            ev.get("dst_ip") or (ocsf.get("dst_endpoint") or {}).get("ip")
        )
        src_ip = normalize_ip(
            ev.get("src_ip") or (ocsf.get("src_endpoint") or {}).get("ip")
        )

        def record_entity(kind: str, val: str | None) -> tuple[str, str] | None:
            if not val or val == "-":
                return None
            key = (kind, val)
            if key not in entity_map:
                entity_map[key] = {
                    "kind": kind,
                    "value": val,
                    "first_seen": ts,
                    "last_seen": ts,
                    "event_ids": {eid},
                }
            else:
                entry = entity_map[key]
                if ts < entry["first_seen"]:
                    entry["first_seen"] = ts
                if ts > entry["last_seen"]:
                    entry["last_seen"] = ts
                entry["event_ids"].add(eid)
            return key

        h_key = record_entity("host", host)
        u_key = record_entity("user", user)
        p_key = record_entity("process", proc)
        par_key = record_entity("process", parent)
        f_key = record_entity("file", file_path)
        dip_key = record_entity("ip", dst_ip)
        sip_key = record_entity("ip", src_ip)

        # Edges
        # 1. user executed process
        if u_key and p_key:
            edge_map[(u_key, p_key, "executed")].add(eid)

        # 2. parent process spawned child process
        if par_key and p_key and par_key != p_key:
            edge_map[(par_key, p_key, "spawned")].add(eid)

        # 3. process wrote file
        if p_key and f_key and p_key != f_key:
            edge_map[(p_key, f_key, "wrote")].add(eid)

        # 4. process connected to dst_ip
        if p_key and dip_key:
            edge_map[(p_key, dip_key, "connected_to")].add(eid)

        # 5. host authenticated as user
        if h_key and u_key and not is_machine_account(user):
            edge_map[(h_key, u_key, "authenticated_as")].add(eid)

    # Format entity records
    entities: list[dict[str, Any]] = []
    # (kind, value) -> index in entities list
    key_to_idx: dict[tuple[str, str], int] = {}

    for idx, (key, data) in enumerate(entity_map.items()):
        entities.append(
            {
                "incident_id": incident_id,
                "kind": data["kind"],
                "value": data["value"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "event_ids": sorted(list(data["event_ids"])),
                "enrichment": None,
            }
        )
        key_to_idx[key] = idx

    # Format edge records
    edges: list[dict[str, Any]] = []
    for (src_key, dst_key, rel), eids in edge_map.items():
        if src_key in key_to_idx and dst_key in key_to_idx:
            edges.append(
                {
                    "incident_id": incident_id,
                    "src_kind": src_key[0],
                    "src_value": src_key[1],
                    "dst_kind": dst_key[0],
                    "dst_value": dst_key[1],
                    "relation": rel,
                    "event_ids": sorted(list(eids)),
                }
            )

    return entities, edges
