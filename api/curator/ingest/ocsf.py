"""OCSF event model (schema 1.3.0 attributes) and its projection onto events columns.

A parser builds a plain dict in OCSF shape and validates it with OcsfEvent. The §5.1
columns are computed from the validated event by OcsfEvent.columns(), so the columns can
never disagree with the stored ocsf document.

Every object forbids unknown attributes: a mapping typo fails validation instead of
silently writing a non-OCSF key. Source fields a parser does not map go to `unmapped`.

Serialize with model_dump_json(exclude_unset=True): only what the parser set is stored.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

OCSF_VERSION = "1.3.0"

# class_uid -> (class_name, category_uid, category_name)
CLASSES: dict[int, tuple[str, int, str]] = {
    0: ("Base Event", 0, "Uncategorized"),
    1001: ("File System Activity", 1, "System Activity"),
    1005: ("Module Activity", 1, "System Activity"),
    1007: ("Process Activity", 1, "System Activity"),
    201001: ("Registry Key Activity", 1, "System Activity"),  # Windows extension
    201002: ("Registry Value Activity", 1, "System Activity"),  # Windows extension
    3001: ("Account Change", 3, "Identity & Access Management"),
    3002: ("Authentication", 3, "Identity & Access Management"),
    3003: ("Authorize Session", 3, "Identity & Access Management"),
    3006: ("Group Management", 3, "Identity & Access Management"),
    4001: ("Network Activity", 4, "Network Activity"),
    4003: ("DNS Activity", 4, "Network Activity"),
}

# The activities each class is used with here (0 = Unknown, 99 = Other in every class).
ACTIVITIES: dict[int, dict[int, str]] = {
    0: {0: "Unknown"},
    1001: {1: "Create", 4: "Delete", 6: "Set Attributes", 14: "Open", 99: "Other"},
    1005: {1: "Load"},
    1007: {1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject"},
    201001: {0: "Unknown", 99: "Other"},
    201002: {2: "Set", 3: "Modify"},
    3001: {1: "Create", 2: "Enable", 4: "Password Reset", 99: "Other"},
    3002: {
        1: "Logon",
        2: "Logoff",
        3: "Authentication Ticket",
        4: "Service Ticket Request",
    },
    3003: {1: "Assign Privileges"},
    3006: {3: "Add User"},
    4001: {1: "Open", 5: "Refuse", 7: "Listen", 99: "Other"},
    4003: {1: "Query"},
}

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class _Obj(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Product(_Obj):
    name: str
    vendor_name: str


class Metadata(_Obj):
    version: str
    uid: str  # Curator-assigned: "<dataset>/<file>:<line>"
    product: Product
    log_name: str | None = None
    log_provider: str | None = None
    event_code: str
    sequence: int | None = None
    original_time: str  # the source string the event time was parsed from
    # Epoch ms when the collector logged the event. Not the event time.
    logged_time: int | None = None


class Fingerprint(_Obj):
    algorithm: str
    value: str


class File(_Obj):
    path: str
    name: str | None = None
    hashes: list[Fingerprint] | None = None


class User(_Obj):
    name: str  # "DOMAIN\\user" when the source gives a separate domain
    domain: str | None = None
    uid: str | None = None  # SID


class Group(_Obj):
    name: str | None = None
    domain: str | None = None
    uid: str | None = None


class Process(_Obj):
    pid: int | None = None
    uid: str | None = None  # Sysmon ProcessGuid
    name: str | None = None
    file: File | None = None
    cmd_line: str | None = None
    integrity: str | None = None
    user: User | None = None
    parent_process: Process | None = None


class Actor(_Obj):
    user: User | None = None
    process: Process | None = None


class Device(_Obj):
    hostname: str


class Endpoint(_Obj):
    ip: str | None = None
    port: int | None = None
    hostname: str | None = None

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v is not None:
            ipaddress.ip_address(v)
        return v


class ConnectionInfo(_Obj):
    protocol_name: str | None = None
    protocol_num: int | None = None
    direction: str | None = None


class RegKey(_Obj):
    path: str


class RegValue(_Obj):
    path: str
    name: str | None = None
    data: str | None = None


class Module(_Obj):
    file: File


class Query(_Obj):
    hostname: str


class Provenance(_Obj):
    """How the event time was obtained. Not an OCSF attribute; hence the x_ prefix."""

    time_field: str  # source field the time came from
    time_utc_offset: str  # offset of that field's clock, e.g. "+00:00" or "-04:00"


class OcsfEvent(_Obj):
    class_uid: int
    class_name: str
    category_uid: int
    category_name: str
    activity_id: int
    activity_name: str
    type_uid: int
    time: int  # epoch ms, derived from time_dt
    time_dt: datetime  # timezone-aware UTC
    severity_id: int
    severity: str | None = None
    status_id: int | None = None
    status: str | None = None
    message: str | None = None
    metadata: Metadata
    device: Device
    actor: Actor | None = None
    user: User | None = None
    group: Group | None = None
    process: Process | None = None
    file: File | None = None
    module: Module | None = None
    reg_key: RegKey | None = None
    reg_value: RegValue | None = None
    query: Query | None = None
    src_endpoint: Endpoint | None = None
    dst_endpoint: Endpoint | None = None
    connection_info: ConnectionInfo | None = None
    logon_type_id: int | None = None
    auth_protocol: str | None = None
    unmapped: dict[str, Any]
    x_curator: Provenance

    @model_validator(mode="before")
    @classmethod
    def _derive(cls, data: Any) -> Any:
        """Fill the attributes implied by class_uid, activity_id and time_dt."""
        if not isinstance(data, dict):
            return data
        cid, aid, when = (
            data.get("class_uid"),
            data.get("activity_id"),
            data.get("time_dt"),
        )
        if cid not in CLASSES:
            raise ValueError(f"unsupported class_uid {cid}")
        if aid not in ACTIVITIES[cid]:
            raise ValueError(f"unsupported activity_id {aid} for class {cid}")
        if not isinstance(when, datetime) or when.utcoffset() is None:
            raise ValueError("time_dt must be a timezone-aware datetime")
        name, cat, cat_name = CLASSES[cid]
        return {
            **data,
            "class_name": name,
            "category_uid": cat,
            "category_name": cat_name,
            "activity_name": ACTIVITIES[cid][aid],
            "type_uid": cid * 100 + aid,
            "time": (when - _EPOCH) // timedelta(milliseconds=1),
        }

    @field_validator("time_dt")
    @classmethod
    def _to_utc(cls, v: datetime) -> datetime:
        return v.astimezone(UTC)

    def _primary_process(self) -> Process | None:
        # Launch/Terminate events are about `process`; in every other event the process
        # doing the activity is the actor.
        if self.class_uid == 1007 and self.activity_id in (1, 2) and self.process:
            return self.process
        return self.actor.process if self.actor else None

    def columns(self) -> dict[str, Any]:
        """§5.1 column values derived from this event (source, ocsf, raw excluded)."""
        proc = self._primary_process()
        if self.class_uid in (3002, 3003):
            user = self.user
        else:
            user = self.actor.user if self.actor else None
        if user is None and proc is not None:
            user = proc.user
        parent = proc.parent_process if proc else None
        return {
            "ts": self.time_dt,
            "host": self.device.hostname,
            "user_name": user.name if user else None,
            "process_name": proc.file.path if proc and proc.file else None,
            "process_id": proc.pid if proc else None,
            "parent_process": parent.file.path if parent and parent.file else None,
            "src_ip": _column_ip(self.src_endpoint),
            "dst_ip": _column_ip(self.dst_endpoint),
            "file_path": self.file.path if self.file else None,
            "command_line": proc.cmd_line if proc else None,
            "event_code": self.metadata.event_code,
        }


def _column_ip(ep: Endpoint | None) -> str | None:
    """IP for an inet column: IPv4-mapped IPv6 as plain IPv4, no zone index."""
    if ep is None or ep.ip is None:
        return None
    ip = ipaddress.ip_address(ep.ip.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


Process.model_rebuild()
