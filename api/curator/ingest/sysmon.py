"""Windows event log records -> OCSF: Sysmon, Windows Security, and the other channels.

Input is one NXLog im_msvistalog JSON record as delivered in OTRF Security-Datasets
APT29. Every field name used here is recorded in datasets/SCHEMA_NOTES.md as verified.

- Sysmon and Security events get per-EventID mappings.
- PowerShell and the remaining channels get the envelope mapping only (their content is
  in free text such as Message or ScriptBlockText, which is kept, not parsed).
- A field is consumed only when its value is written into the OCSF event; everything
  else, including '-' placeholders and values that fail conversion, goes to
  ocsf.unmapped verbatim.
- Event time becomes timezone-aware UTC here, at parse time.
"""

from __future__ import annotations

import json
import ntpath
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any

from curator.ingest.ocsf import OCSF_VERSION, OcsfEvent

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# Two collection paths deliver Security-Auditing events under different spellings.
SECURITY_CHANNELS = frozenset({"Security", "security"})
POWERSHELL_CHANNELS = frozenset(
    {"Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"}
)

# NXLog SeverityValue (1 DEBUG .. 5 CRITICAL) -> OCSF severity_id. These are the logging
# subsystem's levels, not a threat assessment; incident priority is §6.1's job.
_SEVERITY_ID = {1: 1, 2: 1, 3: 2, 4: 3, 5: 5}
_STATUS = {"AUDIT_SUCCESS": (1, "Success"), "AUDIT_FAILURE": (2, "Failure")}
_DIRECTION = {"true": "Outbound", "false": "Inbound"}  # Sysmon 3 Initiated
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def source_for(channel: str) -> str:
    """events.source for a Windows event log channel."""
    if channel == SYSMON_CHANNEL:
        return "sysmon"
    if channel in SECURITY_CHANNELS:
        return "winsec"
    if channel in POWERSHELL_CHANNELS:
        return "powershell"
    return "winevt"


class Record:
    """A source record plus the keys whose values have been written into the event."""

    __slots__ = ("d", "used")

    def __init__(self, d: dict[str, Any]) -> None:
        self.d = d
        self.used: set[str] = set()

    def peek(self, key: str) -> Any:
        return self.d.get(key)

    def consume(self, key: str) -> None:
        self.used.add(key)

    def has(self, key: str | None) -> bool:
        """True for a non-empty string other than Windows' '-' placeholder."""
        v = self.d.get(key) if key else None
        return isinstance(v, str) and v not in ("", "-")

    def text(self, key: str | None) -> str | None:
        if not self.has(key):
            return None
        self.used.add(key)
        return self.d[key]

    def number(self, key: str | None) -> int | None:
        """An int, or a decimal or 0x-hex string (Security uses both for PIDs)."""
        v = self.d.get(key) if key else None
        if isinstance(v, bool):
            return None
        if isinstance(v, int):
            n = v
        elif isinstance(v, str):
            try:
                n = int(v, 16) if v[:2].lower() == "0x" else int(v, 10)
            except ValueError:
                return None
        else:
            return None
        self.used.add(key)
        return n

    def ip(self, key: str | None) -> str | None:
        v = self.d.get(key) if key else None
        if not isinstance(v, str):
            return None
        try:
            ip_address(v)
        except ValueError:
            return None
        self.used.add(key)
        return v

    def port(self, key: str | None) -> int | None:
        v = self.d.get(key) if key else None
        if isinstance(v, str) and v.isdigit() and int(v) <= 65535:
            self.used.add(key)
            return int(v)
        return None

    def unmapped(self) -> dict[str, Any]:
        return {k: v for k, v in self.d.items() if k not in self.used}


def _prune(d: dict[str, Any]) -> dict[str, Any] | None:
    out = {k: v for k, v in d.items() if v is not None and v != {}}
    return out or None


# --- object builders ------------------------------------------------------------------


def _user(
    r: Record, name: str, domain: str | None = None, sid: str | None = None
) -> dict | None:
    if not r.has(name):
        return None
    n = r.text(name)
    dom = r.text(domain)
    qualified = f"{dom}\\{n}" if dom and "\\" not in n and "@" not in n else n
    return _prune({"name": qualified, "domain": dom, "uid": r.text(sid)})


def _sysmon_user(r: Record) -> dict | None:
    """Sysmon's own User field, already 'DOMAIN\\user'."""
    v = r.text("User")
    if v is None:
        return None
    return _prune({"name": v, "domain": v.split("\\", 1)[0] if "\\" in v else None})


def _hashes(r: Record, key: str | None) -> list[dict] | None:
    """Sysmon 'ALG=HEX,...' -> OCSF fingerprints; any other shape stays unmapped."""
    v = r.peek(key) if key else None
    if not isinstance(v, str) or not v:
        return None
    pairs = [p.split("=", 1) for p in v.split(",")]
    if not all(len(p) == 2 and p[0] and p[1] for p in pairs):
        return None
    r.consume(key)
    return [{"algorithm": a, "value": h} for a, h in pairs]


def _file(r: Record, path: str | None, hashes: str | None = None) -> dict | None:
    p = r.text(path)
    if p is None:
        return None
    return _prune(
        {"path": p, "name": ntpath.basename(p) or None, "hashes": _hashes(r, hashes)}
    )


def _process(
    r: Record,
    *,
    pid: str | None = None,
    uid: str | None = None,
    path: str | None = None,
    cmd: str | None = None,
    integrity: str | None = None,
    hashes: str | None = None,
    user: dict | None = None,
    parent: dict | None = None,
) -> dict | None:
    f = _file(r, path, hashes)
    return _prune(
        {
            "pid": r.number(pid),
            "uid": r.text(uid),
            "name": f.get("name") if f else None,
            "file": f,
            "cmd_line": r.text(cmd),
            "integrity": r.text(integrity),
            "user": user,
            "parent_process": parent,
        }
    )


def _endpoint(
    r: Record,
    ip: str | None = None,
    port: str | None = None,
    hostname: str | None = None,
) -> dict | None:
    return _prune({"ip": r.ip(ip), "port": r.port(port), "hostname": r.text(hostname)})


def _cls(e: dict, class_uid: int, activity_id: int) -> None:
    e["class_uid"] = class_uid
    e["activity_id"] = activity_id


# --- per-source mappings --------------------------------------------------------------


def _sysmon(r: Record, e: dict) -> None:
    eid = r.peek("EventID")
    user = _sysmon_user(r)  # present on 1, 3, 19, 20, 21, 23

    def image() -> dict | None:
        return _process(r, pid="ProcessId", uid="ProcessGuid", path="Image")

    if eid == 1:
        parent = _process(
            r,
            pid="ParentProcessId",
            uid="ParentProcessGuid",
            path="ParentImage",
            cmd="ParentCommandLine",
        )
        _cls(e, 1007, 1)
        e["process"] = _process(
            r,
            pid="ProcessId",
            uid="ProcessGuid",
            path="Image",
            cmd="CommandLine",
            integrity="IntegrityLevel",
            hashes="Hashes",
            user=user,
            parent=parent,
        )
        e["actor"] = _prune({"user": user, "process": parent})
    elif eid == 2:
        _cls(e, 1001, 6)
        e["actor"] = _prune({"process": image()})
        e["file"] = _file(r, "TargetFilename")
    elif eid == 3:
        _cls(e, 4001, 1)
        e["actor"] = _prune({"user": user, "process": image()})
        e["src_endpoint"] = _endpoint(r, "SourceIp", "SourcePort", "SourceHostname")
        e["dst_endpoint"] = _endpoint(
            r, "DestinationIp", "DestinationPort", "DestinationHostname"
        )
        direction = _DIRECTION.get(r.peek("Initiated"))
        if direction:
            r.consume("Initiated")
        e["connection_info"] = _prune(
            {"protocol_name": r.text("Protocol"), "direction": direction}
        )
    elif eid == 5:
        _cls(e, 1007, 2)
        e["process"] = image()
    elif eid == 7:
        _cls(e, 1005, 1)
        e["actor"] = _prune({"process": image()})
        module_file = _file(r, "ImageLoaded", "Hashes")
        e["module"] = {"file": module_file} if module_file else None
    elif eid in (8, 10):
        guid = "Guid" if eid == 8 else "GUID"  # Sysmon 10 spells it SourceProcessGUID
        _cls(e, 1007, 4 if eid == 8 else 3)
        e["actor"] = _prune(
            {
                "process": _process(
                    r,
                    pid="SourceProcessId",
                    uid=f"SourceProcess{guid}",
                    path="SourceImage",
                )
            }
        )
        e["process"] = _process(
            r, pid="TargetProcessId", uid=f"TargetProcess{guid}", path="TargetImage"
        )
    elif eid == 11:
        _cls(e, 1001, 1)
        e["actor"] = _prune({"process": image()})
        e["file"] = _file(r, "TargetFilename")
    elif eid == 12:
        # Sysmon's own EventType (CreateKey/DeleteKey) is overwritten by NXLog's
        # EventType in this data, so whether the key was created or deleted is unknown.
        _cls(e, 201001, 0)
        e["actor"] = _prune({"process": image()})
        if r.has("TargetObject"):
            e["reg_key"] = {"path": r.text("TargetObject")}
    elif eid == 13:
        _cls(e, 201002, 2)
        e["actor"] = _prune({"process": image()})
        if r.has("TargetObject"):
            e["reg_value"] = _prune(
                {"path": r.text("TargetObject"), "data": r.text("Details")}
            )
    elif eid == 15:
        _cls(e, 1001, 1)
        e["actor"] = _prune({"process": image()})
        e["file"] = _file(r, "TargetFilename", "Hash")
    elif eid == 22:
        _cls(e, 4003, 1)
        e["actor"] = _prune({"process": image()})
        if r.has("QueryName"):
            e["query"] = {"hostname": r.text("QueryName")}
    elif eid == 23:
        _cls(e, 1001, 4)
        e["actor"] = _prune({"user": user, "process": image()})
        e["file"] = _file(r, "TargetFilename", "Hashes")
    else:  # 4, 9, 17, 18, 19, 20, 21, 255: no closer OCSF class
        _cls(e, 0, 0)
        e["actor"] = _prune({"user": user, "process": image()})


def _winsec(r: Record, e: dict) -> None:
    eid = r.peek("EventID")

    def subject() -> dict | None:
        return _user(r, "SubjectUserName", "SubjectDomainName", "SubjectUserSid")

    def target(sid: str | None = "TargetUserSid") -> dict | None:
        return _user(r, "TargetUserName", "TargetDomainName", sid)

    def proc(pid: str = "ProcessId", path: str = "ProcessName") -> dict | None:
        return _process(r, pid=pid, path=path)

    if eid == 4688:
        parent = _process(
            r, pid="ProcessId", path="ParentProcessName"
        )  # creator process
        _cls(e, 1007, 1)
        e["process"] = _process(
            r,
            pid="NewProcessId",
            path="NewProcessName",
            cmd="CommandLine",
            user=target(),
            parent=parent,
        )
        e["actor"] = _prune({"user": subject(), "process": parent})
    elif eid == 4689:
        _cls(e, 1007, 2)
        e["process"] = proc()
        e["actor"] = _prune({"user": subject()})
    elif eid == 4624:
        _cls(e, 3002, 1)
        e["user"] = target()
        e["actor"] = _prune({"user": subject(), "process": proc()})
        e["src_endpoint"] = _endpoint(r, "IpAddress", "IpPort", "WorkstationName")
        e["logon_type_id"] = r.number("LogonType")
        e["auth_protocol"] = r.text("AuthenticationPackageName")
    elif eid in (4634, 4647):
        _cls(e, 3002, 2)
        e["user"] = target()
        e["logon_type_id"] = r.number("LogonType")
    elif eid == 4648:  # logon with explicit credentials
        _cls(e, 3002, 1)
        e["user"] = target(sid=None)
        e["actor"] = _prune({"user": subject(), "process": proc()})
        e["src_endpoint"] = _endpoint(r, "IpAddress", "IpPort")
        e["dst_endpoint"] = _endpoint(r, hostname="TargetServerName")
    elif eid == 4672:
        _cls(e, 3003, 1)
        e["user"] = subject()
    elif eid == 4768:
        _cls(e, 3002, 3)
        e["user"] = target(sid="TargetSid")
        e["src_endpoint"] = _endpoint(r, "IpAddress", "IpPort")
    elif eid == 4769:
        _cls(e, 3002, 4)
        e["user"] = target(sid=None)
        e["src_endpoint"] = _endpoint(r, "IpAddress", "IpPort")
    elif eid == 4776:
        _cls(e, 3002, 1)
        e["user"] = _user(r, "TargetUserName")
        e["src_endpoint"] = _endpoint(r, hostname="Workstation")
        e["auth_protocol"] = r.text("PackageName")
    elif eid in (4720, 4722, 4724, 4738):
        _cls(e, 3001, {4720: 1, 4722: 2, 4724: 4, 4738: 99}[eid])
        e["user"] = target(sid="TargetSid")
        e["actor"] = _prune({"user": subject()})
    elif eid in (4728, 4732):
        _cls(e, 3006, 3)
        e["group"] = _prune(
            {
                "name": r.text("TargetUserName"),
                "domain": r.text("TargetDomainName"),
                "uid": r.text("TargetSid"),
            }
        )
        e["user"] = _user(r, "MemberName", sid="MemberSid")
        e["actor"] = _prune({"user": subject()})
    elif eid in (4656, 4663):
        # ObjectType only selects the class; its value stays in unmapped.
        otype = r.peek("ObjectType") if r.has("ObjectName") else None
        e["actor"] = _prune({"user": subject(), "process": proc()})
        if otype == "File":
            _cls(e, 1001, 14 if eid == 4656 else 99)
            e["file"] = _file(r, "ObjectName")
        elif otype == "Key":
            _cls(e, 201001, 99)
            e["reg_key"] = {"path": r.text("ObjectName")}
        elif otype == "Process":
            _cls(e, 1007, 3)
            e["process"] = _process(r, path="ObjectName")
        else:
            _cls(e, 0, 0)
    elif eid == 4657:
        _cls(e, 201002, 3)
        e["actor"] = _prune({"user": subject(), "process": proc()})
        if r.has("ObjectName"):
            e["reg_value"] = _prune(
                {
                    "path": r.text("ObjectName"),
                    "name": r.text("ObjectValueName"),
                    "data": r.text("NewValue"),
                }
            )
    elif eid in (5154, 5156, 5157, 5158):  # Windows Filtering Platform
        _cls(e, 4001, {5154: 7, 5156: 1, 5157: 5, 5158: 99}[eid])
        e["actor"] = _prune({"process": proc(path="Application")})
        e["src_endpoint"] = _endpoint(r, "SourceAddress", "SourcePort")
        e["dst_endpoint"] = _endpoint(r, "DestAddress", "DestPort")
        e["connection_info"] = _prune({"protocol_num": r.number("Protocol")})
    elif eid in (5140, 5145):  # network share access
        _cls(e, 0, 0)
        e["actor"] = _prune({"user": subject()})
        e["src_endpoint"] = _endpoint(r, "IpAddress", "IpPort")
    elif eid in (4798, 4799):  # group membership enumerated
        _cls(e, 0, 0)
        e["actor"] = _prune(
            {"user": subject(), "process": proc("CallerProcessId", "CallerProcessName")}
        )
    else:
        _cls(e, 0, 0)
        e["actor"] = _prune({"user": subject(), "process": proc()})


def _envelope_only(r: Record, e: dict) -> None:
    """PowerShell and other channels: the envelope's security context is the actor."""
    _cls(e, 0, 0)
    e["actor"] = _prune({"user": _user(r, "AccountName", "Domain", "UserID")})


# --- entry point ----------------------------------------------------------------------


def _offset_label(offset: timedelta) -> str:
    minutes = int(offset.total_seconds()) // 60
    sign = "+" if minutes >= 0 else "-"
    h, m = divmod(abs(minutes), 60)
    return f"{sign}{h:02d}:{m:02d}"


def _event_time(
    r: Record, channel: str, offset: timedelta
) -> tuple[datetime, str, str, str]:
    """(event time, source field, original string, that field's UTC offset)."""
    if channel == SYSMON_CHANNEL and r.has("UtcTime"):
        v = r.text("UtcTime")
        return (
            datetime.strptime(v, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC),
            "UtcTime",
            v,
            "+00:00",
        )
    v = r.text("EventTime")
    if v is None:
        raise ValueError("record has no EventTime")
    local = datetime.strptime(v, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone(offset))
    return local, "EventTime", v, _offset_label(offset)


def _logged_time(r: Record) -> int | None:
    v = r.peek("@timestamp")
    if not isinstance(v, str):
        return None
    try:
        t = datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    r.consume("@timestamp")
    return (t - _EPOCH) // timedelta(milliseconds=1)


def parse(
    text: str, *, uid: str, event_time_offset: timedelta
) -> tuple[str, OcsfEvent]:
    """One source record -> (events.source, OcsfEvent).

    event_time_offset is the UTC offset of the EventTime clock, which the record does
    not state; for APT29 it is -04:00 (derived in datasets/SCHEMA_NOTES.md).
    """
    d = json.loads(text)
    if not isinstance(d, dict):
        raise ValueError("record is not a JSON object")
    r = Record(d)
    channel = r.text("Channel")
    eid = r.number("EventID")
    if channel is None or eid is None:
        raise ValueError("record has no Channel or EventID")
    source = source_for(channel)
    when, time_field, original, offset = _event_time(r, channel, event_time_offset)
    provider = r.text("SourceName")
    sv = r.peek("SeverityValue")
    severity_id = _SEVERITY_ID.get(sv, 0) if isinstance(sv, int) else 0
    if severity_id:
        r.consume("SeverityValue")
    status = _STATUS.get(r.peek("EventType"))
    if status:
        r.consume("EventType")

    e: dict[str, Any] = {
        "time_dt": when,
        "severity_id": severity_id,
        "severity": r.text("Severity"),
        "status_id": status[0] if status else None,
        "status": status[1] if status else None,
        "message": r.text("Message"),
        "metadata": _prune(
            {
                "version": OCSF_VERSION,
                "uid": uid,
                "product": {"name": provider or channel, "vendor_name": "Microsoft"},
                "log_name": channel,
                "log_provider": provider,
                "event_code": str(eid),
                "sequence": r.number("RecordNumber"),
                "original_time": original,
                "logged_time": _logged_time(r),
            }
        ),
        "device": {"hostname": r.text("Hostname")},
        "x_curator": {"time_field": time_field, "time_utc_offset": offset},
    }
    if source == "sysmon":
        _sysmon(r, e)
    elif source == "winsec":
        _winsec(r, e)
    else:
        _envelope_only(r, e)

    event = _prune(e) or {}
    event["unmapped"] = r.unmapped()  # after every mapping has consumed its fields
    return source, OcsfEvent.model_validate(event)
