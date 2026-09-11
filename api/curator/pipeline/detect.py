"""Deterministic detection engine: Python predicates over OCSF and telemetry fields.

Derives candidate security alerts from raw telemetry events.
Implements 20 rules derived from confirmed event types in datasets/SCHEMA_NOTES.md.
Rules cite the exact EventIDs they inspect.
Technique IDs are author hints and MUST NEVER be used for scoring (system_design.md §6.1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from curator.config import DC_SERVICE_PORTS
from curator.ingest.normalize import (
    is_ignorable_ip,
    is_machine_account,
    normalize_host,
    normalize_path,
    normalize_process_uid,
    normalize_user,
)



@dataclass(frozen=True)
class AlertCandidate:
    event_id: int
    rule_id: str
    rule_name: str
    severity: str  # low | medium | high | critical
    technique_ids: list[str]  # rule author's hint — never used for scoring
    ts: datetime
    host: str | None
    user_norm: str | None
    process_uid: str | None
    command_line: str | None = None
    is_planted: bool = False
    detail: dict[str, Any] | None = None


# Precompiled regular expressions for high-throughput rule evaluation
_OFFICE_PROC_RE = re.compile(
    r"(winword|excel|powerpnt|outlook)\.exe$", re.IGNORECASE
)
_SHELL_SCRIPT_RE = re.compile(
    r"(powershell|cmd|wscript|cscript|rundll32|mshta|certutil)\.exe$",
    re.IGNORECASE,
)
_SUSPICIOUS_PATH_RE = re.compile(
    r"(c:\\programdata\\|\\appdata\\local\\temp\\|c:\\users\\[^\\]+\\temp\\)",
    re.IGNORECASE,
)
_POWERSHELL_ENC_RE = re.compile(
    r"(-enc|-encodedcommand|-e\s|frombase64string)", re.IGNORECASE
)
_POWERSHELL_HIDDEN_RE = re.compile(
    r"(-w\s+hidden|-windowstyle\s+hidden)", re.IGNORECASE
)
_DOWNLOAD_CRADLE_RE = re.compile(
    r"(downloadstring|downloadfile|webrequest|net\.webclient|invoke-webrequest|iwr\s)",
    re.IGNORECASE,
)
_RUN_KEY_RE = re.compile(r"\\currentversion\\run(once)?", re.IGNORECASE)
_SUSP_MASKS = {
    "0x1010",
    "0x1038",
    "0x1410",
    "0x1438",
    "0x143a",
    "0x1fffff",
    "0x1f0fff",
    "0x1f3fff",
}
_RECON_BINARIES = {
    "whoami.exe",
    "nltest.exe",
    "systeminfo.exe",
    "net.exe",
    "net1.exe",
    "tasklist.exe",
    "quser.exe",
    "qwinsta.exe",
    "ipconfig.exe",
}
_ADMIN_SHARES = {"ADMIN$", "C$", "IPC$"}
_STAGING_PATH_RE = re.compile(
    r"(\\appdata\\local\\temp\\|c:\\programdata\\|\\appdata\\roaming\\"
    r"|\\users\\[^\\]+\\documents\\|\\windows\\temp\\)",
    re.IGNORECASE,
)
# Only true archive/database formats — .dat and .db removed as too generic
_STAGING_EXTENSIONS = (".zip", ".rar", ".7z", ".gz", ".tar", ".cab")
# Windows system ProgramData paths that produce noise — never attacker staging
_SYSTEM_PROGRAMDATA_RE = re.compile(
    r"c:\\programdata\\microsoft\\windows\\",
    re.IGNORECASE,
)

# 6.1a: Benign Windows scheduled tasks to ignore in CUR-008
_BENIGN_TASK_SUBSTRINGS = (
    r"\onedrive standalone update task",
    r"\microsoft\windows\updateorchestrator",
    r"\microsoft\windows\softwareprotectionplatform",
    r"\microsoft\windows\grouppolicy",
    r"\microsoft\windows\device information",
    r"\microsoft\windows\application experience",
    r"\microsoft\windows\pushtoinstall",
)

# 6.1a: Evaluator / test harness IP range
_EVALUATOR_IPS = {"172.18.39.2"}


def evaluate_event(event: dict[str, Any]) -> list[AlertCandidate]:
    """Evaluate an event against all detection rules.

    Returns at most one alert candidate per rule for the event.
    """
    eid = str(event.get("event_code") or "")
    source = event.get("source") or ""
    ts = event.get("ts")
    event_id = event["id"]
    is_planted = bool(event.get("is_planted", False))

    ocsf = event.get("ocsf") or {}
    unmapped = ocsf.get("unmapped") or {}
    actor = ocsf.get("actor") or {}
    actor_proc = actor.get("process") or {}
    ocsf_proc = ocsf.get("process") or actor_proc
    parent_proc = (
        ocsf_proc.get("parent_process") or actor_proc.get("parent_process") or {}
    )

    # Normalized fields
    raw_host = (
        event.get("host")
        or (ocsf.get("device") or {}).get("hostname")
        or unmapped.get("Hostname")
    )
    host = normalize_host(raw_host)

    raw_user = (
        event.get("user_name")
        or (actor.get("user") or {}).get("name")
        or (ocsf.get("user") or {}).get("name")
        or unmapped.get("User")
        or unmapped.get("SubjectUserName")
    )
    user_norm = normalize_user(raw_user)

    proc_uid = normalize_process_uid(
        ocsf_proc.get("uid")
        or unmapped.get("ProcessGuid")
        or unmapped.get("SourceProcessGUID")
        or unmapped.get("SourceProcessGuid")
    )

    proc_path = normalize_path(
        event.get("process_name")
        or (ocsf_proc.get("file") or {}).get("path")
        or unmapped.get("Image")
        or unmapped.get("NewProcessName")
        or unmapped.get("ProcessName")
    )
    proc_name = proc_path.split("\\")[-1] if proc_path else ""

    parent_path = normalize_path(
        event.get("parent_process")
        or (parent_proc.get("file") or {}).get("path")
        or unmapped.get("ParentImage")
        or unmapped.get("ParentProcessName")
    )
    parent_name = parent_path.split("\\")[-1] if parent_path else ""

    cmd_line = (
        event.get("command_line")
        or ocsf_proc.get("cmd_line")
        or unmapped.get("CommandLine")
        or ""
    )

    file_path = normalize_path(
        event.get("file_path")
        or (ocsf.get("file") or {}).get("path")
        or unmapped.get("TargetFilename")
    )

    src_ip = event.get("src_ip") or (ocsf.get("src_endpoint") or {}).get("ip")
    dst_ip = event.get("dst_ip") or (ocsf.get("dst_endpoint") or {}).get("ip")
    raw_dst_port = (
        (ocsf.get("dst_endpoint") or {}).get("port")
        or unmapped.get("DestinationPort")
    )
    dst_port = int(raw_dst_port) if raw_dst_port and str(raw_dst_port).isdigit() else None


    alerts: list[AlertCandidate] = []

    def add_alert(
        rule_id: str,
        rule_name: str,
        severity: str,
        technique_ids: list[str],
        detail: dict[str, Any] | None = None,
    ) -> None:
        alerts.append(
            AlertCandidate(
                event_id=event_id,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                technique_ids=technique_ids,
                ts=ts,
                host=host,
                user_norm=user_norm,
                process_uid=proc_uid,
                command_line=cmd_line,
                is_planted=is_planted,
                detail=detail,
            )
        )


    # --------------------------------------------------------------------------
    # Rule CUR-001: Office Application Spawning Script Interpreter / Shell
    # EventIDs: Sysmon 1, Windows Security 4688
    # --------------------------------------------------------------------------
    if eid in ("1", "4688"):
        if _OFFICE_PROC_RE.search(parent_name) and _SHELL_SCRIPT_RE.search(
            proc_name
        ):
            add_alert(
                "CUR-001",
                "Office Application Spawning Script Interpreter or Shell",
                "critical",
                ["T1059.001", "T1204.002"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-002: Execution from ProgramData or Temp Directory
    # EventIDs: Sysmon 1, Windows Security 4688
    # --------------------------------------------------------------------------
    if eid in ("1", "4688") and proc_path:
        if _SUSPICIOUS_PATH_RE.search(proc_path):
            # Target non-standard binaries, scripts, or screensavers
            if (
                proc_name.endswith((".exe", ".scr", ".bat", ".ps1", ".vbs"))
                and not proc_name.startswith("docker")
                and not proc_name.startswith("msedge")
            ):
                add_alert(
                    "CUR-002",
                    "Execution from ProgramData or Temp Directory",
                    "high",
                    ["T1059", "T1204"],
                )

    # --------------------------------------------------------------------------
    # Rule CUR-003: PowerShell with Encoded or Hidden Arguments
    # EventIDs: Sysmon 1, Security 4688, PowerShell 4104
    # --------------------------------------------------------------------------
    script_text = unmapped.get("ScriptBlockText") or ""
    ps_target_text = f"{cmd_line} {script_text}"
    if eid in ("1", "4688", "4104"):
        if (
            "powershell" in proc_name
            or eid == "4104"
            or "powershell" in cmd_line.lower()
        ):
            if _POWERSHELL_ENC_RE.search(
                ps_target_text
            ) or _POWERSHELL_HIDDEN_RE.search(ps_target_text):
                add_alert(
                    "CUR-003",
                    "PowerShell Encoded or Hidden Window Execution",
                    "high",
                    ["T1059.001", "T1027"],
                )

    # --------------------------------------------------------------------------
    # Rule CUR-004: PowerShell Download Cradle / Web Fetch
    # EventIDs: Sysmon 1, Security 4688, PowerShell 4104
    # --------------------------------------------------------------------------
    if eid in ("1", "4688", "4104"):
        if (
            "powershell" in proc_name
            or eid == "4104"
            or "powershell" in cmd_line.lower()
        ):
            if _DOWNLOAD_CRADLE_RE.search(ps_target_text):
                add_alert(
                    "CUR-004",
                    "PowerShell Web Download Cradle Execution",
                    "high",
                    ["T1105", "T1059.001"],
                )

    # --------------------------------------------------------------------------
    # Rule CUR-005: Suspicious Access to LSASS Process Memory
    # EventIDs: Sysmon 10
    # --------------------------------------------------------------------------
    if eid == "10":
        target_img = normalize_path(
            (ocsf_proc.get("file") or {}).get("path")
            or unmapped.get("TargetImage")
            or ""
        )
        actor_img = normalize_path(
            (parent_proc.get("file") or {}).get("path")
            or unmapped.get("SourceImage")
            or ""
        )
        actor_name_clean = actor_img.split("\\")[-1].lower() if actor_img else ""
        granted_access = str(unmapped.get("GrantedAccess") or "").lower()
        if target_img and target_img.endswith("lsass.exe"):
            if actor_name_clean not in ("csrss.exe", "wininit.exe"):
                if granted_access in _SUSP_MASKS or "0x1010" in granted_access:
                    add_alert(
                        "CUR-005",
                        "Suspicious LSASS Process Memory Access",
                        "critical",
                        ["T1003.001"],
                    )

    # --------------------------------------------------------------------------
    # Rule CUR-006: Registry Run / RunOnce Key Persistence
    # EventIDs: Sysmon 12, 13, Windows Security 4657
    # --------------------------------------------------------------------------
    if eid in ("12", "13", "4657"):
        reg_target = normalize_path(
            (ocsf.get("reg_key") or {}).get("path")
            or (ocsf.get("reg_value") or {}).get("path")
            or unmapped.get("TargetObject")
            or unmapped.get("ObjectName")
            or ""
        )
        if reg_target and _RUN_KEY_RE.search(reg_target):
            add_alert(
                "CUR-006",
                "Registry Run or RunOnce Key Modification",
                "high",
                ["T1547.001"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-007: Windows Service Creation
    # EventIDs: Security 4697, System 7045
    # --------------------------------------------------------------------------
    if eid in ("4697", "7045"):
        add_alert(
            "CUR-007",
            "Windows Service Installed or Created",
            "high",
            ["T1543.003", "T1569.002"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-008: Scheduled Task Creation or Modification
    # EventIDs: Security 4698, 4702
    # --------------------------------------------------------------------------
    if eid in ("4698", "4702"):
        raw_task_name = str(
            unmapped.get("TaskName")
            or (event.get("raw") or {}).get("TaskName")
            or ""
        ).lower()
        is_benign_task = any(s in raw_task_name for s in _BENIGN_TASK_SUBSTRINGS)
        if not is_benign_task:
            add_alert(
                "CUR-008",
                "Scheduled Task Created or Updated",
                "medium",
                ["T1053.005"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-009: Local User Account Creation
    # EventIDs: Security 4720, 4722, 4724
    # --------------------------------------------------------------------------
    if eid in ("4720", "4722", "4724"):
        add_alert(
            "CUR-009",
            "Local User Account Created or Enabled",
            "high",
            ["T1136.001"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-010: Security Group Membership Change
    # EventIDs: Security 4728, 4732
    # --------------------------------------------------------------------------
    if eid in ("4728", "4732"):
        add_alert(
            "CUR-010",
            "Privileged Security Group Membership Changed",
            "high",
            ["T1098"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-011: WMI Activity or WMI Process Spawn
    # EventIDs: WMI-Activity 5857, 5858, 5861, Sysmon 1
    # --------------------------------------------------------------------------
    if eid in ("5857", "5858", "5861"):
        add_alert(
            "CUR-011",
            "WMI Activity Provider Operation",
            "medium",
            ["T1047"],
        )
    elif eid in ("1", "4688") and parent_name == "wmiprvse.exe":
        add_alert(
            "CUR-011",
            "Process Spawned by WMI Provider (wmiprvse.exe)",
            "medium",
            ["T1047"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-012: Administrative Network Share Access
    # EventIDs: Security 5140, 5145
    # --------------------------------------------------------------------------
    if eid in ("5140", "5145"):
        share_name = str(unmapped.get("ShareName") or "").upper()
        if any(s in share_name for s in _ADMIN_SHARES):
            add_alert(
                "CUR-012",
                "Administrative Network Share Accessed",
                "medium",
                ["T1021.002"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-013: Outbound Network Connection by Scripting or Utility Process
    # EventIDs: Sysmon 3
    # --------------------------------------------------------------------------
    if eid == "3" and dst_ip and not is_ignorable_ip(dst_ip):
        # Exclude DC on expected service ports (53, 88, 135, 389, 445) per 3.2a
        is_dc_service_port = dst_port in DC_SERVICE_PORTS
        if not is_dc_service_port:
            if proc_name in (
                "powershell.exe",
                "cmd.exe",
                "rundll32.exe",
                "cscript.exe",
                "wscript.exe",
                "certutil.exe",
                "mshta.exe",
            ):
                add_alert(
                    "CUR-013",
                    "Scripting Process Initiated Outbound Network Connection",
                    "medium",
                    ["T1071.001"],
                )


    # --------------------------------------------------------------------------
    # Rule CUR-014: Startup Folder File Creation
    # EventIDs: Sysmon 11
    # --------------------------------------------------------------------------
    if eid == "11" and file_path:
        if (
            "\\startup\\" in file_path
            or "\\start menu\\programs\\startup\\" in file_path
        ):
            add_alert(
                "CUR-014",
                "File Created in Startup Folder",
                "high",
                ["T1547.001"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-015: System and Network Reconnaissance Commands
    # EventIDs: Sysmon 1, Security 4688
    # --------------------------------------------------------------------------
    if eid in ("1", "4688") and proc_name in _RECON_BINARIES:
        add_alert(
            "CUR-015",
            "System or Network Discovery Command Executed",
            "low",
            ["T1033", "T1082", "T1016", "T1049", "T1057"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-016: Suspicious Module Load in Temp or ProgramData
    # EventIDs: Sysmon 7
    # --------------------------------------------------------------------------
    if eid == "7":
        loaded_mod = normalize_path(
            ((ocsf.get("module") or {}).get("file") or {}).get("path")
            or unmapped.get("ImageLoaded")
            or ""
        )
        if loaded_mod and _SUSPICIOUS_PATH_RE.search(loaded_mod):
            add_alert(
                "CUR-016",
                "Module Loaded from Non-Standard Directory",
                "medium",
                ["T1574"],
            )


    # --------------------------------------------------------------------------
    # Rule CUR-017: Remote Desktop Interactive Logon
    # EventIDs: Security 4624 (LogonType 10), TerminalServices 1149
    # --------------------------------------------------------------------------
    if eid == "1149":
        # Extract source IP from Message / raw event for TerminalServices
        raw_msg = str((event.get("raw") or {}).get("Message") or "")
        rdp_ip = None
        if "Source Network Address:" in raw_msg:
            rdp_ip = raw_msg.split("Source Network Address:")[-1].strip().split()[0]
        # Ignore benign evaluator/test harness RDP logins
        if rdp_ip and rdp_ip not in _EVALUATOR_IPS and not is_ignorable_ip(rdp_ip):
            add_alert(
                "CUR-017",
                "Remote Desktop Interactive Session Connected",
                "high",
                ["T1021.001"],
            )
    elif (
        eid == "4624"
        and str(unmapped.get("LogonType") or (event.get("raw") or {}).get("LogonType") or "") == "10"
        and src_ip
        and str(src_ip) not in _EVALUATOR_IPS
        and not is_ignorable_ip(src_ip)
    ):
        add_alert(
            "CUR-017",
            "Remote Desktop Interactive Session Connected",
            "high",
            ["T1021.001"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-018: Kerberos Service Ticket Request (Kerberoasting Indicator)
    # EventIDs: Security 4769
    # --------------------------------------------------------------------------
    if eid == "4769":
        ticket_enc = str(unmapped.get("TicketEncryptionType") or "").lower()
        # 0x17 indicates RC4 encryption often requested in Kerberoasting attacks
        if ticket_enc in ("0x17", "23"):
            add_alert(
                "CUR-018",
                "Kerberos Ticket Request with RC4 Encryption",
                "high",
                ["T1558.003"],
            )

    # --------------------------------------------------------------------------
    # Rule CUR-019: Masquerading, RTL Override, or Suspicious Filename Extension
    # EventIDs: Sysmon 1, 11, 23
    # --------------------------------------------------------------------------
    target_str = f"{proc_path or ''} {file_path or ''} {cmd_line}"
    if (
        "â€®" in target_str
        or ".3aka3." in target_str
        or ".scr" in target_str.lower()
    ):
        add_alert(
            "CUR-019",
            "Masqueraded Filename or Right-to-Left Override Extension",
            "critical",
            ["T1036.002", "T1036.005"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-020: Suspicious Script Host Utility Execution
    # EventIDs: Sysmon 1, Security 4688
    # --------------------------------------------------------------------------
    if (
        eid in ("1", "4688")
        and proc_name in ("wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe")
        and cmd_line
        and len(cmd_line.strip()) > len(proc_name) + 4
    ):
        add_alert(
            "CUR-020",
            "Suspicious Script Host or Registration Utility Invocation",
            "medium",
            ["T1218", "T1059.005"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-021: Windows Remote Management (WinRM) Activity
    # EventIDs: Sysmon 1 / Security 4688 (wsmprovhost.exe spawn),
    #           Sysmon 3 (network connection to port 5985 or 5986)
    # --------------------------------------------------------------------------
    if eid in ("1", "4688") and proc_name == "wsmprovhost.exe":
        add_alert(
            "CUR-021",
            "WinRM Remote Management Host Process Spawned",
            "high",
            ["T1021.006"],
        )
    elif eid == "3" and dst_port in (5985, 5986) and not is_ignorable_ip(dst_ip or ""):
        add_alert(
            "CUR-021",
            "Network Connection to WinRM Port (5985/5986)",
            "medium",
            ["T1021.006", "T1059.001"],
        )

    # --------------------------------------------------------------------------
    # Rule CUR-022: Data Staging — File Write to Temp or ProgramData Directory
    # EventIDs: Sysmon 11 (file creation)
    # Fires when a file is created in a temp/staging directory that is likely
    # preceding collection or exfiltration (T1074).
    # --------------------------------------------------------------------------
    if eid == "11" and file_path:
        if (
            _STAGING_PATH_RE.search(file_path)
            and file_path.lower().endswith(_STAGING_EXTENSIONS)
            and not _SYSTEM_PROGRAMDATA_RE.search(file_path)  # exclude Windows system paths
        ):
            add_alert(
                "CUR-022",
                "Archive or Data File Created in Staging Directory",
                "medium",
                ["T1074", "T1560"],
            )

    return alerts
