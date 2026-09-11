r"""Entity normalization for users, hosts, processes, paths, and IP addresses.

Enforces the dataset realities documented in datasets/SCHEMA_NOTES.md:
- Host is always the endpoint Hostname (e.g. UTICA), never the collector host.
- User accounts strip DMEVALS domain variants, case-fold, and flag machine accounts ($).
- Processes join on process GUIDs (ocsf.process.uid), not case-inconsistent names.
- Paths case-fold and resolve \device\harddiskvolumeN\ to standard drive letters.
- Non-routable/loopback IPs (0.0.0.0, 127.0.0.1, ::, broadcast) are excluded from correlation.
"""

from __future__ import annotations

import ipaddress
import re

_HARDDISK_RE = re.compile(r"^\\device\\harddiskvolume\d+\\", re.IGNORECASE)
_DOMAIN_PREFIX_RE = re.compile(r"^(dmevals\.local|dmevals)\\+", re.IGNORECASE)
_DOMAIN_SUFFIX_RE = re.compile(r"@dmevals(\.local)?$", re.IGNORECASE)

_IGNORABLE_IPS = {
    "0.0.0.0",
    "::",
    "127.0.0.1",
    "::1",
    "0:0:0:0:0:0:0:1",
    "255.255.255.255",
}


def normalize_user(user: str | None) -> str | None:
    """Normalize user account names: strip domain variations, case-fold."""
    if not user or user == "-":
        return None
    val = user.strip()
    # Strip prefix domain (DMEVALS\ or dmevals.local\)
    val = _DOMAIN_PREFIX_RE.sub("", val)
    # Strip suffix domain (@DMEVALS.LOCAL or @dmevals)
    val = _DOMAIN_SUFFIX_RE.sub("", val)
    val = val.lower().strip()
    return val if val and val != "-" else None


def is_machine_account(user: str | None) -> bool:
    """Check if the user is a Windows machine account (ends with $)."""
    norm = normalize_user(user)
    return bool(norm and norm.endswith("$"))


def is_correlating_user(user: str | None) -> bool:
    """Check if a user account can be used as a correlation join key (3.2c).

    Excludes built-in service accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE,
    ANONYMOUS LOGON), machine accounts (ending with $), and DWM/UMFD session accounts.
    """
    norm = normalize_user(user)
    if not norm or norm == "-":
        return False
    if norm.endswith("$"):
        return False
    if norm.startswith("dwm-") or norm.startswith("umfd-") or norm.startswith("font driver host\\"):
        return False
    from curator.config import NON_CORRELATING_USERS

    if norm in NON_CORRELATING_USERS:
        return False
    # Check without domain prefix or variations
    clean = norm.split("\\")[-1]
    if clean in ("system", "network service", "local service", "anonymous logon"):
        return False
    return True


def normalize_host(hostname: str | None) -> str | None:
    """Normalize endpoint host from Hostname (never the collector host).

    Collapses FQDNs like UTICA.dmevals.local -> UTICA.
    """
    if not hostname or hostname == "-":
        return None
    val = hostname.strip().split(".")[0].upper()
    return val if val else None


def normalize_process_uid(uid: str | None) -> str | None:
    """Normalize Sysmon / Security Process GUIDs: strip braces, uppercase."""
    if not uid or uid == "-":
        return None
    cleaned = uid.strip().strip("{}").upper()
    return cleaned if cleaned else None


def normalize_path(path: str | None) -> str | None:
    """Normalize file or registry paths: case-fold, map harddiskvolume to C:."""
    if not path or path == "-":
        return None
    cleaned = path.strip()
    # Map \device\harddiskvolumeN\... to C:\...
    cleaned = _HARDDISK_RE.sub(r"c:\\", cleaned)
    cleaned = cleaned.lower()
    return cleaned


def normalize_ip(ip_str: Any) -> str | None:
    """Normalize and validate an IP address. Returns None if invalid or ignorable."""
    if not ip_str or ip_str == "-":
        return None
    raw = str(ip_str).split("%", 1)[0].strip()
    if raw in _IGNORABLE_IPS:
        return None
    try:
        ip = ipaddress.ip_address(raw)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
            return None
        # Convert IPv4-mapped IPv6 to IPv4 string
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return None


def is_ignorable_ip(ip_str: str | None) -> bool:
    """Check if an IP should be excluded from correlation joins."""
    return normalize_ip(ip_str) is None
