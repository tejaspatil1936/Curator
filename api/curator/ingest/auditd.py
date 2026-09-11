"""Linux auditd -> OCSF. Interface only.

The APT29 dataset contains no Linux data (datasets/SCHEMA_NOTES.md), so there are no
verified auditd field names to map from. This fixes the signature a parser implements,
matching curator.ingest.sysmon.parse.
"""

from datetime import timedelta

from curator.ingest.ocsf import OcsfEvent

SOURCE = "auditd"


def parse(
    text: str, *, uid: str, event_time_offset: timedelta
) -> tuple[str, OcsfEvent]:
    """One auditd record -> (events.source, OcsfEvent). Not implemented."""
    raise NotImplementedError(
        "auditd parsing is not implemented: no Linux data to verify against"
    )
