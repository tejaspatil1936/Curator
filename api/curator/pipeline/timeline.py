"""Deterministic timeline generation (system_design.md §6.1).

Orders events and alerts strictly by:
1. ts (timestamp) ASC
2. event_code ASC (resolves second-precision timestamp ties on non-Sysmon logs)
3. id ASC

No model involvement, ever.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def build_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a deterministic timeline from events or alerts."""

    def sort_key(e: dict[str, Any]) -> tuple[datetime, str, int]:
        ts = e.get("ts")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        event_code = str(e.get("event_code") or e.get("rule_id") or "")
        event_id = int(e.get("id") or 0)
        return (ts, event_code, event_id)

    return sorted(events, key=sort_key)
