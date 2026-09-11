"""Hash-chained audit log (system_design.md §5.7).

    hash = sha256(prev_hash || ts || actor || action || canonical_json(detail))

The five fields are concatenated as UTF-8 strings in that order. ts is rendered as ISO
8601 UTC with microseconds, which timestamptz stores exactly, so every hash can be
recomputed from the stored row. The genesis row's prev_hash is '0' * 64.

detail must not contain floats: jsonb normalizes number formatting, which would change
canonical_json on read-back. Use integers (e.g. durations in milliseconds).
"""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from curator.db import engine

GENESIS_HASH = "0" * 64
# Advisory lock key: serializes appends so the chain never forks.
_APPEND_LOCK = 0x61756469


def canonical_json(detail: Any) -> str:
    return json.dumps(detail, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ts(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def compute_hash(
    prev_hash: str, ts: datetime, actor: str, action: str, detail: Any
) -> str:
    payload = prev_hash + _ts(ts) + actor + action + canonical_json(detail)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("audit detail must not contain floats; use integers")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, list | tuple):
        for v in value:
            _reject_floats(v)


def append(
    conn: Connection, actor: str, action: str, detail: dict | None = None
) -> int:
    """Append one row inside the caller's transaction. Returns its id."""
    _reject_floats(detail)
    conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _APPEND_LOCK})
    prev = conn.execute(
        text("SELECT hash FROM audit_chain ORDER BY id DESC LIMIT 1")
    ).scalar()
    prev = prev or GENESIS_HASH
    ts = datetime.now(UTC)
    row = {
        "ts": ts,
        "actor": actor,
        "action": action,
        "detail": None if detail is None else canonical_json(detail),
        "prev_hash": prev,
        "hash": compute_hash(prev, ts, actor, action, detail),
    }
    return conn.execute(
        text(
            "INSERT INTO audit_chain (ts, actor, action, detail, prev_hash, hash) "
            "VALUES (:ts, :actor, :action, CAST(:detail AS jsonb), :prev_hash, :hash) "
            "RETURNING id"
        ),
        row,
    ).scalar_one()


def verify_chain() -> tuple[bool, int | None]:
    """Walk the chain in id order. Returns (valid, id of the first broken row)."""
    prev = GENESIS_HASH
    with engine.connect() as conn:
        rows = conn.execution_options(yield_per=1000).execute(
            text(
                "SELECT id, ts, actor, action, detail, prev_hash, hash "
                "FROM audit_chain ORDER BY id"
            )
        )
        for r in rows:
            if r.prev_hash != prev or r.hash != compute_hash(
                r.prev_hash, r.ts, r.actor, r.action, r.detail
            ):
                return False, r.id
            prev = r.hash
    return True, None


def row_count() -> int:
    with engine.connect() as conn:
        return conn.execute(text("SELECT count(*) FROM audit_chain")).scalar_one()
