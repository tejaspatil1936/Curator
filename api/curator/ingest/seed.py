"""Dataset loader: streams a dataset's files through the parsers into events, then loads
the dataset's ground truth.

Idempotent. Each source record is identified by "<dataset>/<file>:<line>"
(ocsf.metadata.uid, unique-indexed), so re-running inserts nothing new; identical
records at different positions stay distinct events for dedup (§6.1) to see. Rows go
through COPY into a temp table, then INSERT ... ON CONFLICT DO NOTHING, in file order.

raw is the line's exact text minus its terminating newline. --verify-raw re-hashes every
line of the source files and compares it with sha256(raw) in the database.

    python -m curator.ingest.seed apt29
    python -m curator.ingest.seed apt29 --verify-raw
"""

import argparse
import hashlib
import itertools
import json
import logging
import re
import sys
import time
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import openpyxl
from sqlalchemy import text

from curator import audit
from curator.config import configure_logging, settings
from curator.db import engine
from curator.fetch import RemoteFile, ensure
from curator.ingest import sysmon

logger = logging.getLogger(__name__)

_APT29 = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/"
    "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/compound/apt29"
)


@dataclass(frozen=True)
class Dataset:
    name: str
    event_files: tuple[RemoteFile, ...]
    ground_truth: RemoteFile | None
    # UTC offset of the records' EventTime clock, which the records do not state.
    event_time_offset: timedelta


DATASETS = {
    "apt29": Dataset(
        name="apt29",
        event_files=(
            RemoteFile(
                "apt29/day1/apt29_evals_day1_manual.zip",
                f"{_APT29}/day1/apt29_evals_day1_manual.zip",
                "98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5",
            ),
            RemoteFile(
                "apt29/day2/apt29_evals_day2_manual.zip",
                f"{_APT29}/day2/apt29_evals_day2_manual.zip",
                "377f8cba5db95a453a3ee8bd19f493efafc23724541482a4da99da28ee4665f9",
            ),
        ),
        ground_truth=RemoteFile(
            "apt29/emulationplans/apt29.xlsx",
            f"{_APT29}/emulationplans/apt29.xlsx",
            "053e70c6ba95eac481b370f8b1545ec3f1f00306c828634741a8c7399719c228",
        ),
        # Verified in datasets/SCHEMA_NOTES.md: EventTime = UtcTime - 4h for Sysmon.
        event_time_offset=timedelta(hours=-4),
    ),
}

_COLUMNS = (
    "ts, source, host, user_name, process_name, process_id, parent_process, "
    "src_ip, dst_ip, file_path, command_line, event_code, ocsf, raw"
)
_STAGE = """
    CREATE TEMP TABLE IF NOT EXISTS events_stage (
        n bigint NOT NULL, ts timestamptz NOT NULL, source text NOT NULL, host text,
        user_name text, process_name text, process_id integer, parent_process text,
        src_ip inet, dst_ip inet, file_path text, command_line text, event_code text,
        ocsf jsonb NOT NULL, raw json NOT NULL
    ) ON COMMIT DELETE ROWS
"""
_MOVE = f"""
    WITH moved AS (
        INSERT INTO events ({_COLUMNS})
        SELECT {_COLUMNS} FROM events_stage ORDER BY n
        ON CONFLICT ((ocsf #>> '{{metadata,uid}}')) DO NOTHING
        RETURNING source
    )
    SELECT source, count(*) FROM moved GROUP BY source
"""
_ROW_KEYS = tuple(k.strip() for k in _COLUMNS.split(","))


def _lines(path: Path, dataset: str) -> Iterator[tuple[str, bytes]]:
    """(uid, line bytes minus the newline) for each line of each member of the zip."""
    with zipfile.ZipFile(path) as z:
        for member in z.namelist():
            with z.open(member) as f:
                for n, line in enumerate(f, 1):
                    yield f"{dataset}/{member}:{n}", (
                        line[:-1] if line.endswith(b"\n") else line
                    )


def _batched(items: Iterable, size: int) -> Iterator[list]:
    it = iter(items)
    while batch := list(itertools.islice(it, size)):
        yield batch


def _load_events(ds: Dataset) -> dict:
    started = time.monotonic()
    inserted: Counter[str] = Counter()
    present = rejected = n = 0
    files = []
    raw_conn = engine.raw_connection()
    try:
        pg = raw_conn.driver_connection  # psycopg connection, for COPY
        with pg.cursor() as cur:
            cur.execute(_STAGE)
            for rf in ds.event_files:
                path = ensure(rf)
                f_records = f_inserted = 0
                for batch in _batched(_lines(path, ds.name), settings.seed_batch_size):
                    rows = []
                    for uid, line in batch:
                        f_records += 1
                        n += 1
                        try:
                            raw = line.decode("utf-8")
                            source, event = sysmon.parse(
                                raw, uid=uid, event_time_offset=ds.event_time_offset
                            )
                        except (
                            Exception
                        ) as exc:  # noqa: BLE001 - logged and counted, never silent
                            rejected += 1
                            logger.warning("rejected %s: %s", uid, exc)
                            continue
                        c = event.columns()
                        c["source"] = source
                        c["ocsf"] = event.model_dump_json(exclude_unset=True)
                        c["raw"] = raw
                        rows.append((n, *(c[k] for k in _ROW_KEYS)))
                    with cur.copy(
                        f"COPY events_stage (n, {_COLUMNS}) FROM STDIN"
                    ) as copy:
                        for row in rows:
                            copy.write_row(row)
                    cur.execute(_MOVE)
                    moved = dict(cur.fetchall())
                    pg.commit()
                    inserted.update(moved)
                    f_inserted += sum(moved.values())
                    present += len(rows) - sum(moved.values())
                    if f_records % 100_000 < settings.seed_batch_size:
                        logger.info(
                            "%s: %d records read, %d inserted",
                            rf.path,
                            f_records,
                            f_inserted,
                        )
                files.append(
                    {
                        "path": rf.path,
                        "sha256": rf.sha256,
                        "records": f_records,
                        "inserted": f_inserted,
                    }
                )
                logger.info(
                    "%s: done, %d records, %d inserted", rf.path, f_records, f_inserted
                )
    finally:
        raw_conn.close()
    return {
        "dataset": ds.name,
        "files": files,
        "records": n,
        "inserted": sum(inserted.values()),
        "already_present": present,
        "rejected": rejected,
        "sources": dict(sorted(inserted.items())),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def ground_truth_rows(path: Path, dataset: str) -> list[dict]:
    """Technique IDs cited in each step's Description of the emulation plan.

    The plan's technique column holds names only; the IDs appear in the Description
    prose, e.g. "clicks (T1204)". Setup rows cite none. The plan has no timestamps.
    """
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    rows = []
    for ws in wb.worksheets:
        values = ws.iter_rows(values_only=True)
        header = {
            str(h).strip().lower(): i
            for i, h in enumerate(next(values))
            if h is not None
        }
        stage, step, desc = header["stage"], header["step"], header["description"]
        tech = header.get("technique", header.get("techniques"))
        for v in values:
            ids = list(dict.fromkeys(_TECHNIQUE_ID.findall(str(v[desc] or ""))))
            techniques = (
                " ".join(str(v[tech] or "").split()) if tech is not None else ""
            )
            where = f"{ws.title} step {str(v[step]).strip()}"
            note = f"{where} ({str(v[stage] or '').strip()}); plan: {techniques}"
            rows.extend(
                {"dataset": dataset, "technique_id": t, "note": note} for t in ids
            )
    wb.close()
    return rows


def _load_ground_truth(ds: Dataset) -> dict:
    path = ensure(ds.ground_truth)
    rows = ground_truth_rows(path, ds.name)
    with engine.begin() as conn:
        # Serialize concurrent loads of one dataset. Without this, a second
        # transaction's DELETE cannot see the first one's uncommitted INSERT, and
        # both sets of rows survive.
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('ground_truth:' || :d))"),
            {"d": ds.name},
        )
        conn.execute(
            text("DELETE FROM ground_truth WHERE dataset = :d"), {"d": ds.name}
        )
        if rows:
            conn.execute(
                text(
                    "INSERT INTO ground_truth (dataset, technique_id, ts, note) "
                    "VALUES (:dataset, :technique_id, NULL, :note)"
                ),
                rows,
            )
        current = conn.execute(
            text(
                "SELECT count(DISTINCT g.technique_id) FROM ground_truth g "
                "JOIN techniques t ON t.id = g.technique_id WHERE g.dataset = :d"
            ),
            {"d": ds.name},
        ).scalar_one()
        detail = {
            "dataset": ds.name,
            "file": ds.ground_truth.path,
            "sha256": ds.ground_truth.sha256,
            "rows": len(rows),
            "distinct_technique_ids": len({r["technique_id"] for r in rows}),
            "ids_in_current_attack": current,
        }
        audit.append(conn, "pipeline", "seed.ground_truth", detail)
    logger.info("ground truth loaded %s", json.dumps(detail))
    return detail


def seed(name: str) -> dict:
    """Load a dataset's events, then its ground truth.

    Returns {"events": rows inserted, "skipped": records not inserted, "sources":
    inserted rows per source}. skipped counts records already present plus any the
    parser rejected; the audit chain records the two separately.
    """
    ds = DATASETS[name]
    detail = _load_events(ds)
    with engine.begin() as conn:
        audit.append(conn, "pipeline", "seed.events", detail)
    logger.info("events loaded %s", json.dumps(detail))
    if ds.ground_truth is not None:
        _load_ground_truth(ds)
    return {
        "events": detail["inserted"],
        "skipped": detail["already_present"] + detail["rejected"],
        "sources": detail["sources"],
    }


def verify_raw(name: str) -> dict:
    """Compare sha256 of every source line with sha256(raw) of its stored event."""
    ds = DATASETS[name]
    expected: dict[str, bytes] = {}
    for rf in ds.event_files:
        for uid, line in _lines(ensure(rf), ds.name):
            expected[uid] = hashlib.sha256(line).digest()
    records = len(expected)
    matched = mismatched = extra = 0
    with engine.connect() as conn:
        rows = conn.execution_options(yield_per=20_000).execute(
            text(
                "SELECT ocsf #>> '{metadata,uid}' AS uid, "
                "sha256(convert_to(raw::text, 'UTF8')) AS h "
                "FROM events WHERE ocsf #>> '{metadata,uid}' LIKE :prefix"
            ),
            {"prefix": f"{ds.name}/%"},
        )
        for r in rows:
            want = expected.pop(r.uid, None)
            if want is None:
                extra += 1
            elif want == bytes(r.h):
                matched += 1
            else:
                mismatched += 1
                if mismatched <= 5:
                    logger.error("raw differs from source: %s", r.uid)
    return {
        "records_in_files": records,
        "byte_identical": matched,
        "different": mismatched,
        "missing_from_db": len(expected),
        "in_db_not_in_files": extra,
    }


def _main() -> None:
    configure_logging()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset", choices=sorted(DATASETS))
    ap.add_argument(
        "--verify-raw",
        action="store_true",
        help="check stored raw against the source files",
    )
    args = ap.parse_args()
    result = verify_raw(args.dataset) if args.verify_raw else seed(args.dataset)
    sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    _main()
