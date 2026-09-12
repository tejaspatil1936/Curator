"""credit_pass.py — Single-command credit pass for Curator APT29 evaluation.

Run this once API credits are restored:
    docker exec curator-curator-api-1 python curator/scripts/credit_pass.py

What it does (in order):
  1. Narrative generation   — POST /incidents/{id}/narrative for every open incident
  2. ATT&CK mapping         — map_incident_techniques() for every open incident
  3. Sentence verification  — verify_incident() for every open incident
  4. Accuracy harness       — evaluate_accuracy() reporting 4 headline numbers
  5. Cost summary           — total tokens & USD from audit_chain

Resumable: if it fails at incident 12, re-running skips the 11 already done.
An incident is considered done when narrative_sentences has >= 1 row for it.

Estimated cost before you run:
  24 open incidents:
    - 2 multi-host campaigns (#803, #855): ~25-30 sentences each
    - 22 single-host/component clusters: ~2-9 sentences each (avg ~4)
    - Total estimated sentences: ~140-160 sentences
  Per-model rates:
    - Narrative (Sonnet 5): $3.00/M in, $15.00/M out, $3.75/M cache write, $0.30/M cache read
    - Mapping (Sonnet 5):   $3.00/M in, $15.00/M out, $3.75/M cache write, $0.30/M cache read
    - Verification (Haiku): $0.80/M in, $4.00/M out
  Observed cost from previous run: ~$3.00 for full 20-incident set (~$0.02-$0.04 per small incident,
  ~$0.65-$0.75 per large campaign).
  Total estimated cost for 24 incidents: ~$3.20 - $3.70 USD.
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime

from sqlalchemy import text

from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.ai.verify import verify_incident
from curator.eval.harness import evaluate_accuracy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_incidents(session, limit: int | None = None) -> list[int]:
    query = "SELECT id FROM incidents WHERE status = 'open' ORDER BY priority DESC, id"
    if limit is not None and limit > 0:
        query += f" LIMIT {int(limit)}"
    rows = session.execute(text(query)).fetchall()
    return [r[0] for r in rows]


def _already_done(session, incident_id: int) -> bool:
    """Return True if this incident already has at least one narrative sentence."""
    n = session.execute(text(
        "SELECT COUNT(*) FROM narrative_sentences WHERE incident_id = :id"
    ), {"id": incident_id}).scalar() or 0
    return n > 0


def _cost_from_audit(session) -> dict:
    """Read token counts and USD from audit_chain since pass started."""
    rows = session.execute(text("""
        SELECT
            coalesce(sum((detail->>'input_tokens')::int), 0)           AS in_toks,
            coalesce(sum((detail->>'output_tokens')::int), 0)          AS out_toks,
            coalesce(sum((detail->>'cache_creation_tokens')::int), 0)  AS cache_write_toks,
            coalesce(sum((detail->>'cache_read_tokens')::int), 0)      AS cache_read_toks,
            coalesce(sum((detail->>'cost_micro_usd')::bigint), 0)      AS cost_micro_usd
        FROM audit_chain
        WHERE action = 'anthropic_api_call'
          AND ts >= :since
    """), {"since": _PASS_START}).fetchone()
    usd = round((rows[4] or 0) / 1_000_000, 4)
    return {"in_toks": rows[0], "out_toks": rows[1], "cache_write_toks": rows[2], "cache_read_toks": rows[3], "usd": usd}



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_PASS_START = datetime.now(UTC)


def main() -> None:
    parser = argparse.ArgumentParser(description="Curator credit pass for APT29 evaluation")
    parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=None,
        help="Limit execution to top N open incidents ordered by priority",
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        default=6.0,
        help="Abort if cumulative estimated cost exceeds this many USD (default: 6.0)",
    )
    args = parser.parse_args()

    print(f"Credit pass started at {_PASS_START.isoformat()}")
    if args.limit:
        print(f"Processing top {args.limit} incident(s) by priority")
    print(f"Max-cost guard: ${args.max_cost:.2f}")
    print("=" * 70)

    with SessionLocal() as session:
        incident_ids = _open_incidents(session, limit=args.limit)
        print(f"Open incidents: {len(incident_ids)} — {incident_ids}")

        if not incident_ids:
            print("No open incidents matching criteria.")
            sys.exit(1)

        # ------------------------------------------------------------------
        # Step 1: Narrative generation
        # ------------------------------------------------------------------
        print("\n[1/4] Narrative generation")
        narr_results: dict[int, dict] = {}
        for i, iid in enumerate(incident_ids, 1):
            if _already_done(session, iid):
                n = session.execute(text(
                    "SELECT COUNT(*) FROM narrative_sentences WHERE incident_id = :id"
                ), {"id": iid}).scalar()
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: SKIP ({n} sentences already exist)")
                continue
            t0 = time.time()
            try:
                result = generate_incident_narrative(iid, session=session)
                elapsed = round(time.time() - t0, 1)
                n_sent = len(result.get("sentences", []))
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: {n_sent} sentences in {elapsed}s")
                narr_results[iid] = result
            except Exception as exc:
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: ERROR — {exc}", file=sys.stderr)
                print("  Continuing with next incident (this one will be skipped in mapping).",
                      file=sys.stderr)
            # --- cumulative cost guard ---
            spend = _cost_from_audit(session)
            if spend["usd"] > args.max_cost:
                print(
                    f"\n  COST GUARD TRIGGERED after #{iid}: ${spend['usd']:.4f} exceeds "
                    f"--max-cost ${args.max_cost:.2f}. Aborting.",
                    file=sys.stderr,
                )
                sys.exit(2)

        # ------------------------------------------------------------------
        # Step 2: ATT&CK mapping
        # ------------------------------------------------------------------
        print("\n[2/4] ATT&CK technique mapping")
        for i, iid in enumerate(incident_ids, 1):
            n_sent = session.execute(text(
                "SELECT COUNT(*) FROM narrative_sentences WHERE incident_id = :id AND technique_id IS NULL"
            ), {"id": iid}).scalar() or 0
            if n_sent == 0:
                # Already mapped or no sentences
                already_mapped = session.execute(text(
                    "SELECT COUNT(*) FROM narrative_sentences WHERE incident_id = :id AND technique_id IS NOT NULL"
                ), {"id": iid}).scalar() or 0
                if already_mapped > 0:
                    print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: SKIP (already mapped)")
                continue
            t0 = time.time()
            try:
                result = map_incident_techniques(iid, session=session)
                elapsed = round(time.time() - t0, 1)
                n_mapped = result.get("mapped_count", 0)
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: {n_mapped} mapped in {elapsed}s")
            except Exception as exc:
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: ERROR — {exc}", file=sys.stderr)
            # --- cumulative cost guard ---
            spend = _cost_from_audit(session)
            if spend["usd"] > args.max_cost:
                print(
                    f"\n  COST GUARD TRIGGERED after #{iid}: ${spend['usd']:.4f} exceeds "
                    f"--max-cost ${args.max_cost:.2f}. Aborting.",
                    file=sys.stderr,
                )
                sys.exit(2)

        # ------------------------------------------------------------------
        # Step 3: Sentence verification
        # ------------------------------------------------------------------
        print("\n[3/4] Sentence verification")
        verify_results: dict[int, dict] = {}
        for i, iid in enumerate(incident_ids, 1):
            n_sent = session.execute(text(
                "SELECT COUNT(*) FROM narrative_sentences WHERE incident_id = :id"
            ), {"id": iid}).scalar() or 0
            if n_sent == 0:
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: SKIP (no sentences)")
                continue
            n_unverified = session.execute(text(
                """
                SELECT COUNT(*)
                FROM narrative_sentences s
                LEFT JOIN verifications v ON v.sentence_id = s.id
                WHERE s.incident_id = :id AND v.id IS NULL
                """
            ), {"id": iid}).scalar() or 0
            if n_unverified == 0:
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: SKIP (already verified)")
                continue
            t0 = time.time()
            try:
                result = verify_incident(iid, session=session)
                elapsed = round(time.time() - t0, 1)
                supported   = result.get("supported", 0)
                unsupported = result.get("unsupported", 0)
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: "
                      f"{supported} supported / {unsupported} unsupported in {elapsed}s")
                verify_results[iid] = result
            except Exception as exc:
                print(f"  [{i:02d}/{len(incident_ids)}] #{iid}: ERROR — {exc}", file=sys.stderr)
            # --- cumulative cost guard ---
            spend = _cost_from_audit(session)
            if spend["usd"] > args.max_cost:
                print(
                    f"\n  COST GUARD TRIGGERED after #{iid}: ${spend['usd']:.4f} exceeds "
                    f"--max-cost ${args.max_cost:.2f}. Aborting.",
                    file=sys.stderr,
                )
                sys.exit(2)

        # ------------------------------------------------------------------
        # Step 4: Accuracy harness
        # ------------------------------------------------------------------
        print("\n[4/4] Accuracy harness")
        score = evaluate_accuracy(session)

        print("\n" + "=" * 70)
        print("SCOREBOARD")
        print("=" * 70)
        print(f"  Ground-truth techniques executed : {score.get('executed')}")
        print(f"  Recovered (in evidence)          : {score.get('recovered')}")
        print(f"  Not in evidence (false claims)   : {score.get('not_in_evidence')}")
        print(f"  Invented (beyond ground-truth)   : {score.get('invented_beyond_gt')}")
        print(f"  Precision                        : {score.get('precision')}")
        print(f"  Recall                           : {score.get('recall')}")
        print(f"  F1                               : {score.get('f1')}")

        # ------------------------------------------------------------------
        # Cost summary
        # ------------------------------------------------------------------
        cost = _cost_from_audit(session)
        print("\n" + "=" * 70)
        print("COST SUMMARY (this pass only)")
        print("=" * 70)
        print(f"  Input tokens         : {cost['in_toks']:,}")
        print(f"  Output tokens        : {cost['out_toks']:,}")
        print(f"  Cache write tokens   : {cost['cache_write_toks']:,}")
        print(f"  Cache read tokens    : {cost['cache_read_toks']:,}")
        print(f"  Total USD            : ${cost['usd']:.4f}")

        elapsed_total = round((datetime.now(UTC) - _PASS_START).total_seconds(), 1)
        print(f"\nPass completed in {elapsed_total}s")


if __name__ == "__main__":
    main()
