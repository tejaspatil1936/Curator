"""One-shot script: destructive rebuild of the full pipeline.

This explicitly calls rebuild=True, force=True because it is intended
for clean-slate re-seeding only. Do NOT use this after generating
narratives — use POST /pipeline/run instead.
"""
import logging
import sys

logging.basicConfig(level=logging.WARNING)

from curator.db import SessionLocal
import curator.pipeline.runner as _runner

with SessionLocal() as session:
    narrative_count = session.execute(
        __import__("sqlalchemy").text("SELECT COUNT(*) FROM narrative_sentences")
    ).scalar() or 0
    if narrative_count > 0:
        print(
            f"WARNING: {narrative_count} narrative sentence(s) exist and will be discarded.",
            file=sys.stderr,
        )
        print("Proceeding with force=True as this script is an explicit rebuild tool.",
              file=sys.stderr)

    result = _runner.run_pipeline(session, rebuild=True, force=True)
    print("total_alerts_fired:", result["total_alerts_fired"])
    print("surfaced_incidents:", result["surfaced_incidents"])
    print("suppressed_incidents:", result["suppressed_incidents"])
