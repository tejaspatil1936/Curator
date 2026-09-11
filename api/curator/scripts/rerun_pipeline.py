"""Re-run the full deterministic pipeline to pick up CUR-021 and CUR-022."""
import logging
logging.basicConfig(level=logging.WARNING)

from curator.db import SessionLocal
import curator.pipeline.runner as _runner

with SessionLocal() as session:
    result = _runner.run_pipeline(session)
    print("Pipeline result:", result)

