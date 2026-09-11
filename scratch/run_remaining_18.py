"""Batch runner for the remaining 18 surfaced incidents.
Generates narrative and ATT&CK mapping live with strict validation and audit logging.
"""

from __future__ import annotations
import json
import logging
import time
import numpy as np
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("batch_runner")

REMAINING_INCIDENTS = [
    416, 418, 421, 423, 430, 431, 441, 444,
    477, 483, 490, 492, 495, 504, 505, 513, 521, 524
]

def run():
    print(f"Starting live run across {len(REMAINING_INCIDENTS)} remaining incidents...")
    print(f"Environment DRY_RUN: {settings.dry_run}")
    
    start_audit_id = None
    with SessionLocal() as session:
        r = session.execute(text("SELECT coalesce(max(id), 0) FROM audit_chain")).scalar()
        start_audit_id = r

    results = []
    for inc_id in REMAINING_INCIDENTS:
        t0 = time.time()
        print(f"\n[{inc_id}] Processing narrative...")
        with SessionLocal() as session:
            n_res = generate_incident_narrative(inc_id, session)
        
        print(f"[{inc_id}] Processing mapping...")
        with SessionLocal() as session:
            m_res = map_incident_techniques(inc_id, session, k_candidates=30)
            
        elapsed = time.time() - t0
        print(f"[{inc_id}] Done in {elapsed:.2f}s | Sentences: {n_res.get('sentence_count')} | Mapped: {m_res.get('mapped_count')} | Dropped IDs: {n_res.get('dropped_ids_count')}")
        results.append({
            "incident_id": inc_id,
            "sentence_count": n_res.get("sentence_count", 0),
            "dropped_ids": n_res.get("dropped_ids_count", 0),
            "mapped": m_res.get("mapped_count", 0),
            "declined": m_res.get("declined_count", 0),
            "rejected": m_res.get("rejected_out_of_candidates_count", 0),
        })

    print("\n" + "="*80)
    print("ALL 18 INCIDENTS COMPLETED")
    print("="*80)

if __name__ == "__main__":
    run()
