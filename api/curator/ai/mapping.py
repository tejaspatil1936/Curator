"""ATT&CK technique mapping engine (system_design.md §5.6, §7.3 & Step 4d).

Retrieval-grounded mapping of narrative sentences to MITRE ATT&CK techniques:
1. For each sentence, retrieves top-k candidates via hybrid retrieval (attack/retrieve.py).
2. Sends candidate list to Claude Sonnet 5.
3. The model selects a matching candidate or declines (no forced mappings).
4. Strict Python validation: any technique_id not in the candidate set is rejected.
5. Updates narrative_sentences with technique_id, technique_name, and confidence.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.ai.client import call_claude
from curator.attack.retrieve import Candidate, retrieve
from curator.config import MODEL_SONNET

logger = logging.getLogger(__name__)

_MAPPING_SYSTEM_PROMPT = """You are a MITRE ATT&CK expert mapping incident narrative sentences to specific techniques.
For each sentence, you are provided a strict whitelist of retrieved candidate ATT&CK techniques.

STRICT RULES:
1. You may ONLY choose a technique_id that appears in the candidate list for that sentence.
2. If none of the candidate techniques accurately describes the specific technical action in the sentence, DO NOT map it (decline).
3. Return a JSON object with this exact structure:
{
  "mappings": [
    {
      "seq": 1,
      "technique_id": "T1059.001",
      "confidence": 0.90
    }
  ]
}
If a sentence has no appropriate match, simply omit it from the mappings array.
"""


def map_incident_techniques(
    incident_id: int,
    session: Session,
    k_candidates: int = 10,
) -> dict[str, Any]:
    """Ground and map narrative sentences to ATT&CK techniques."""
    logger.info("Mapping ATT&CK techniques for incident #%d", incident_id)

    # 1. Fetch narrative sentences for this incident
    q_sentences = text("""
        SELECT id, seq, text
        FROM narrative_sentences
        WHERE incident_id = :inc_id
        ORDER BY seq ASC
    """)
    sentences = session.execute(q_sentences, {"inc_id": incident_id}).fetchall()
    if not sentences:
        logger.warning("No narrative sentences found for incident #%d to map", incident_id)
        return {
            "mapped_count": 0,
            "declined_count": 0,
            "rejected_out_of_candidates_count": 0,
            "mappings": [],
        }

    # 2. Retrieve candidates per sentence using hybrid search
    candidates_by_seq: dict[int, list[Candidate]] = {}
    valid_tech_ids_by_seq: dict[int, set[str]] = {}
    tech_name_lookup: dict[str, str] = {}

    sentence_candidate_blocks: list[str] = []

    for s in sentences:
        seq = s.seq
        txt = s.text
        # Hybrid retrieval over pgvector embeddings & keyword search
        cands = retrieve(txt, k=k_candidates, conn=session.connection())
        candidates_by_seq[seq] = cands
        valid_tech_ids_by_seq[seq] = {c.id for c in cands}
        for c in cands:
            tech_name_lookup[c.id] = c.name

        c_text = "\n".join(
            f"    - {c.id}: {c.name} (tactics: {', '.join(c.tactics)}) [RRF Score: {c.score:.4f}]"
            for c in cands
        )
        sentence_candidate_blocks.append(
            f"Sentence {seq}: \"{txt}\"\n  Candidate Whitelist:\n{c_text}"
        )

    prompt_corpus = "\n\n".join(sentence_candidate_blocks)

    system_blocks = [
        {
            "type": "text",
            "text": _MAPPING_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    user_blocks = [
        {
            "type": "text",
            "text": prompt_corpus,
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "text",
            "text": f"Select the best matching ATT&CK technique from the candidate whitelists for each sentence of Incident #{incident_id}, or omit if none apply.",
        },
    ]

    # 3. Call Claude via AI client gateway
    resp = call_claude(
        model=MODEL_SONNET,
        system_blocks=system_blocks,
        user_blocks=user_blocks,
        max_tokens=1024,
        session=session,
        incident_id=incident_id,
        task_name="mapping",
    )

    raw_content = resp["content"].strip()
    if raw_content.startswith("```"):
        raw_content = raw_content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

    try:
        parsed_data = json.loads(raw_content)
    except json.JSONDecodeError as err:
        logger.error("Failed to parse ATT&CK mapping JSON: %s\nContent: %s", err, raw_content)
        parsed_data = {"mappings": []}

    raw_mappings = parsed_data.get("mappings") or []

    # 4. Strict Python Validation against candidate sets
    mapped_count = 0
    rejected_out_of_candidates = 0
    mapped_seqs: set[int] = set()
    final_mappings: list[dict[str, Any]] = []

    for m in raw_mappings:
        seq = int(m.get("seq", 0))
        tech_id = str(m.get("technique_id", "")).strip().upper()
        conf = float(m.get("confidence", 0.8))

        if seq not in valid_tech_ids_by_seq:
            continue

        allowed_ids = valid_tech_ids_by_seq[seq]
        if tech_id not in allowed_ids:
            rejected_out_of_candidates += 1
            logger.warning(
                "Incident #%d Seq %d: Rejected technique %s (not in candidate whitelist %s)",
                incident_id,
                seq,
                tech_id,
                sorted(allowed_ids),
            )
            continue

        mapped_count += 1
        mapped_seqs.add(seq)
        tech_name = tech_name_lookup.get(tech_id, tech_id)

        # Update narrative sentence record
        session.execute(
            text("""
                UPDATE narrative_sentences
                SET technique_id = :tid,
                    technique_name = :tname,
                    technique_conf = :tconf
                WHERE incident_id = :inc_id AND seq = :seq
            """),
            {
                "tid": tech_id,
                "tname": tech_name,
                "tconf": conf,
                "inc_id": incident_id,
                "seq": seq,
            },
        )

        final_mappings.append({
            "seq": seq,
            "technique_id": tech_id,
            "technique_name": tech_name,
            "confidence": conf,
        })

    session.commit()

    declined_count = len(sentences) - len(mapped_seqs)

    logger.info(
        "Incident #%d ATT&CK mapping complete: %d mapped, %d declined, %d rejected out-of-candidates",
        incident_id,
        mapped_count,
        declined_count,
        rejected_out_of_candidates,
    )

    return {
        "incident_id": incident_id,
        "total_sentences": len(sentences),
        "mapped_count": mapped_count,
        "declined_count": declined_count,
        "rejected_out_of_candidates_count": rejected_out_of_candidates,
        "mappings": final_mappings,
        "usage": {
            "input_tokens": resp["input_tokens"],
            "output_tokens": resp["output_tokens"],
            "cache_read_tokens": resp["cache_read_tokens"],
            "cache_creation_tokens": resp["cache_creation_tokens"],
            "cost_usd": resp["estimated_cost_usd"],
        },
    }
