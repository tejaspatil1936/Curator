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
For each sentence, you are provided a strict whitelist of retrieved candidate ATT&CK techniques with their names and descriptions.

STRICT RULES:
1. You may ONLY choose a technique_id that appears in the candidate list for that sentence.
2. Select the best matching technique from the candidate list that accurately reflects the technical action and telemetry.
3. Decline (omit) ONLY when none of the candidate techniques genuinely fits the activity described. Do not decline merely due to minor uncertainty if a candidate directly matches the mechanism (e.g. PowerShell execution, web C2 beaconing, LSASS memory access, administrative shares, or WMI execution).
4. Return a JSON object with this exact structure:
{
  "mappings": [
    {
      "seq": 1,
      "technique_id": "T1059.001",
      "confidence": 0.90
    }
  ]
}
"""


def map_incident_techniques(
    incident_id: int,
    session: Session,
    k_candidates: int = 20,
) -> dict[str, Any]:
    """Ground and map narrative sentences to ATT&CK techniques."""
    logger.info("Mapping ATT&CK techniques for incident #%d (k=%d)", incident_id, k_candidates)

    # 1. Fetch narrative sentences for this incident
    q_sentences = text("""
        SELECT id, seq, text, evidence_event_ids
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

    # 2. Retrieve candidates per sentence using hybrid search enriched with cited event context
    candidates_by_seq: dict[int, list[Candidate]] = {}
    valid_tech_ids_by_seq: dict[int, set[str]] = {}
    tech_name_lookup: dict[str, str] = {}

    sentence_candidate_blocks: list[str] = []

    for s in sentences:
        seq = s.seq
        txt = s.text
        eids = s.evidence_event_ids or []

        # Gather concrete telemetry context from cited events to enrich retrieval query
        context_terms: list[str] = []
        if eids:
            q_ctx = text("""
                SELECT process_name, command_line, file_path, dst_ip,
                       ocsf->'dst_endpoint'->>'port' as port, event_code,
                       ocsf->'unmapped'->>'ShareName' as share_name
                FROM events
                WHERE id = ANY(:eids)
                LIMIT 10
            """)
            ctx_rows = session.execute(q_ctx, {"eids": eids}).fetchall()
            for cr in ctx_rows:
                if cr[0]: context_terms.append(str(cr[0]))
                if cr[1]: context_terms.append(str(cr[1]))
                if cr[2]: context_terms.append(str(cr[2]))
                if cr[3]: context_terms.append(str(cr[3]))
                if cr[4]: context_terms.append(f"port {cr[4]}")
                if cr[5]: context_terms.append(f"event {cr[5]}")
                if cr[6]: context_terms.append(f"share {cr[6]}")

        enriched_query = f"{txt} {' '.join(context_terms[:15])}".strip()

        # Hybrid retrieval over pgvector embeddings & keyword search (k=20)
        cands = retrieve(enriched_query, k=k_candidates, conn=session.connection())
        candidates_by_seq[seq] = cands
        valid_tech_ids_by_seq[seq] = {c.id for c in cands}

        # Fetch descriptions for candidate techniques to give the model full semantic context
        cand_ids = [c.id for c in cands]
        q_desc = text("SELECT id, name, description FROM techniques WHERE id = ANY(:ids)")
        desc_rows = session.execute(q_desc, {"ids": cand_ids}).fetchall()
        desc_lookup = {r[0]: (r[2] or "")[:180] for r in desc_rows}
        for r in desc_rows:
            tech_name_lookup[r[0]] = r[1]

        c_lines = []
        for c in cands:
            tech_name_lookup.setdefault(c.id, c.name)
            desc_snippet = desc_lookup.get(c.id, "")
            desc_str = f" - {desc_snippet}..." if desc_snippet else ""
            c_lines.append(
                f"    - {c.id}: {c.name} (tactics: {', '.join(c.tactics)}){desc_str}"
            )

        c_text = "\n".join(c_lines)
        sentence_candidate_blocks.append(
            f"Sentence {seq}: \"{txt}\"\n  Candidate Whitelist ({len(cands)} techniques):\n{c_text}"
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
        raw_tech = m.get("technique_id")
        conf = float(m.get("confidence", 0.8))

        if seq not in valid_tech_ids_by_seq:
            continue

        if not raw_tech or str(raw_tech).strip().upper() in ("", "NONE", "NULL"):
            # Model declined this sentence because no candidate genuinely fits
            continue

        tech_id = str(raw_tech).strip().upper()
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
