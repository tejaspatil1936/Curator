"""Narrative generation engine (system_design.md §7.2 & Step 4c).

Uses Claude Sonnet 5 to synthesize a factual, evidence-grounded incident narrative.
- Input: alerts and bounded evidence set with evidence_selection_reason.
- Output: strict JSON with title and numbered sentences citing supporting evidence_event_ids.
- Validation: drops any hallucinated event IDs not in the incident's event set.
- Sentences with zero valid IDs are retained with empty array [] (rendered as struck-through).
- Records all sentences in narrative_sentences table.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.ai.client import call_claude
from curator.config import MODEL_SONNET
from curator.pipeline.evidence import fetch_incident_evidence

logger = logging.getLogger(__name__)

_NARRATIVE_SYSTEM_PROMPT = """You are a senior digital forensics investigator writing a precise incident narrative for a security operations center.
Your task is to review the chronological events and security alerts for an incident and produce an executive title and a concise, numbered sequence of narrative sentences.

STRICT FACTUAL GROUNDING RULES:
1. Describe ONLY actions and facts directly demonstrated by the provided telemetry events.
2. NEVER speculate, assume intent, or extrapolate steps not present in the events.
3. NEVER state a timestamp or host that is not explicitly present in the supporting events.
4. For every sentence, provide the exact IDs of the specific events that prove that sentence in `evidence_event_ids`.
5. Maintain strictly chronological order matching the sequence of events.
6. The output must be pure JSON conforming to the schema:
{
  "title": "<Brief title describing the core incident>",
  "sentences": [
    {
      "seq": 1,
      "text": "<Sentence describing the factual event step>",
      "evidence_event_ids": [<integer event id>, ...]
    }
  ]
}
"""


def generate_incident_narrative(
    incident_id: int,
    session: Session,
) -> dict[str, Any]:
    """Generate and validate an evidence-grounded narrative for an incident."""
    logger.info("Generating narrative for incident #%d", incident_id)

    # 1. Fetch incident metadata and alert event IDs
    q_inc = text("""
        SELECT id, first_seen, last_seen, hosts, users, raw_alert_count, priority
        FROM incidents
        WHERE id = :id
    """)
    inc = session.execute(q_inc, {"id": incident_id}).fetchone()
    if not inc:
        raise ValueError(f"Incident {incident_id} does not exist")

    q_alerts = text("""
        SELECT a.event_id, a.rule_id, a.rule_name, a.severity, a.host, a.user_norm,
               e.command_line, e.process_name, e.ts
        FROM alerts a
        JOIN events e ON a.event_id = e.id
        WHERE a.incident_id = :id
        ORDER BY a.ts ASC
    """)
    alert_rows = session.execute(q_alerts, {"id": incident_id}).fetchall()
    alert_event_ids = list({r[0] for r in alert_rows})

    # 2. Fetch bounded evidence set
    evidence_events = fetch_incident_evidence(session, alert_event_ids)
    all_valid_event_ids: set[int] = {e["id"] for e in evidence_events}

    # 3. Format event corpus for model with prompt caching blocks
    # Cacheable corpus block
    corpus_lines: list[str] = [
        f"Incident #{incident_id} Telemetry Corpus ({len(evidence_events)} events):"
    ]
    for ev in evidence_events:
        reason = ev.get("evidence_selection_reason", "context")
        cmd = ev.get("command_line") or ""
        proc = ev.get("process_name") or ""
        ts_str = ev["ts"].isoformat() if hasattr(ev["ts"], "isoformat") else str(ev["ts"])
        corpus_lines.append(
            f"- Event ID={ev['id']} | TS={ts_str} | Host={ev.get('host')} | "
            f"User={ev.get('user_name')} | Proc={proc} | Cmd={cmd} | Reason={reason} | Code={ev.get('event_code')}"
        )
    corpus_text = "\n".join(corpus_lines)

    # Alerts summary block
    alert_lines: list[str] = [f"Alerts Triggered ({len(alert_rows)}):"]
    for a in alert_rows:
        alert_lines.append(
            f"- Event ID={a[0]} | Rule={a[1]} ({a[2]}) | Sev={a[3]} | Host={a[4]} | User={a[5]}"
        )
    alerts_text = "\n".join(alert_lines)

    system_blocks = [
        {
            "type": "text",
            "text": _NARRATIVE_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    user_blocks = [
        {
            "type": "text",
            "text": f"{alerts_text}\n\n{corpus_text}",
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "text",
            "text": f"Generate the structured JSON narrative for Incident #{incident_id}.",
        },
    ]

    # 4. Call Claude via AI client gateway
    resp = call_claude(
        model=MODEL_SONNET,
        system_blocks=system_blocks,
        user_blocks=user_blocks,
        max_tokens=2048,
        session=session,
        incident_id=incident_id,
        task_name="narrative",
    )

    raw_content = resp["content"].strip()
    # Strip markdown code fences if model enclosed JSON
    if raw_content.startswith("```"):
        raw_content = raw_content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

    try:
        parsed_data = json.loads(raw_content)
    except json.JSONDecodeError as err:
        logger.error("Failed to parse JSON narrative response: %s\nContent: %s", err, raw_content)
        parsed_data = {
            "title": f"Incident #{incident_id}",
            "sentences": [
                {"seq": 1, "text": "Telemetry analysis detected anomalous activity.", "evidence_event_ids": []}
            ],
        }

    title = parsed_data.get("title") or f"Incident #{incident_id}"
    sentences_raw = parsed_data.get("sentences") or []

    # 5. Strict Python Validation of Evidence Event IDs
    dropped_ids_count = 0
    total_ids_count = 0
    validated_sentences: list[dict[str, Any]] = []

    for item in sentences_raw:
        seq = int(item.get("seq", len(validated_sentences) + 1))
        text_content = str(item.get("text", "")).strip()
        claimed_ids = item.get("evidence_event_ids") or []

        valid_ids: list[int] = []
        for eid in claimed_ids:
            total_ids_count += 1
            if eid in all_valid_event_ids:
                valid_ids.append(int(eid))
            else:
                dropped_ids_count += 1
                logger.warning(
                    "Incident #%d dropped invalid hallucinated evidence ID %s (not in incident events)",
                    incident_id,
                    eid,
                )

        validated_sentences.append({
            "seq": seq,
            "text": text_content,
            "evidence_event_ids": valid_ids,
        })

    logger.info(
        "Incident #%d narrative validation: %d sentences, %d dropped IDs / %d claimed IDs",
        incident_id,
        len(validated_sentences),
        dropped_ids_count,
        total_ids_count,
    )

    # 6. Store title to incidents and sentences to narrative_sentences table
    session.execute(
        text("UPDATE incidents SET title = :title WHERE id = :id"),
        {"title": title, "id": incident_id},
    )

    # Delete existing sentences for idempotency
    session.execute(
        text("DELETE FROM narrative_sentences WHERE incident_id = :id"),
        {"id": incident_id},
    )

    q_insert_sentence = text("""
        INSERT INTO narrative_sentences (
            incident_id, seq, text, evidence_event_ids, generated_by
        ) VALUES (
            :incident_id, :seq, :text, :evidence_event_ids, :generated_by
        )
    """)

    for s in validated_sentences:
        session.execute(
            q_insert_sentence,
            {
                "incident_id": incident_id,
                "seq": s["seq"],
                "text": s["text"],
                "evidence_event_ids": s["evidence_event_ids"],
                "generated_by": MODEL_SONNET,
            },
        )

    session.commit()

    return {
        "incident_id": incident_id,
        "title": title,
        "sentences": validated_sentences,
        "dropped_ids_count": dropped_ids_count,
        "total_claimed_ids": total_ids_count,
        "valid_ids_count": total_ids_count - dropped_ids_count,
        "usage": {
            "input_tokens": resp["input_tokens"],
            "output_tokens": resp["output_tokens"],
            "cache_read_tokens": resp["cache_read_tokens"],
            "cache_creation_tokens": resp["cache_creation_tokens"],
            "cost_usd": resp["estimated_cost_usd"],
        },
    }
