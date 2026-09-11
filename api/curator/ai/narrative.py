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

_NARRATIVE_SYSTEM_PROMPT = """You are a senior digital forensics investigator writing a comprehensive, evidence-grounded incident narrative for a security operations center.
Your task is to review the chronological events and security alerts for an incident and produce an executive title and a detailed, numbered sequence of forensic narrative sentences.

STRICT FORENSIC GROUNDING & CITATION RULES:
1. CITE EVERY SUPPORTING EVENT: Every sentence MUST cite ALL events that support or demonstrate that claim in `evidence_event_ids`. For repeated connections, multiple share accesses, or multi-host activity, cite EVERY relevant event ID from the corpus, NEVER just a single representative ID.
2. PREFER SPECIFIC OVER SUMMARY: Detail exact concrete values from the telemetry—process names, full command lines, file paths, destination IP addresses, destination ports, and exact timestamps. For example: "PowerShell on SCRANTON connected to 192.168.0.4:443 fourteen times between 03:08:12 and 03:14:40" beats "established C2 beaconing."
3. EXACT TIMESTAMPS: Always state exact timestamps taken directly from the events (e.g. '02:55:56.151 UTC' or 'between 03:11:40 and 03:15:03 UTC'). Never use rounded, approximate, or estimated time ranges.
4. NO IP CHARACTERIZATION: Do not characterize IP addresses as 'internal' or 'external' (e.g. 192.168.x.x, 10.x.x.x)—simply state the exact IP address and port.
5. ONE STEP PER SENTENCE: Do not merge disparate steps (e.g. discovery, network share access, and lateral movement) into a single high-level line. Break each technical action into its own chronological sentence.
6. FACTUAL GROUNDING: Describe ONLY actions and facts directly demonstrated by the provided telemetry events. NEVER speculate or extrapolate unobserved steps.
7. CITATION BOUNDARY: Every ID in `evidence_event_ids` MUST be an exact Event ID from the provided Incident Telemetry Corpus. Never invent or synthesize event IDs.
8. TARGET LENGTH GUIDANCE: Produce 12–25 sentences for a large incident (many alerts/hosts), and 2–5 sentences for a small incident.
9. Output format MUST be pure JSON conforming to:
{
  "title": "<Concise executive title describing the incident narrative>",
  "sentences": [
    {
      "seq": 1,
      "text": "<Specific forensic description using concrete values>",
      "evidence_event_ids": [<integer event id>, <integer event id>, ...]
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
        max_tokens=8192,
        session=session,
        incident_id=incident_id,
        task_name="narrative",
    )

    raw_content = resp["content"].strip()
    # Strip markdown code fences if model enclosed JSON
    if raw_content.startswith("```"):
        raw_content = raw_content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

    parsed_data = None
    try:
        parsed_data = json.loads(raw_content)
    except json.JSONDecodeError as err:
        logger.warning("Direct JSON decode failed: %s. Attempting graceful repair.", err)
        # Find the last complete sentence object
        last_brace = raw_content.rfind("}")
        if last_brace != -1:
            candidate = raw_content[:last_brace + 1].strip()
            if not candidate.endswith("]}"):
                candidate = candidate.rstrip(" ,") + "\n]}"
            try:
                parsed_data = json.loads(candidate)
                logger.info("Successfully recovered truncated JSON with %d sentences", len(parsed_data.get("sentences", [])))
            except Exception as repair_err:
                logger.error("JSON repair also failed: %s", repair_err)

    if not parsed_data:
        logger.error("Failed to parse JSON narrative response:\nContent: %s", raw_content[:500])
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
    dropped_details: list[dict[str, Any]] = []
    validated_sentences: list[dict[str, Any]] = []

    for idx, item in enumerate(sentences_raw, start=1):
        seq = idx
        text_content = str(item.get("text", "")).strip()
        claimed_ids = item.get("evidence_event_ids") or []

        valid_ids: list[int] = []
        sentence_dropped: list[int] = []
        for eid in claimed_ids:
            total_ids_count += 1
            if eid in all_valid_event_ids:
                valid_ids.append(int(eid))
            else:
                dropped_ids_count += 1
                sentence_dropped.append(eid)
                logger.warning(
                    "Incident #%d dropped invalid hallucinated evidence ID %s (not in incident events)",
                    incident_id,
                    eid,
                )
        if sentence_dropped:
            dropped_details.append({
                "seq": seq,
                "text": text_content[:60],
                "invalid_ids": sentence_dropped,
            })

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

    ev_counts = [len(s["evidence_event_ids"]) for s in validated_sentences]
    import numpy as np
    mean_ev_ids = float(np.mean(ev_counts)) if ev_counts else 0.0
    median_ev_ids = float(np.median(ev_counts)) if ev_counts else 0.0

    return {
        "incident_id": incident_id,
        "title": title,
        "sentences": validated_sentences,
        "dropped_ids_count": dropped_ids_count,
        "dropped_details": dropped_details,
        "total_claimed_ids": total_ids_count,
        "valid_ids_count": total_ids_count - dropped_ids_count,
        "mean_evidence_ids_per_sentence": mean_ev_ids,
        "median_evidence_ids_per_sentence": median_ev_ids,
        "usage": {
            "input_tokens": resp["input_tokens"],
            "output_tokens": resp["output_tokens"],
            "cache_read_tokens": resp["cache_read_tokens"],
            "cache_creation_tokens": resp["cache_creation_tokens"],
            "cost_usd": resp["estimated_cost_usd"],
        },
    }

