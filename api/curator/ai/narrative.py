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
import re
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
2. PREFER SPECIFIC OVER SUMMARY: Detail exact concrete values from the telemetry—process names, target processes, full command lines, file paths, destination IP addresses, destination ports, share names, registry keys, and exact timestamps. For example: "PowerShell on SCRANTON connected to 192.168.0.4:443 fourteen times between 03:08:12 and 03:14:40" beats "established C2 beaconing."
3. EXACT TIMESTAMPS: Always state exact timestamps taken directly from the events (e.g. '02:55:56.151 UTC' or 'between 03:11:40 and 03:15:03 UTC'). Never use rounded, approximate, or estimated time ranges, and never write malformed relative offsets like '03:610 seconds later'.
4. NO IP CHARACTERIZATION: Do not characterize IP addresses as 'internal' or 'external' (e.g. 192.168.x.x, 10.x.x.x)—simply state the exact IP address and port.
5. ONE STEP PER SENTENCE: Do not merge disparate steps (e.g. discovery, network share access, and lateral movement) into a single high-level line. Break each technical action into its own chronological sentence.
6. FACTUAL GROUNDING: Describe ONLY actions and facts directly demonstrated by the provided telemetry events. NEVER speculate or extrapolate unobserved steps.
7. CITATION BOUNDARY: Every ID in `evidence_event_ids` MUST be an exact Event ID from the provided Incident Telemetry Corpus. Never invent or synthesize event IDs.
8. TARGET LENGTH GUIDANCE: Produce 12–25 sentences for a large incident (many alerts/hosts), and 2–5 sentences for a small incident.
9. QUOTING COMMAND LINES AND FILE PATHS: When including a command line, file path, or executable argument inside sentence text, do NOT wrap it in double-quote characters. State it bare (e.g. C:\ProgramData\victim\cod.3aka3.scr /S) or use single quotes (e.g. 'cmd /c whoami'). Double quotes inside a JSON string value break the JSON envelope and MUST be avoided.

EXPLICIT PROHIBITIONS (MANDATORY):
- NO NEGATIVE CORPUS CLAIMS: NEVER state negative claims about the broader corpus (e.g. NEVER write "No further corroborating events are present in the corpus", "No additional telemetry was observed"). Describe ONLY the positive activity actually captured in the events.
- NO INTENT OR TRADECRAFT ASSERTIONS: Do NOT speculate on intent or attribute tradecraft (e.g. NEVER write "consistent with known tradecraft for lateral movement", "indicating preparation for account manipulation", "likely for defense evasion", "consistent with credential-dumping activity"). State the raw technical action that occurred, not its supposed strategic motivation or tradecraft alignment.
- NO ALERT METADATA CLAIMS: Do NOT cite internal alert rule identifiers, severities, or detection reasons (e.g. NEVER write "triggered critical alert CUR-005", "high-severity alert", "logged with reason 'alerting'"). Rule IDs and severities are Curator's own labels, not facts in the telemetry. The model should describe the observed behaviour (e.g. "Process X accessed memory of lsass.exe"), never the alert that fired on it.

Output format MUST be pure JSON conforming to:
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


# ---------------------------------------------------------------------------
# Tolerant JSON repair — sentence-by-sentence scanner
# ---------------------------------------------------------------------------

def _repair_narrative_json(raw: str, incident_id: int) -> dict | None:
    """Two-pass repair for malformed narrative JSON.

    Pass 1: strip the outermost envelope and close the array, then re-parse.
    Pass 2: if pass 1 also fails, scan for individual sentence objects with a
            regex and decode each independently — one bad sentence loses only
            itself, not the whole narrative.

    Returns a dict with 'title' and 'sentences' on success, None on total failure.
    """
    # Extract title from preamble (very likely well-formed)
    title: str = f"Incident #{incident_id}"
    title_match = re.search(r'"title"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
    if title_match:
        try:
            # Re-parse the captured group as a JSON string literal to handle escapes
            title = json.loads('"' + title_match.group(1) + '"')
        except Exception:
            title = title_match.group(1)

    # ------------------------------------------------------------------
    # Pass 1: close the JSON array if it's just truncated / trailing-comma
    # ------------------------------------------------------------------
    last_brace = raw.rfind("}")
    if last_brace != -1:
        candidate = raw[: last_brace + 1].strip()
        if not candidate.endswith("]}"):
            candidate = candidate.rstrip(" ,\n") + "\n]}"
        try:
            data = json.loads(candidate)
            n = len(data.get("sentences", []))
            logger.info(
                "Incident #%d JSON pass-1 repair recovered %d sentences.", incident_id, n
            )
            return data
        except Exception:
            pass  # fall through to pass 2

    # ------------------------------------------------------------------
    # Pass 2: sentence-by-sentence tolerant scan
    # Each sentence object must have "seq", "text", and "evidence_event_ids".
    # We find every {...} blob that contains all three keys and try to parse
    # it individually.  Objects that fail are logged and skipped.
    # ------------------------------------------------------------------
    # Grab everything from the opening '[' of the sentences array onward
    array_start = raw.find('"sentences"')
    search_region = raw[array_start:] if array_start != -1 else raw

    sentences: list[dict] = []
    skipped = 0

    # Find candidate JSON objects: greedily match from '{' to a balanced '}'
    depth = 0
    obj_start: int | None = None
    for i, ch in enumerate(search_region):
        if ch == "{":
            if depth == 0:
                obj_start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and obj_start is not None:
                blob = search_region[obj_start: i + 1]
                # Only attempt sentence objects (must have all three fields)
                if '"seq"' in blob and '"text"' in blob and '"evidence_event_ids"' in blob:
                    try:
                        obj = json.loads(blob)
                        if isinstance(obj.get("seq"), int) and isinstance(obj.get("text"), str):
                            sentences.append(obj)
                    except Exception as e:
                        skipped += 1
                        logger.warning(
                            "Incident #%d pass-2 scanner: skipped malformed sentence object "
                            "(blob length %d): %s",
                            incident_id, len(blob), e,
                        )
                obj_start = None

    if sentences:
        logger.info(
            "Incident #%d JSON pass-2 scanner recovered %d sentences, skipped %d malformed.",
            incident_id, len(sentences), skipped,
        )
        return {"title": title, "sentences": sentences}

    logger.error(
        "Incident #%d JSON pass-2 scanner found 0 valid sentences (skipped %d).",
        incident_id, skipped,
    )
    return None


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
    from curator.ai.verify import format_forensic_event

    corpus_lines: list[str] = [
        f"Incident #{incident_id} Telemetry Corpus ({len(evidence_events)} events):"
    ]
    for ev in evidence_events:
        reason = ev.get("evidence_selection_reason", "context")
        corpus_lines.append(f"- {format_forensic_event(ev)} | Reason={reason}")
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
        logger.warning(
            "Incident #%d direct JSON decode failed: %s. Attempting structured repair.",
            incident_id, err,
        )
        parsed_data = _repair_narrative_json(raw_content, incident_id)

    if not parsed_data:
        logger.error(
            "Incident #%d all JSON recovery paths failed. Using empty sentinel.",
            incident_id,
        )
        parsed_data = {
            "title": f"Incident #{incident_id}",
            "sentences": [],
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

