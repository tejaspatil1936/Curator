"""Forensic claim verification engine (system_design.md §5.5 & Step 5a).

Evaluates whether narrative sentences are strictly supported by their cited
telemetry events using Claude Haiku 4.5.
Judges ONLY against the cited events.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.ai.client import call_claude
from curator.config import MODEL_HAIKU, VERIFY_MODEL

logger = logging.getLogger(__name__)

_VERIFY_SYSTEM_PROMPT = """You are an uncompromising, objective forensic evidence verifier for endpoint and network security incident response.
Your task is to determine whether each given claim in a batch of narrative sentences is factually supported by ONLY its cited evidence events.

Rules:
1. Judge ONLY against the cited events provided for that specific sentence. You do not have access to the broader corpus and must NEVER assume unseen supporting evidence exists.
2. Mark supported: true ONLY IF the cited events directly substantiate the specific factual claims made in the sentence (including the actions, processes, commands, hosts, users, network addresses, or forensic techniques claimed).
3. Mark supported: false when:
   - The sentence has no cited events at all.
   - The cited events do not show what the sentence claims (e.g., claiming credential dumping or LSASS memory access when the cited event shows a normal conhost.exe execution, or claiming Pass the Ticket when the citations are routine service logons).
   - The sentence asserts something broader than the cited evidence establishes (e.g., claiming activity occurred across multiple hosts or systems when the citations only cover one host, or claiming 14 outbound connections when only 2 are cited).
4. Provide a clear, concise reason (1-2 sentences) explaining why the claim is supported or why it is unsupported.

Output Contract:
Respond ONLY with a valid JSON object matching this exact structure:
{
  "results": [
    {
      "seq": <integer sequence number matching the sentence seq>,
      "supported": <true or false>,
      "reason": "<concise explanation>"
    }
  ]
}"""


def _format_evidence_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "None (0 events cited)"
    lines: list[str] = []
    for ev in events:
        cmd = ev.get("command_line") or ""
        proc = ev.get("process_name") or ""
        parent = ev.get("parent_process") or ""
        ts_val = ev.get("ts")
        ts_str = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)
        host = ev.get("host") or ""
        user = ev.get("user_name") or ""
        code = ev.get("event_code") or ""
        src_ip = ev.get("src_ip") or ""
        dst_ip = ev.get("dst_ip") or ""
        net_str = f" | Net={src_ip}->{dst_ip}" if (src_ip or dst_ip) else ""
        lines.append(
            f"- Event {ev['id']}: TS={ts_str} | Host={host} | User={user} | Proc={proc} | Parent={parent} | Cmd={cmd} | Code={code}{net_str}"
        )
    return "\n".join(lines)


def _fetch_events_by_ids(session: Session, event_ids: list[int]) -> dict[int, dict[str, Any]]:
    if not event_ids:
        return {}
    q = text("""
        SELECT id, ts, host, user_name, process_name, parent_process,
               command_line, event_code, src_ip, dst_ip
        FROM events
        WHERE id = ANY(:ids)
    """)
    rows = session.execute(q, {"ids": event_ids}).fetchall()
    return {r.id: dict(r._mapping) for r in rows}


def verify_batch(
    sentences: list[dict[str, Any]],
    session: Session,
    incident_id: int,
) -> list[dict[str, Any]]:
    """Verify a batch of up to 5 narrative sentences against their cited evidence."""
    if not sentences:
        return []

    # Collect all event IDs needed for this batch
    all_eids: list[int] = []
    for s in sentences:
        all_eids.extend(s.get("evidence_event_ids") or [])
    all_eids = list(set(all_eids))

    events_by_id = _fetch_events_by_ids(session, all_eids)

    # Format batch prompt
    batch_blocks: list[str] = [
        f"Evaluate the following {len(sentences)} sentence(s) from Incident #{incident_id} against their cited evidence:\n"
    ]
    for s in sentences:
        seq = s["seq"]
        stext = s["text"]
        eids = s.get("evidence_event_ids") or []
        ev_list = [events_by_id[eid] for eid in eids if eid in events_by_id]
        ev_text = _format_evidence_events(ev_list)
        batch_blocks.append(
            f"---\nSentence seq {seq}: \"{stext}\"\nCited Evidence ({len(ev_list)} events):\n{ev_text}\n"
        )

    user_prompt = "\n".join(batch_blocks)

    # Call Claude Haiku 4.5 (NO PROMPT CACHING: prompts are below cache threshold and write premium is a net loss)
    system_blocks = [{"type": "text", "text": _VERIFY_SYSTEM_PROMPT}]
    user_blocks = [{"type": "text", "text": user_prompt}]

    resp = call_claude(
        model=VERIFY_MODEL,
        system_blocks=system_blocks,
        user_blocks=user_blocks,
        max_tokens=1500,
        session=session,
        incident_id=incident_id,
        task_name="narrative_verification",
    )

    raw_content = resp["content"].strip()
    clean_content = re.sub(r"^```(?:json)?\s*", "", raw_content, flags=re.MULTILINE)
    clean_content = re.sub(r"\s*```$", "", clean_content, flags=re.MULTILINE).strip()

    try:
        parsed = json.loads(clean_content)
        results = parsed.get("results", [])
    except Exception as exc:
        logger.error("Failed to parse verifier response for incident #%d: %s; raw: %r", incident_id, exc, raw_content)
        # Fallback to conservative evaluation
        results = []

    results_by_seq = {r.get("seq"): r for r in results if isinstance(r, dict) and "seq" in r}

    verified_list: list[dict[str, Any]] = []
    for s in sentences:
        seq = s["seq"]
        r = results_by_seq.get(seq)
        if r:
            supported = bool(r.get("supported", False))
            reason = str(r.get("reason", "No reason provided."))
        else:
            # If model didn't return seq, check if evidence exists
            has_ev = bool(s.get("evidence_event_ids"))
            supported = False if not has_ev else True
            reason = "No cited evidence events." if not has_ev else "Verification response missing seq."

        verified_list.append(
            {
                "sentence_id": s["id"],
                "seq": seq,
                "text": s["text"],
                "evidence_event_ids": s.get("evidence_event_ids") or [],
                "supported": supported,
                "reason": reason,
                "model": VERIFY_MODEL,
            }
        )

    return verified_list


def verify_incident(
    incident_id: int,
    session: Session,
    batch_size: int = 5,
) -> dict[str, Any]:
    """Verify all narrative sentences for an incident and persist to verifications table."""
    logger.info("Starting verification for incident #%d (batch_size=%d)", incident_id, batch_size)

    # 1. Fetch narrative sentences
    q_sentences = text("""
        SELECT id, seq, text, evidence_event_ids
        FROM narrative_sentences
        WHERE incident_id = :inc_id
        ORDER BY seq ASC
    """)
    rows = session.execute(q_sentences, {"inc_id": incident_id}).fetchall()
    if not rows:
        logger.info("No narrative sentences found for incident #%d", incident_id)
        return {"incident_id": incident_id, "checked": 0, "supported": 0, "unsupported": 0, "results": []}

    sentences = [
        {
            "id": r.id,
            "seq": r.seq,
            "text": r.text,
            "evidence_event_ids": r.evidence_event_ids or [],
        }
        for r in rows
    ]

    # 2. Batch into groups of 5
    all_results: list[dict[str, Any]] = []
    for i in range(0, len(sentences), batch_size):
        batch = sentences[i : i + batch_size]
        batch_results = verify_batch(batch, session=session, incident_id=incident_id)
        all_results.extend(batch_results)

    # 3. Persist to verifications table per §5.5 (idempotent)
    sentence_ids = [s["id"] for s in sentences]
    session.execute(
        text("DELETE FROM verifications WHERE sentence_id = ANY(:sids)"),
        {"sids": sentence_ids},
    )

    q_insert = text("""
        INSERT INTO verifications (
            sentence_id, supported, reason, checked_ids, model, created_at
        ) VALUES (
            :sentence_id, :supported, :reason, :checked_ids, :model, now()
        )
    """)
    for r in all_results:
        session.execute(
            q_insert,
            {
                "sentence_id": r["sentence_id"],
                "supported": r["supported"],
                "reason": r["reason"],
                "checked_ids": r["evidence_event_ids"],
                "model": r["model"],
            },
        )

    session.commit()

    supported_count = sum(1 for r in all_results if r["supported"])
    unsupported_count = sum(1 for r in all_results if not r["supported"])

    logger.info(
        "Verification complete for incident #%d: %d checked (%d supported, %d unsupported)",
        incident_id,
        len(all_results),
        supported_count,
        unsupported_count,
    )

    return {
        "incident_id": incident_id,
        "checked": len(all_results),
        "supported": supported_count,
        "unsupported": unsupported_count,
        "results": all_results,
    }


def verify_all_incidents(
    session: Session,
    batch_size: int = 5,
) -> dict[str, Any]:
    """Verify all narrative sentences across all surfaced incidents."""
    q_inc_ids = text("""
        SELECT DISTINCT incident_id
        FROM narrative_sentences
        ORDER BY incident_id ASC
    """)
    inc_ids = [r[0] for r in session.execute(q_inc_ids).fetchall()]

    logger.info("Running verifier across %d incidents...", len(inc_ids))

    total_checked = 0
    total_supported = 0
    total_unsupported = 0
    incident_summaries: list[dict[str, Any]] = []
    unsupported_sentences: list[dict[str, Any]] = []

    for inc_id in inc_ids:
        summary = verify_incident(inc_id, session=session, batch_size=batch_size)
        total_checked += summary["checked"]
        total_supported += summary["supported"]
        total_unsupported += summary["unsupported"]
        incident_summaries.append(
            {
                "incident_id": inc_id,
                "checked": summary["checked"],
                "supported": summary["supported"],
                "unsupported": summary["unsupported"],
            }
        )
        for r in summary["results"]:
            if not r["supported"]:
                unsupported_sentences.append(
                    {
                        "incident_id": inc_id,
                        "sentence_id": r["sentence_id"],
                        "seq": r["seq"],
                        "text": r["text"],
                        "evidence_event_ids": r["evidence_event_ids"],
                        "reason": r["reason"],
                    }
                )

    return {
        "incidents_count": len(inc_ids),
        "total_checked": total_checked,
        "total_supported": total_supported,
        "total_unsupported": total_unsupported,
        "incidents": incident_summaries,
        "unsupported_sentences": unsupported_sentences,
    }
