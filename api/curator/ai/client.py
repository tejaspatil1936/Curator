"""Anthropic API client gateway (system_design.md §7.1 & Step 4b).

The ONLY module in the codebase permitted to call the Anthropic API.
- Models from config.py constants, never string literals.
- Prompt caching: [cacheable: system + rules], [cacheable: retrieved ATT&CK context],
  [cacheable: incident event corpus], [volatile: task instruction].
- Explicit max_tokens on every invocation.
- Exponential backoff with jitter on 429 / 529.
- Every call logged to audit_chain.
- DRY_RUN=true returns deterministic, grounded canned fixtures.
"""

from __future__ import annotations

import json
import logging
import random
import time
from typing import Any

from sqlalchemy.orm import Session

from curator import audit
from curator.config import (
    CHALLENGE_MODEL,
    IOC_EXTRACTION_MODEL,
    MAPPING_MODEL,
    MODEL_HAIKU,
    MODEL_OPUS,
    MODEL_SONNET,
    NARRATIVE_MODEL,
    RECOMMEND_MODEL,
    VERIFY_MODEL,
    settings,
)

logger = logging.getLogger(__name__)

# Input/Output token pricing per million tokens (Anthropic 2025/2026 pricing)
# Sonnet 5: $3 / $15; Haiku 4.5: $0.80 / $4.00
PRICING_PER_M = {
    MODEL_SONNET: {"input": 3.00, "output": 15.00, "cache_read": 0.30, "cache_write": 3.75},
    MODEL_HAIKU: {"input": 0.80, "output": 4.00, "cache_read": 0.08, "cache_write": 1.00},
    MODEL_OPUS: {"input": 15.00, "output": 75.00, "cache_read": 1.50, "cache_write": 18.75},
}


class AIClientError(Exception):
    """Base exception for AI client failures."""


def call_claude(
    *,
    model: str,
    system_blocks: list[dict[str, Any]] | None = None,
    user_blocks: list[dict[str, Any]],
    max_tokens: int,
    session: Session,
    incident_id: int | None = None,
    task_name: str = "llm_task",
) -> dict[str, Any]:
    """Execute an Anthropic API call with prompt caching, retry backoff, and audit logging.

    Returns dict containing:
    - 'content': raw response text string
    - 'model': model used
    - 'input_tokens': int
    - 'output_tokens': int
    - 'cache_read_tokens': int
    - 'cache_creation_tokens': int
    - 'latency_ms': int
    - 'estimated_cost_usd': float
    """
    start_time = time.time()

    # Dry-run bypass: return canned fixtures without touching Anthropic API
    if settings.dry_run or not settings.anthropic_api_key or settings.anthropic_api_key.get_secret_value() in ("", "your-anthropic-api-key-here"):
        return _handle_dry_run(
            task_name=task_name,
            model=model,
            incident_id=incident_id,
            user_blocks=user_blocks,
            session=session,
        )

    # Real Anthropic API execution with exponential backoff & jitter
    import anthropic
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key.get_secret_value())

    max_retries = 5
    base_delay = 1.0
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "max_tokens": max_tokens,
                "thinking": {"type": "disabled"},
                "messages": [{"role": "user", "content": user_blocks}],
            }
            if system_blocks:
                kwargs["system"] = system_blocks

            resp = client.messages.create(**kwargs)

            latency_ms = int((time.time() - start_time) * 1000)
            in_tok = resp.usage.input_tokens
            out_tok = resp.usage.output_tokens
            cache_read = getattr(resp.usage, "cache_read_input_tokens", 0) or 0
            cache_write = getattr(resp.usage, "cache_creation_input_tokens", 0) or 0

            cost = _compute_cost(model, in_tok, out_tok, cache_read, cache_write)
            content_text = "".join(
                b.text for b in resp.content if hasattr(b, "text")
            )

            # Audit chain logging
            audit.append(
                session.connection(),
                actor=f"ai:{model}",
                action="anthropic_api_call",
                detail={
                    "task": task_name,
                    "model": model,
                    "incident_id": incident_id,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "cache_read_tokens": cache_read,
                    "cache_creation_tokens": cache_write,
                    "latency_ms": latency_ms,
                    "cost_micro_usd": int(cost * 1_000_000),
                },
            )
            session.commit()

            return {
                "content": content_text,
                "model": model,
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "cache_read_tokens": cache_read,
                "cache_creation_tokens": cache_write,
                "latency_ms": latency_ms,
                "estimated_cost_usd": cost,
            }

        except anthropic.RateLimitError as e:
            last_error = e
            delay = base_delay * (2 ** attempt) + random.uniform(0.1, 0.5)
            logger.warning(
                "Anthropic rate limit (429), backing off for %.2fs (attempt %d/%d)",
                delay,
                attempt + 1,
                max_retries,
            )
            time.sleep(delay)
        except anthropic.APIStatusError as e:
            last_error = e
            if e.status_code in (500, 502, 503, 529):
                delay = base_delay * (2 ** attempt) + random.uniform(0.1, 0.5)
                logger.warning(
                    "Anthropic server error (%d), backing off for %.2fs (attempt %d/%d)",
                    e.status_code,
                    delay,
                    attempt + 1,
                    max_retries,
                )
                time.sleep(delay)
            else:
                logger.error("Anthropic API error: %s", e)
                raise AIClientError(f"Anthropic API error: {e}") from e

    raise AIClientError(f"Exceeded max retries calling Anthropic API: {last_error}")


def _compute_cost(
    model: str, input_tokens: int, output_tokens: int, cache_read: int, cache_write: int
) -> float:
    rates = PRICING_PER_M.get(
        model, {"input": 3.0, "output": 15.0, "cache_read": 0.30, "cache_write": 3.75}
    )
    cost = (
        (input_tokens * rates["input"])
        + (output_tokens * rates["output"])
        + (cache_read * rates["cache_read"])
        + (cache_write * rates["cache_write"])
    ) / 1_000_000.0
    return round(cost, 6)


def _handle_dry_run(
    *,
    task_name: str,
    model: str,
    incident_id: int | None,
    user_blocks: list[dict[str, Any]],
    session: Session,
) -> dict[str, Any]:
    """Generate authentic, grounded mock fixtures in DRY_RUN mode."""
    start_time = time.time()
    from sqlalchemy import text

    content_str = "{}"
    in_tok = 1500
    out_tok = 350
    cache_read = 1200
    cache_write = 0

    if task_name == "narrative" and incident_id is not None:
        # Query alerting and evidence event IDs for this incident
        q_ev = text("""
            SELECT e.id, e.ts, e.host, e.user_name, e.process_name, e.command_line, a.rule_id
            FROM events e
            JOIN alerts a ON a.event_id = e.id
            WHERE a.incident_id = :inc_id
            ORDER BY e.ts ASC
        """)
        alerts = session.execute(q_ev, {"inc_id": incident_id}).fetchall()
        alert_ids = [r[0] for r in alerts]

        if not alert_ids:
            # Fallback to any events assigned to the incident
            q_all_ev = text("SELECT id FROM events WHERE incident_id = :inc_id ORDER BY ts ASC LIMIT 20")
            alert_ids = [r[0] for r in session.execute(q_all_ev, {"inc_id": incident_id}).fetchall()]

        # Query incident metadata to detect campaign
        inc_meta = session.execute(
            text("SELECT users, hosts FROM incidents WHERE id = :id"),
            {"id": incident_id},
        ).fetchone()
        inc_users = [str(u).lower() for u in (inc_meta[0] if inc_meta else []) or []]

        is_day1 = any("pbeesly" in u for u in inc_users) or incident_id in (803, 262, 131)
        is_day2 = any("dschrute" in u for u in inc_users) or incident_id in (855, 315, 184)

        if is_day1:  # Day 1 Campaign (pbeesly)
            # High-fidelity multi-sentence narrative covering initial execution, module loading,
            # C2 beaconing, SMB share discovery/movement, service installation, and PowerShell exfil.
            # Intentionally includes 2 non-whitelisted IDs (999991, 999992) to verify validator drop tracking.
            sentences = [
                {
                    "seq": 1,
                    "text": "The masqueraded Right-to-Left Override executable cod.3aka3.scr was executed under user pbeesly from C:\\ProgramData\\victim\\ on SCRANTON.",
                    "evidence_event_ids": [426, 373],
                },
                {
                    "seq": 2,
                    "text": "Support modules and DLLs were dynamically loaded into the masqueraded screensaver process from non-standard directory C:\\ProgramData\\victim\\.",
                    "evidence_event_ids": [381, 382, 383, 384, 385, 999991],
                },
                {
                    "seq": 3,
                    "text": "PowerShell on SCRANTON established initial outbound command-and-control network connections to 192.168.0.5 over port 443 at 02:58:45.",
                    "evidence_event_ids": [7665, 69383],
                },
                {
                    "seq": 4,
                    "text": "PowerShell on SCRANTON initiated repeated outbound HTTPS staging connections to 23.4.15.75:443 between 03:08:04 and 03:08:14.",
                    "evidence_event_ids": [69385, 88468, 89587],
                },
                {
                    "seq": 5,
                    "text": "Persistent C2 beaconing sessions were maintained by powershell.exe from SCRANTON over TLS port 443.",
                    "evidence_event_ids": [90586, 186659],
                },
                {
                    "seq": 6,
                    "text": "Initial SMB sessions connected to administrative share \\\\*\\IPC$ on domain controller NEWYORK.dmevals.local at 03:04:04.",
                    "evidence_event_ids": [50798, 50799],
                },
                {
                    "seq": 7,
                    "text": "Subsequent administrative share accesses were performed against \\\\*\\IPC$ on NEWYORK to enumerate domain resources.",
                    "evidence_event_ids": [57607, 57701],
                },
                {
                    "seq": 8,
                    "text": "Remote administrative shares \\\\*\\C$ and \\\\*\\ADMIN$ were accessed on NASHUA.dmevals.local to stage lateral payloads between 03:08:50 and 03:09:15.",
                    "evidence_event_ids": [92334, 92335, 92338, 92341, 999992],
                },
                {
                    "seq": 9,
                    "text": "A new Windows service was installed and registered via Service Control Manager on SCRANTON at 03:04:15.",
                    "evidence_event_ids": [50933, 50937],
                },
                {
                    "seq": 10,
                    "text": "Remote Windows service creation was executed on NASHUA to obtain persistence and administrative execution at 03:09:33.",
                    "evidence_event_ids": [94192, 94195],
                },
                {
                    "seq": 11,
                    "text": "Service configuration parameters and startup arguments were updated on NASHUA at 03:10:18.",
                    "evidence_event_ids": [95442, 95444],
                },
                {
                    "seq": 12,
                    "text": "Service startup and execution lifecycles were triggered on NASHUA under the local service account.",
                    "evidence_event_ids": [96407, 96411],
                },
                {
                    "seq": 13,
                    "text": "PowerShell was spawned with hidden window and non-interactive arguments (-nop -w hidden) on SCRANTON at 03:21:28.",
                    "evidence_event_ids": [169077, 169112, 185832],
                },
                {
                    "seq": 14,
                    "text": "Encoded PowerShell commands and Invoke-Exfil scriptblock routines were executed on SCRANTON.",
                    "evidence_event_ids": [169083, 169200, 169211, 169283],
                },
            ]
            data = {
                "title": "Initial Access via Masqueraded Executable, Outbound C2 Beaconing, Lateral Movement via SMB Shares and Services by pbeesly",
                "sentences": sentences,
            }
            content_str = json.dumps(data)

        elif is_day2:  # Day 2 Campaign (dschrute)
            sentences = [
                {
                    "seq": 1,
                    "text": "A scheduled task was created or updated on UTICA.dmevals.local to establish persistence under user dschrute at 07:53:41.",
                    "evidence_event_ids": [252475],
                },
                {
                    "seq": 2,
                    "text": "PowerShell was invoked with encoded arguments and hidden window execution (-enc) on UTICA at 07:55:27.",
                    "evidence_event_ids": [304288, 304293],
                },
                {
                    "seq": 3,
                    "text": "Registry Run and RunOnce keys were modified on UTICA to persist adversary script execution.",
                    "evidence_event_ids": [304432, 304288],
                },
                {
                    "seq": 4,
                    "text": "Outbound network connection was initiated from powershell.exe on UTICA to command-and-control server 192.168.0.4:443 at 07:55:27.",
                    "evidence_event_ids": [304512, 315967],
                },
                {
                    "seq": 5,
                    "text": "Repeated outbound C2 sessions were established by powershell.exe from UTICA to external staging addresses.",
                    "evidence_event_ids": [346427, 353357, 360441],
                },
                {
                    "seq": 6,
                    "text": "Persistent C2 beaconing continued from UTICA over HTTP and HTTPS ports 80 and 443.",
                    "evidence_event_ids": [360546, 369591, 497648],
                },
                {
                    "seq": 7,
                    "text": "PowerShell executed WebClient download cradles on UTICA to fetch remote staging scripts.",
                    "evidence_event_ids": [305077, 305081, 305089, 305098],
                },
                {
                    "seq": 8,
                    "text": "Secondary download cradles transferred and decoded in-memory payloads on UTICA.",
                    "evidence_event_ids": [307398, 344365, 344371, 344373],
                },
                {
                    "seq": 9,
                    "text": "Administrative share \\\\*\\IPC$ was accessed on domain controller NEWYORK.dmevals.local from UTICA to prepare lateral movement.",
                    "evidence_event_ids": [301294, 306613, 316910],
                },
                {
                    "seq": 10,
                    "text": "Additional administrative share sessions were opened against \\\\*\\ADMIN$ on NEWYORK to stage remote operations.",
                    "evidence_event_ids": [316912, 316922, 316931, 316961],
                },
                {
                    "seq": 11,
                    "text": "WMI Provider wmiprvse.exe spawned PowerShell processes with encoded payloads on UTICA at 07:59:09.",
                    "evidence_event_ids": [352293, 650928],
                },
                {
                    "seq": 12,
                    "text": "Subsequent WMI execution provider operations launched non-interactive script bypasses on UTICA at 08:12:54.",
                    "evidence_event_ids": [655444, 655454],
                },
                {
                    "seq": 13,
                    "text": "Reconnaissance utility net.exe was executed on UTICA to map network drive connections and shares at 08:09:58.",
                    "evidence_event_ids": [560471, 560389],
                },
            ]
            data = {
                "title": "Scheduled Task Persistence, Encoded PowerShell Downloads, WMI Lateral Execution, and C2 Beaconing by dschrute",
                "sentences": sentences,
            }
            content_str = json.dumps(data)

        else:
            # Multi-event grounded sentences for smaller incidents (2-5 sentences, multi-citations)
            sentences = []
            if len(alert_ids) == 1:
                sentences.append({
                    "seq": 1,
                    "text": f"Suspicious security activity detected on host involving alerting telemetry.",
                    "evidence_event_ids": [alert_ids[0]],
                })
            else:
                # Group alerts into pairs or triples to ensure multi-event citations
                chunk_size = max(2, len(alert_ids) // 3)
                for i in range(0, min(len(alert_ids), 9), chunk_size):
                    chunk = alert_ids[i : i + chunk_size]
                    sentences.append({
                        "seq": len(sentences) + 1,
                        "text": f"Correlated suspicious security event sequence observed across host telemetry ({len(chunk)} events).",
                        "evidence_event_ids": chunk,
                    })
            if not sentences:
                sentences.append({
                    "seq": 1,
                    "text": "Observed suspicious telemetry across host systems.",
                    "evidence_event_ids": [],
                })
            data = {
                "title": f"Security Incident #{incident_id}",
                "sentences": sentences,
            }
            content_str = json.dumps(data)

    elif task_name == "mapping":
        # Parse candidate whitelist and text per sentence from prompt
        import re
        prompt_text = "".join(str(b.get("text", "")) for b in user_blocks)
        
        # Split by Sentence N:
        sentence_chunks = re.split(r"(?:^|\n)(?=Sentence \d+:)", prompt_text)
        mappings = []

        for chunk in sentence_chunks:
            chunk = chunk.strip()
            if not chunk or not chunk.startswith("Sentence "):
                continue
            seq_m = re.search(r"^Sentence (\d+):", chunk)
            if not seq_m:
                continue
            seq = int(seq_m.group(1))

            txt_m = re.search(r'Sentence \d+:\s*"([^"]+)"', chunk)
            sentence_text = (txt_m.group(1) if txt_m else "").lower()

            # Find all candidate technique IDs for this sentence
            cand_matches = re.findall(r"(T\d{4}(?:\.\d{3})?)", chunk)
            # Exclude the sentence header itself if any
            candidates = list(dict.fromkeys(cand_matches))

            chosen_tech = None
            # Semantic matching based on concrete activity in sentence
            if any(k in sentence_text for k in ("masquerad", "right-to-left", ".scr")):
                for t in ("T1036.002", "T1036"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("outbound", "command-and-control", "beacon", "c2", "port 443", "port 8080", "https", "tls")):
                for t in ("T1071.001", "T1071", "T1048", "T1572"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("wmi", "wmiprvse")):
                for t in ("T1047", "T1546.003"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("lsass", "credential", "ticket")):
                for t in ("T1003.001", "T1003", "T1550.003"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("administrative share", "ipc$", "admin$", "c$", "smb")):
                for t in ("T1021.002", "T1021", "T1135"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("service was installed", "service creation", "service control manager")):
                for t in ("T1543.003", "T1543", "T1569.002"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("scheduled task",)):
                for t in ("T1053.005", "T1053"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("registry run", "runonce", "startup folder")):
                for t in ("T1547.001", "T1547", "T1112"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("download cradle", "webclient", "staging scripts", "transfer")):
                for t in ("T1105", "T1059.001"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("powershell", "invoke-", "scriptblock", "encoded")):
                for t in ("T1059.001", "T1059"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("net.exe", "reconnaissance", "map network", "discovery")):
                for t in ("T1082", "T1018", "T1087", "T1135"):
                    if t in candidates: chosen_tech = t; break
            elif any(k in sentence_text for k in ("modules and dlls", "module load")):
                for t in ("T1129", "T1055"):
                    if t in candidates: chosen_tech = t; break

            # If no specific match, decline or select best fitting candidate
            if chosen_tech:
                mappings.append({"seq": seq, "technique_id": chosen_tech, "confidence": 0.94})
            elif candidates and seq % 4 != 0:
                # Map only if candidate reasonably fits; otherwise decline (null)
                mappings.append({"seq": seq, "technique_id": candidates[0], "confidence": 0.82})
            else:
                mappings.append({"seq": seq, "technique_id": None, "confidence": 0.0})

        content_str = json.dumps({"mappings": mappings})

    elif task_name == "narrative_verification":
        # Extract sentence seq numbers from user_blocks
        import re
        prompt_text = (user_blocks[0].get("text", "") if user_blocks else "")
        seqs = [int(m) for m in re.findall(r"Sentence seq (\d+):", prompt_text)]
        results = []
        for s in seqs:
            # Mark planted false alert claim or zero evidence as unsupported in mock
            is_unsupported = "lsass" in prompt_text.lower() and "42145" in prompt_text
            if is_unsupported:
                results.append({
                    "seq": s,
                    "supported": False,
                    "reason": "Cited event 42145 is a conhost.exe execution and does not show LSASS memory access or credential dumping.",
                })
            else:
                results.append({
                    "seq": s,
                    "supported": True,
                    "reason": "Cited evidence events substantiate the forensic claim in this sentence.",
                })
        content_str = json.dumps({"results": results})
        in_tok = 800
        out_tok = 150
        cache_read = 0
        cache_write = 0

    elif task_name == "challenge":
        # Return the grounded DRY_RUN fixture from challenge.py
        from curator.ai.challenge import _DRY_RUN_FIXTURE
        content_str = json.dumps(_DRY_RUN_FIXTURE)
        in_tok = 2000
        out_tok = 400
        cache_read = 1800
        cache_write = 0


    latency_ms = int((time.time() - start_time) * 1000) + 45
    cost = _compute_cost(model, in_tok, out_tok, cache_read, cache_write)

    # Log dry run to audit chain
    audit.append(
        session.connection(),
        actor=f"ai:{model}",
        action="anthropic_api_call",
        detail={
            "task": task_name,
            "model": model,
            "incident_id": incident_id,
            "dry_run": True,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "cache_read_tokens": cache_read,
            "cache_creation_tokens": cache_write,
            "latency_ms": latency_ms,
            "cost_micro_usd": int(cost * 1_000_000),
        },
    )
    session.commit()

    return {
        "content": content_str,
        "model": model,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cache_read_tokens": cache_read,
        "cache_creation_tokens": cache_write,
        "latency_ms": latency_ms,
        "estimated_cost_usd": cost,
        "dry_run": True,
    }

