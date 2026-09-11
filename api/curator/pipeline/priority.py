"""Transparent additive incident prioritization (system_design.md §6.1).

Scoring rules (0-100):
+30  credential-access indicators present
+25  more than one host involved
+20  lateral-movement pattern (auth/connection from host A to host B)
+15  outbound connection to external IP
+10  persistence mechanism touched
+ 5  per additional distinct ATT&CK tactic (beyond 1)

All contributing factors are saved in priority_reason so the UI can explain the ranking.
"""

from __future__ import annotations

from typing import Any

# Map rules to tactics
_RULE_TACTICS: dict[str, str] = {
    "CUR-001": "Execution",
    "CUR-002": "Execution",
    "CUR-003": "Execution",
    "CUR-004": "Command and Control",
    "CUR-005": "Credential Access",
    "CUR-006": "Persistence",
    "CUR-007": "Persistence",
    "CUR-008": "Persistence",
    "CUR-009": "Persistence",
    "CUR-010": "Persistence",
    "CUR-011": "Execution",
    "CUR-012": "Lateral Movement",
    "CUR-013": "Command and Control",
    "CUR-014": "Persistence",
    "CUR-015": "Discovery",
    "CUR-016": "Defense Evasion",
    "CUR-017": "Lateral Movement",
    "CUR-018": "Credential Access",
    "CUR-019": "Defense Evasion",
    "CUR-020": "Execution",
    "CUR-021": "Lateral Movement",   # WinRM remote execution (T1021.006)
    "CUR-022": "Collection",          # Data staging (T1074)
}


def calculate_priority(
    alerts: list[dict[str, Any]] | list[Any],
    hosts: list[str],
) -> tuple[int, dict[str, Any]]:
    """Calculate transparent additive priority score (0-100) and rationale."""
    factors: list[dict[str, Any]] = []
    score = 0

    rule_ids = {
        (
            a.get("rule_id")
            if isinstance(a, dict)
            else getattr(a, "rule_id", None)
        )
        for a in alerts
    }

    # 1. Credential Access (+30)
    has_cred_access = bool(
        rule_ids & {"CUR-005", "CUR-018"}
        or any("1003" in str(r) for r in rule_ids)
    )
    if has_cred_access:
        score += 30
        factors.append(
            {"points": 30, "reason": "credential-access indicators present"}
        )

    # 2. Multi-host (+25)
    clean_hosts = [h for h in hosts if h and h != "-"]
    if len(clean_hosts) > 1:
        score += 25
        factors.append(
            {
                "points": 25,
                "reason": f"more than one host involved ({len(clean_hosts)} hosts: {', '.join(clean_hosts)})",
            }
        )

    # 3. Lateral movement (+20)
    # CUR-012: SMB/NTLM lateral  CUR-017: RDP  CUR-021: WinRM
    has_lat_move = bool(
        rule_ids & {"CUR-012", "CUR-017", "CUR-021"}
    )
    if has_lat_move:
        score += 20
        factors.append(
            {
                "points": 20,
                "reason": "lateral-movement pattern (network share / remote interactive logon / WinRM across endpoints)",
            }
        )

    # 4. Outbound external connection (+15)
    has_external_c2 = bool(rule_ids & {"CUR-004", "CUR-013"})
    if has_external_c2:
        score += 15
        factors.append(
            {
                "points": 15,
                "reason": "outbound connection or download cradle to external IP",
            }
        )

    # 5. Persistence (+10)
    has_persistence = bool(
        rule_ids
        & {"CUR-006", "CUR-007", "CUR-008", "CUR-009", "CUR-010", "CUR-014"}
    )
    if has_persistence:
        score += 10
        factors.append(
            {
                "points": 10,
                "reason": "persistence mechanism touched (registry run keys, service, or scheduled task)",
            }
        )

    # 6. Distinct tactics (+5 per additional tactic beyond 1)
    tactics: set[str] = set()
    for rid in rule_ids:
        if rid in _RULE_TACTICS:
            tactics.add(_RULE_TACTICS[rid])

    if len(tactics) > 1:
        extra_tactics = len(tactics) - 1
        tactic_points = min(20, extra_tactics * 5)
        score += tactic_points
        factors.append(
            {
                "points": tactic_points,
                "reason": f"multiple distinct ATT&CK tactics ({len(tactics)} tactics: {', '.join(sorted(tactics))})",
            }
        )

    total_score = min(100, score)
    reason = {
        "score": total_score,
        "factors": factors,
    }
    return total_score, reason
