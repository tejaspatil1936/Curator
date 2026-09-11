"""Deduplication stage for security alerts (system_design.md §6.1).

Computes:
1. Exact dedup key: sha256(rule_id | host | user_norm | process_uid | floor(ts, 60s)).
2. Near-duplicate detection: MinHash / Jaccard similarity over tokenized command-lines
   within a 5-minute sliding window (threshold 0.9).

Duplicates are marked (is_duplicate = True, canonical_id = original), never deleted.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from curator.config import (
    DEDUP_EXACT_WINDOW_SECONDS,
    DEDUP_MINHASH_THRESHOLD,
    DEDUP_MINHASH_WINDOW_SECONDS,
)

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-\.\:\\]+")
_NUM_PERMUTATIONS = 64
# Simple linear hash coefficients for MinHash: (a * x + b) % prime
_PRIME = 4294967311
_COEFF_A = [((i * 10007 + 12345) % 100000 + 1) for i in range(_NUM_PERMUTATIONS)]
_COEFF_B = [((i * 32452843 + 98765) % 100000 + 1) for i in range(_NUM_PERMUTATIONS)]


def compute_exact_dedup_key(
    rule_id: str,
    host: str | None,
    user_norm: str | None,
    process_uid: str | None,
    ts: datetime,
) -> str:
    """Compute the 60-second exact deduplication key."""
    epoch_s = int(ts.timestamp())
    bucket = epoch_s // DEDUP_EXACT_WINDOW_SECONDS
    h_str = host or ""
    u_str = user_norm or ""
    p_str = process_uid or ""
    raw = f"{rule_id}|{h_str}|{u_str}|{p_str}|{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def tokenize_command_line(cmd: str | None) -> set[str]:
    """Tokenize a command line string into a set of normalized tokens."""
    if not cmd:
        return set()
    return {t.lower() for t in _TOKEN_RE.findall(cmd) if len(t) > 1}


def compute_minhash(tokens: set[str]) -> list[int]:
    """Compute MinHash signature for a token set."""
    if not tokens:
        return [0] * _NUM_PERMUTATIONS
    sig = [_PRIME] * _NUM_PERMUTATIONS
    for token in tokens:
        # String hash into integer
        h = (
            int.from_bytes(
                hashlib.md5(token.encode("utf-8")).digest()[:4], "little"
            )
            % _PRIME
        )
        for i in range(_NUM_PERMUTATIONS):
            val = (_COEFF_A[i] * h + _COEFF_B[i]) % _PRIME
            if val < sig[i]:
                sig[i] = val
    return sig


def minhash_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    """Estimate Jaccard similarity from two MinHash signatures."""
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(sig_a, sig_b, strict=True) if a == b)
    return matches / len(sig_a)


@dataclass
class AlertRecord:
    id: int
    rule_id: str
    host: str | None
    user_norm: str | None
    process_uid: str | None
    ts: datetime
    command_line: str | None = None
    dedup_key: str | None = None
    is_duplicate: bool = False
    canonical_id: int | None = None


def deduplicate_alerts(
    alerts: list[AlertRecord],
) -> tuple[list[AlertRecord], int]:
    """Perform exact and MinHash near-duplicate detection in chronological order.

    Returns the mutated alert list and the count of duplicates identified.
    """
    # Sort chronologically
    sorted_alerts = sorted(alerts, key=lambda a: a.ts)

    # exact_keys: key -> canonical AlertRecord
    seen_exact: dict[str, AlertRecord] = {}

    # recent_canonical: list of canonical AlertRecords for near-duplicate checks
    # keep window of DEDUP_MINHASH_WINDOW_SECONDS
    recent_signatures: list[tuple[AlertRecord, list[int], set[str]]] = []
    duplicate_count = 0

    for a in sorted_alerts:
        # 1. Exact match on 60s bucket
        key = compute_exact_dedup_key(
            a.rule_id, a.host, a.user_norm, a.process_uid, a.ts
        )
        a.dedup_key = key

        if key in seen_exact:
            canonical = seen_exact[key]
            a.is_duplicate = True
            a.canonical_id = canonical.id
            duplicate_count += 1
            continue

        # 2. MinHash near-duplicate check
        tokens = tokenize_command_line(a.command_line)
        is_near_dup = False

        # Expire signatures older than 5 minutes
        current_ts = a.ts.timestamp()
        cutoff = current_ts - DEDUP_MINHASH_WINDOW_SECONDS
        recent_signatures = [
            (c, s, tok)
            for c, s, tok in recent_signatures
            if c.ts.timestamp() >= cutoff
        ]

        if len(tokens) >= 3:
            sig = compute_minhash(tokens)
            for cand, cand_sig, cand_tokens in recent_signatures:
                # Same rule, same host, same user
                if (
                    cand.rule_id == a.rule_id
                    and cand.host == a.host
                    and cand.user_norm == a.user_norm
                ):
                    sim = minhash_jaccard(sig, cand_sig)
                    if sim >= DEDUP_MINHASH_THRESHOLD:
                        a.is_duplicate = True
                        a.canonical_id = cand.id
                        duplicate_count += 1
                        is_near_dup = True
                        break

            if is_near_dup:
                continue

            # It's a canonical alert; record signature
            recent_signatures.append((a, sig, tokens))

        seen_exact[key] = a

    return sorted_alerts, duplicate_count
