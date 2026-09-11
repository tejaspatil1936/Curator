"""ATT&CK Enterprise STIX bundle -> techniques table, with local embeddings (§5.6).

Loads active techniques only: attack-pattern objects that are neither revoked nor
deprecated. Descriptions have "(Citation: ...)" markers and markdown link syntax
removed; that cleaned text is stored and feeds both search_tsv and the embedding. Rows
whose content is unchanged keep their embedding, so re-running is cheap.

    python -m curator.attack.load_attack
"""

import json
import logging
import re
import time
from dataclasses import dataclass

from sqlalchemy import text

from curator import audit
from curator.attack.retrieve import embed_passages, vector_literal
from curator.config import EMBEDDING_MODEL, configure_logging
from curator.db import engine
from curator.fetch import RemoteFile, ensure

logger = logging.getLogger(__name__)

ATTACK_VERSION = "19.2"
BUNDLE = RemoteFile(
    path=f"attack/enterprise-attack-{ATTACK_VERSION}.json",
    url=(
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
    ),
    sha256="dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
)

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_CODE_TAG = re.compile(r"</?code>")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    description: str


def clean_description(s: str) -> str:
    return _CODE_TAG.sub("", _MD_LINK.sub(r"\1", _CITATION.sub("", s))).strip()


def techniques_from_bundle(bundle: dict) -> list[Technique]:
    out: dict[str, Technique] = {}
    for o in bundle["objects"]:
        if (
            o.get("type") != "attack-pattern"
            or o.get("revoked")
            or o.get("x_mitre_deprecated")
        ):
            continue
        ext_id = next(
            (
                r["external_id"]
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if ext_id is None:
            continue
        if ext_id in out:
            raise ValueError(f"duplicate active technique id {ext_id} in bundle")
        tactics = tuple(
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        out[ext_id] = Technique(
            ext_id, o["name"], tactics, clean_description(o.get("description", ""))
        )
    return sorted(out.values(), key=lambda t: t.id)


def load() -> dict:
    started = time.monotonic()
    path = ensure(BUNDLE)
    techniques = techniques_from_bundle(json.loads(path.read_bytes()))
    logger.info("bundle %s: %d active techniques", path.name, len(techniques))

    with engine.connect() as conn:
        existing = {
            r.id: (r.name, tuple(r.tactic or ()), r.description)
            for r in conn.execute(
                text(
                    "SELECT id, name, tactic, description FROM techniques "
                    "WHERE embedding IS NOT NULL"
                )
            )
        }
    stale = [
        t
        for t in techniques
        if existing.get(t.id) != (t.name, t.tactics, t.description)
    ]
    logger.info(
        "embedding %d new or changed techniques with %s", len(stale), EMBEDDING_MODEL
    )
    vectors = (
        embed_passages(f"{t.name}. {t.description}" for t in stale) if stale else []
    )

    with engine.begin() as conn:
        if stale:
            conn.execute(
                text(
                    "INSERT INTO techniques (id, name, tactic, description, embedding) "
                    "VALUES (:id, :name, :tactic, :description, "
                    "CAST(:embedding AS vector)) "
                    "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "
                    "tactic = EXCLUDED.tactic, description = EXCLUDED.description, "
                    "embedding = EXCLUDED.embedding"
                ),
                [
                    {
                        "id": t.id,
                        "name": t.name,
                        "tactic": list(t.tactics),
                        "description": t.description,
                        "embedding": vector_literal(v),
                    }
                    for t, v in zip(stale, vectors, strict=True)
                ],
            )
        removed = conn.execute(
            text("DELETE FROM techniques WHERE NOT (id = ANY(:ids))"),
            {"ids": [t.id for t in techniques]},
        ).rowcount
        total = conn.execute(text("SELECT count(*) FROM techniques")).scalar_one()
        detail = {
            "bundle": BUNDLE.path,
            "attack_version": ATTACK_VERSION,
            "sha256": BUNDLE.sha256,
            "active_techniques": len(techniques),
            "embedded": len(stale),
            "unchanged": len(techniques) - len(stale),
            "removed": removed,
            "rows": total,
            "embedding_model": EMBEDDING_MODEL,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        audit.append(conn, "pipeline", "attack.load", detail)
    logger.info("attack load complete %s", json.dumps(detail))
    return detail


if __name__ == "__main__":
    configure_logging()
    load()
