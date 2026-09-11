"""Hybrid ATT&CK technique retrieval (system_design.md §5.6).

Vector similarity over techniques.embedding is fused with a keyword match over
techniques.search_tsv. Step 4 grounds technique mapping on this: the model may only
choose among the candidates returned here, never recall an ID from memory.

Fusion is reciprocal rank fusion: score = sum over both rankings of 1 / (rrf_k + rank).
It needs no calibration between cosine distance and ts_rank_cd.

    python -m curator.attack.retrieve "powershell spawned by winword" -k 10
"""

import argparse
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import Connection, text

from curator.config import EMBEDDING_MODEL, configure_logging
from curator.db import engine

# BGE v1.5's recommended instruction for short retrieval queries (from the model card).
# fastembed's query_embed() does not add it for this model, so it is added here.
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


@lru_cache(maxsize=1)
def _model():
    from fastembed import TextEmbedding  # heavy import; load only when embedding

    return TextEmbedding(EMBEDDING_MODEL)


def embed_passages(texts: Iterable[str]) -> list[list[float]]:
    # Small batches: at fastembed's default of 256, long ATT&CK descriptions (512
    # tokens each) need several GB for attention and get the process OOM-killed.
    return [v.tolist() for v in _model().embed(list(texts), batch_size=16)]


def embed_query(query: str) -> list[float]:
    return next(iter(_model().embed([QUERY_INSTRUCTION + query]))).tolist()


def vector_literal(vec: Iterable[float]) -> str:
    return "[" + ",".join(f"{x:.8g}" for x in vec) + "]"


@dataclass(frozen=True)
class Candidate:
    id: str
    name: str
    tactics: list[str]
    score: float
    vector_rank: int | None
    keyword_rank: int | None


_HYBRID = text("""
    WITH q AS (
        -- plainto_tsquery ANDs every term, so a descriptive phrase would match
        -- nothing; OR the terms instead.
        SELECT CAST(replace(plainto_tsquery('english', :qtext)::text, ' & ', ' | ')
                    AS tsquery) AS q
    ),
    vec AS (
        SELECT id, row_number() OVER (ORDER BY d, id) AS rnk
        FROM (
            SELECT id, embedding <=> CAST(:qvec AS vector) AS d
            FROM techniques
            WHERE embedding IS NOT NULL
            ORDER BY d, id
            LIMIT :pool
        ) nearest
    ),
    kw AS (
        SELECT id, row_number() OVER (ORDER BY r DESC, id) AS rnk
        FROM (
            SELECT id, ts_rank_cd(search_tsv, q.q) AS r
            FROM techniques, q
            WHERE search_tsv @@ q.q
            ORDER BY r DESC, id
            LIMIT :pool
        ) matched
    )
    SELECT t.id, t.name, t.tactic, vec.rnk AS vector_rank, kw.rnk AS keyword_rank,
           coalesce(1.0 / (:rrf_k + vec.rnk), 0)
           + coalesce(1.0 / (:rrf_k + kw.rnk), 0) AS score
    FROM vec FULL OUTER JOIN kw USING (id)
    JOIN techniques t USING (id)
    ORDER BY score DESC, t.id
    LIMIT :k
    """)


def retrieve(
    query: str,
    k: int = 10,
    *,
    pool: int = 50,
    rrf_k: int = 60,
    conn: Connection | None = None,
) -> list[Candidate]:
    """Top-k technique candidates for a free-text description of observed behaviour."""
    params = {
        "qvec": vector_literal(embed_query(query)),
        "qtext": query,
        "pool": pool,
        "rrf_k": rrf_k,
        "k": k,
    }

    def run(c: Connection) -> list[Candidate]:
        # HNSW returns at most ef_search rows; make sure it can fill the pool.
        c.execute(
            text("SELECT set_config('hnsw.ef_search', :ef, true)"),
            {"ef": str(max(pool, 40))},
        )
        return [
            Candidate(
                r.id,
                r.name,
                list(r.tactic or []),
                float(r.score),
                r.vector_rank,
                r.keyword_rank,
            )
            for r in c.execute(_HYBRID, params)
        ]

    if conn is not None:
        return run(conn)
    with engine.begin() as c:
        return run(c)


def _main() -> None:
    configure_logging()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=10)
    args = ap.parse_args()
    out = [
        f"{'rank':>4}  {'id':<10} {'score':>7}  {'vec':>4} {'kw':>4}  name  [tactics]"
    ]
    for i, c in enumerate(retrieve(args.query, args.k), 1):
        vr = "-" if c.vector_rank is None else str(c.vector_rank)
        kr = "-" if c.keyword_rank is None else str(c.keyword_rank)
        tactics = ", ".join(c.tactics)
        out.append(
            f"{i:>4}  {c.id:<10} {c.score:7.4f}  {vr:>4} {kr:>4}  {c.name}  [{tactics}]"
        )
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    _main()
