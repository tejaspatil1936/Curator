"""Curator API. Step 2: health, dataset seeding, audit chain verification."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from curator import __version__, audit, db
from curator.config import configure_logging, settings
from curator.ingest import seed as seeding

configure_logging()

app = FastAPI(title="Curator", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class Health(BaseModel):
    status: str
    db: bool
    version: str


@app.get("/health")
def health() -> Health:
    # Sync on purpose: the DB round-trip blocks, so FastAPI runs this in its threadpool.
    return Health(status="ok", db=db.ping(), version=__version__)


class SeedRequest(BaseModel):
    dataset: str


class SeedResult(BaseModel):
    events: int  # rows inserted by this call
    skipped: (
        int  # records already present (idempotent re-run) or rejected by the parser
    )
    sources: dict[str, int]  # inserted rows per events.source


@app.post("/seed")
def seed(req: SeedRequest) -> SeedResult:
    # Sync: a full load takes minutes and runs in the threadpool.
    if req.dataset not in seeding.DATASETS:
        raise HTTPException(
            404, f"unknown dataset {req.dataset!r}; known: {sorted(seeding.DATASETS)}"
        )
    return SeedResult(**seeding.seed(req.dataset))


class ChainStatus(BaseModel):
    valid: bool
    rows: int
    broken_at: int | None


@app.get("/audit/verify")
def audit_verify() -> ChainStatus:
    valid, broken_at = audit.verify_chain()
    return ChainStatus(valid=valid, rows=audit.row_count(), broken_at=broken_at)
