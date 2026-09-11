"""Runtime configuration.

Settings are read from the environment, which docker compose populates from api/.env.
Model IDs are module-level constants: call sites import them from here and never
hardcode a model string, so a swap is one line (system_design.md §7.1).
"""

import logging
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Real environment variables win over the file; the file only matters when
    # running outside compose (e.g. pytest from api/).
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres. The same variables initialise the curator-db container.
    postgres_user: str
    postgres_password: SecretStr
    postgres_db: str
    postgres_host: str = "curator-db"
    postgres_port: int = 5432

    # Connection pool.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_connect_timeout_s: int = 3  # keeps /health fast when the DB is down

    # Browser origins allowed to call the API. JSON list when set via env.
    cors_origins: list[str] = ["http://localhost:5173"]

    # Anthropic. Unused until Step 4.
    anthropic_api_key: SecretStr | None = None
    # true: every LLM call returns canned fixtures instead of hitting the API (§7.4).
    dry_run: bool = True
    # true: narrative + challenge run on Opus, as a one-off diagnostic (§10.2).
    opus_diagnostic: bool = False

    # Downloaded datasets and reference data; compose mounts ./datasets here.
    datasets_dir: Path = Path("/datasets")
    # Rows per COPY batch when seeding events.
    seed_batch_size: int = 5000

    log_level: str = "INFO"


settings = Settings()

LOG_FORMAT = "%(asctime)s level=%(levelname)s logger=%(name)s %(message)s"


def configure_logging() -> None:
    logging.basicConfig(level=settings.log_level, format=LOG_FORMAT)


# --- Model IDs (§7.1) --------------------------------------------------------

MODEL_HAIKU = "claude-haiku-4-5-20251001"
MODEL_SONNET = "claude-sonnet-5"
MODEL_OPUS = "claude-opus-5"  # diagnostic only, never a dependency

IOC_EXTRACTION_MODEL = MODEL_HAIKU
VERIFY_MODEL = MODEL_HAIKU
MAPPING_MODEL = MODEL_SONNET
RECOMMEND_MODEL = MODEL_SONNET
NARRATIVE_MODEL = MODEL_OPUS if settings.opus_diagnostic else MODEL_SONNET
CHALLENGE_MODEL = MODEL_OPUS if settings.opus_diagnostic else MODEL_SONNET

# --- Embeddings (§5.6) -------------------------------------------------------

# Baked into the image at build time (api/Dockerfile names the same model).
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
EMBEDDING_DIM = 384

# --- Pipeline constants (§6.1 & Step 3) --------------------------------------

# Dedup windows
DEDUP_EXACT_WINDOW_SECONDS = 60
DEDUP_MINHASH_WINDOW_SECONDS = 300  # 5 min near-duplicate window
DEDUP_MINHASH_THRESHOLD = 0.9

# Correlation windows (named constants, tuned against dataset)
CORRELATE_HOST_WINDOW_SECONDS = 1800     # 30 min on same host
CORRELATE_USER_WINDOW_SECONDS = 1800     # 30 min on same user
CORRELATE_PROCESS_WINDOW_SECONDS = 900   # 15 min on process lineage
CORRELATE_IP_WINDOW_SECONDS = 1800       # 30 min on shared IP
CORRELATE_FILE_WINDOW_SECONDS = 3600     # 60 min on shared file path/hash

# Bounded evidence context per incident
EVIDENCE_SURROUNDING_SECONDS = 60        # ±60s surrounding alerting processes
EVIDENCE_MAX_EVENTS = 250                # low hundreds cap for Step 4 model context
PIPELINE_SCHEDULE_SECONDS = 10

# Incident suppression threshold (3.1c)
INCIDENT_MIN_ALERTS = 3

