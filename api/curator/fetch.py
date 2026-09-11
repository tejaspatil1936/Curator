"""Pinned downloads into the datasets directory.

Every file is identified by URL and SHA-256. A file already on disk is re-hashed and
used only if it matches, so a loaded dataset is always the published original. Files
are downloaded only when missing; a box with no internet works once they are present.
"""

import hashlib
import logging
import shutil
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from curator.config import settings

logger = logging.getLogger(__name__)


class ChecksumError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteFile:
    path: str  # relative to settings.datasets_dir
    url: str
    sha256: str

    @property
    def local(self) -> Path:
        return settings.datasets_dir / self.path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure(f: RemoteFile) -> Path:
    """Return the local path of f, downloading it first if it is missing."""
    dest = f.local
    if not dest.exists():
        logger.info("downloading %s -> %s", f.url, dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".part")
        with urllib.request.urlopen(f.url, timeout=120) as resp, part.open("wb") as out:
            shutil.copyfileobj(resp, out, 1 << 20)
        part.rename(dest)
    actual = sha256_file(dest)
    if actual != f.sha256:
        raise ChecksumError(f"{dest}: sha256 {actual}, expected {f.sha256}")
    return dest
