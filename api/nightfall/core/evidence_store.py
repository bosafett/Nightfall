"""Content-addressed evidence stores.

EvidenceStore (default): blobs written once under <dir>/<sha256[:2]>/<sha256>, never
modified. PostgresEvidenceStore: the same contract in a table, for hosts where the API and
the worker can't share a disk. Reads always verify the hash, so tampering is detected
instead of served.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

MAX_BLOB_BYTES = 5 * 1024 * 1024


class IntegrityError(RuntimeError):
    pass


class BlobStore(Protocol):
    def put(self, data: bytes) -> bytes: ...
    def get(self, digest: bytes) -> bytes: ...


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, digest: bytes) -> Path:
        h = digest.hex()
        return self.root / h[:2] / h

    def put(self, data: bytes) -> bytes:
        if len(data) > MAX_BLOB_BYTES:
            raise ValueError("evidence blob too large")
        digest = hashlib.sha256(data).digest()
        path = self._path(digest)
        if path.exists():
            return digest
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o440)
            os.replace(tmp, path)  # atomic: readers never see a partial file
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return digest

    def get(self, digest: bytes) -> bytes:
        try:
            data = self._path(digest).read_bytes()
        except FileNotFoundError as exc:
            raise IntegrityError("evidence content is missing") from exc
        if hashlib.sha256(data).digest() != digest:
            raise IntegrityError("evidence content failed its integrity check")
        return data


def _verified(data: bytes | None, digest: bytes) -> bytes:
    if data is None:
        raise IntegrityError("evidence content is missing")
    if hashlib.sha256(data).digest() != digest:
        raise IntegrityError("evidence content failed its integrity check")
    return data


class PostgresEvidenceStore:
    """Content-addressed store in the evidence_blobs table (migration 0006), for hosts
    without a disk shared by the API and the worker. Same contract as EvidenceStore: write
    once, never modified, hash verified on every read."""

    def __init__(self, sessions: Callable[[], Session]) -> None:
        self.sessions = sessions

    def put(self, data: bytes) -> bytes:
        if len(data) > MAX_BLOB_BYTES:
            raise ValueError("evidence blob too large")
        digest = hashlib.sha256(data).digest()
        with self.sessions() as db:
            db.execute(
                text(
                    "INSERT INTO evidence_blobs (sha256, content, size_bytes) "
                    "VALUES (:d, :c, :n) ON CONFLICT (sha256) DO NOTHING"
                ),
                {"d": digest, "c": data, "n": len(data)},
            )
            db.commit()
        return digest

    def get(self, digest: bytes) -> bytes:
        with self.sessions() as db:
            return read_from(db, digest)


def read_from(db: Session, digest: bytes) -> bytes:
    """Reads a blob in the caller's session, so the caller's row-level security applies:
    the API sees only blobs its current workspace's evidence refers to."""
    data = db.scalar(text("SELECT content FROM evidence_blobs WHERE sha256 = :d"), {"d": digest})
    return _verified(None if data is None else bytes(data), digest)
