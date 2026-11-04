"""Content-addressed evidence store on the local filesystem.

Blobs are written once under <dir>/<sha256[:2]>/<sha256> and never modified. Reads verify
the hash, so tampering with a stored file is detected instead of served.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

MAX_BLOB_BYTES = 5 * 1024 * 1024


class IntegrityError(RuntimeError):
    pass


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
