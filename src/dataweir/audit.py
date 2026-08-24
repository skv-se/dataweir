"""Tamper-evident audit log.

Every decision is appended to a JSONL file as one record. With ``hash_chain``
enabled each record carries the SHA-256 of the previous record, so deleting or
editing any line breaks the chain from that point onward and
``dataweir audit verify`` will say exactly where.

This is deliberately a plain file: it is greppable, it ships to any SIEM that
reads JSONL, and it needs no service to be running.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

GENESIS_HASH = "0" * 64

_REDACTED = "<redacted>"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(payload: dict[str, Any]) -> str:
    """Stable serialization — the hash must not depend on key order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(payload: dict[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class AuditSink(Protocol):
    """Anywhere audit records can go."""

    def write(self, record: dict[str, Any]) -> dict[str, Any]: ...

    def close(self) -> None: ...


class NullAuditSink:
    """Discards records. Used when auditing is switched off."""

    def write(self, record: dict[str, Any]) -> dict[str, Any]:
        return record

    def close(self) -> None:
        return None


class MemoryAuditSink:
    """Keeps records in a list. Useful in tests and for embedding."""

    def __init__(self, hash_chain: bool = True) -> None:
        self.records: list[dict[str, Any]] = []
        self.hash_chain = hash_chain
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = dict(record)
            record.setdefault("ts", _utcnow())
            record["seq"] = len(self.records)
            if self.hash_chain:
                previous = self.records[-1]["hash"] if self.records else GENESIS_HASH
                record["prev_hash"] = previous
                record["hash"] = record_hash(record)
            self.records.append(record)
            return record

    def close(self) -> None:
        return None


class JsonlAuditSink:
    """Append-only hash-chained JSONL on disk."""

    def __init__(self, path: str | Path, hash_chain: bool = True) -> None:
        self.path = Path(path)
        self.hash_chain = hash_chain
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        last = _last_record(self.path)
        self._seq = (last.get("seq", -1) + 1) if last else 0
        self._prev_hash = last.get("hash", GENESIS_HASH) if last else GENESIS_HASH

    def write(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record = dict(record)
            record.setdefault("ts", _utcnow())
            record["seq"] = self._seq
            if self.hash_chain:
                record["prev_hash"] = self._prev_hash
                record["hash"] = record_hash(record)
                self._prev_hash = record["hash"]
            self._seq += 1
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    def close(self) -> None:
        return None


def _last_record(path: Path) -> dict[str, Any] | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    # Read the tail rather than the whole file: audit logs grow without bound.
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        window = min(size, 65536)
        handle.seek(size - window)
        chunk = handle.read(window)
    lines = [line for line in chunk.decode("utf-8", errors="replace").splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield every well-formed record in an audit file."""
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as err:
                raise ValueError(f"{path}:{lineno}: malformed JSON ({err})") from err


@dataclass
class ChainReport:
    ok: bool
    checked: int
    broken_at: int | None = None
    message: str = ""

    def __str__(self) -> str:
        if self.ok:
            return f"chain intact across {self.checked} record(s)"
        return f"chain broken at record {self.broken_at}: {self.message}"


def verify_chain(path: str | Path) -> ChainReport:
    """Recompute every hash and confirm each record points at the last.

    Detects edits, deletions and reordering. It does not stop someone who can
    rewrite the whole file from re-chaining it — for that, ship records off-host
    or co-sign them. It does mean tampering cannot be silent.
    """
    previous = GENESIS_HASH
    checked = 0

    for expected_seq, record in enumerate(read_records(path)):
        checked += 1
        seq = record.get("seq")
        if seq != expected_seq:
            return ChainReport(
                False, checked, expected_seq, f"expected seq {expected_seq}, found {seq!r}"
            )
        if "hash" not in record:
            return ChainReport(False, checked, expected_seq, "record has no hash")
        if record.get("prev_hash") != previous:
            return ChainReport(
                False,
                checked,
                expected_seq,
                f"prev_hash {record.get('prev_hash')!r} does not match {previous!r}",
            )
        recomputed = record_hash(record)
        if recomputed != record["hash"]:
            return ChainReport(
                False, checked, expected_seq, "record content does not match its hash"
            )
        previous = record["hash"]

    return ChainReport(True, checked)


def redact_params(params: Any, enabled: bool = True) -> Any:
    """Replace bound parameter values while keeping their shape.

    Query parameters routinely hold the very values the audit log exists to
    protect, so the default is to record the shape and not the data.
    """
    if params is None:
        return None
    if not enabled:
        return params
    if isinstance(params, dict):
        return {key: _REDACTED for key in params}
    if isinstance(params, (list, tuple)):
        return [_REDACTED] * len(params)
    return _REDACTED


def build_sink(path: str | Path | None, hash_chain: bool = True, enabled: bool = True) -> AuditSink:
    if not enabled or path is None:
        return NullAuditSink()
    return JsonlAuditSink(path, hash_chain=hash_chain)
