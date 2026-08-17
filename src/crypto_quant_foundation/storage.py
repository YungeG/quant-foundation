from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

from crypto_quant_domain import (
    ArtifactEnvelope,
    ArtifactReadResult,
    ArtifactRef,
    canonical_bytes,
)

FAILURE_PRECEDENCE = (
    "UNSUPPORTED_FILESYSTEM",
    "WRITE_LOCK_UNAVAILABLE",
    "CLOCK_NOT_MONOTONIC",
    "ARTIFACT_NOT_FOUND",
    "ARTIFACT_INTEGRITY",
    "ARTIFACT_PUBLICATION_FAILED",
    "LOG_CONFLICT",
    "LOG_INTEGRITY",
    "LOG_PUBLICATION_FAILED",
    "SNAPSHOT_PUBLICATION_FAILED",
)

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOG_NAME_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_PAYLOAD_RE = re.compile(r"[0-9a-f]*\Z")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


class FoundationFailure(ValueError):
    def __init__(self, code: str) -> None:
        if code not in FAILURE_PRECEDENCE:
            raise ValueError(f"unknown Foundation failure code: {code}")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LogEntryRef:
    log_name: str
    log_sequence: int
    receipt_hash: str


@dataclass(frozen=True, slots=True)
class LogCheckpoint:
    log_name: str
    as_of: str
    upper_log_sequence: int
    head_receipt_hash: str | None


@dataclass(frozen=True, slots=True)
class AppendReceipt:
    log_name: str
    event_id: str
    payload_source_hash: str
    ledger_sequence: int
    log_sequence: int
    previous_receipt_hash: str | None
    receipt_hash: str
    accepted_at: str

    @property
    def entry_ref(self) -> LogEntryRef:
        return LogEntryRef(self.log_name, self.log_sequence, self.receipt_hash)


@dataclass(frozen=True, slots=True)
class LogEntry:
    entry_ref: LogEntryRef
    event_id: str
    payload: bytes
    payload_source_hash: str
    ledger_sequence: int
    log_sequence: int
    previous_receipt_hash: str | None
    receipt_hash: str
    accepted_at: str


def _system_clock() -> str:
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def _fail(code: str, error: Exception | None = None) -> NoReturn:
    raise FoundationFailure(code) from error


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _require_text(value: object, name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    if not value or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


def _positive_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be nonnegative")
    return value


def _validate_log_name(value: object) -> str:
    value = _require_text(value, "log_name")
    if _LOG_NAME_RE.fullmatch(value) is None:
        raise ValueError("log_name is not canonical")
    return value


def _validate_event_id(value: object) -> str:
    return _require_text(value, "event_id")


def _validate_hash(value: object, name: str) -> str:
    value = _require_text(value, name)
    if _HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must use sha256:<64 lowercase hex>")
    return value


def _parse_timestamp(value: object) -> tuple[str, datetime]:
    value = _require_text(value, "accepted_at")
    if _TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError("accepted_at must be canonical UTC microseconds")
    try:
        parsed = datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError("accepted_at is not a UTC instant") from error
    if parsed.strftime(_TIMESTAMP_FORMAT) != value:
        raise ValueError("accepted_at is not canonical")
    return value, parsed


def _decode_payload(value: object) -> bytes:
    if type(value) is not str:
        raise ValueError("payload must be lowercase hexadecimal")
    if _PAYLOAD_RE.fullmatch(value) is None or len(value) % 2:
        raise ValueError("payload must be lowercase hexadecimal")
    return bytes.fromhex(value)


def _validate_artifact_ref(value: object) -> ArtifactRef:
    if type(value) is not ArtifactRef:
        raise TypeError("ref must be an ArtifactRef")
    return value


def _decode_artifact_source(source: bytes) -> ArtifactEnvelope:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("artifact source contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_number(value: str) -> NoReturn:
        raise ValueError(f"artifact source contains a forbidden number: {value}")

    try:
        decoded = json.loads(
            source.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("artifact source is not canonical JSON") from error
    if type(decoded) is not dict or set(decoded) != {
        "artifact_type",
        "schema_version",
        "payload",
        "content_hash",
    }:
        raise ValueError("artifact source is not an exact Envelope")
    try:
        envelope = ArtifactEnvelope(
            artifact_type=decoded["artifact_type"],
            schema_version=decoded["schema_version"],
            payload=decoded["payload"],
            content_hash=decoded["content_hash"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("artifact source contains an invalid Envelope") from error
    if canonical_bytes(envelope) != source:
        raise ValueError("artifact source is not canonical Envelope bytes")
    return envelope


def _artifact_result(source: bytes, ref: ArtifactRef) -> ArtifactReadResult:
    envelope = _decode_artifact_source(source)
    if ArtifactRef.from_envelope(envelope) != ref:
        raise ValueError("artifact source does not match ref")
    return ArtifactReadResult(
        envelope=envelope,
        artifact=envelope.payload,
        source_bytes=source,
        source_hash=_sha256(source),
    )


def _checkpoint_wire(checkpoint: LogCheckpoint) -> dict[str, object]:
    return {
        "log_name": checkpoint.log_name,
        "as_of": checkpoint.as_of,
        "upper_log_sequence": checkpoint.upper_log_sequence,
        "head_receipt_hash": checkpoint.head_receipt_hash,
    }


def _checkpoint_from_wire(value: object) -> LogCheckpoint:
    if type(value) is not dict or set(value) != {
        "log_name",
        "as_of",
        "upper_log_sequence",
        "head_receipt_hash",
    }:
        raise ValueError("checkpoint state record is malformed")
    return _validate_checkpoint(
        LogCheckpoint(
            value["log_name"],
            value["as_of"],
            value["upper_log_sequence"],
            value["head_receipt_hash"],
        )
    )


def _read_checkpoint_state(source: bytes) -> tuple[LogCheckpoint, ...]:
    if not source or not source.endswith(b"\n"):
        raise ValueError("checkpoint state is malformed")
    checkpoints: list[LogCheckpoint] = []
    previous: datetime | None = None
    for line in source[:-1].split(b"\n"):
        if not line:
            raise ValueError("checkpoint state contains an empty line")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("checkpoint state contains invalid JSON") from error
        if _canonical_json_bytes(value) != line:
            raise ValueError("checkpoint state is not canonical JSON")
        checkpoint = _checkpoint_from_wire(value)
        _, recorded = _parse_timestamp(checkpoint.as_of)
        if previous is not None and recorded < previous:
            raise ValueError("checkpoint state moves backwards")
        checkpoints.append(checkpoint)
        previous = recorded
    return tuple(checkpoints)


def _checkpoint_state_bytes(checkpoints: tuple[LogCheckpoint, ...]) -> bytes:
    return b"".join(
        _canonical_json_bytes(_checkpoint_wire(checkpoint)) + b"\n"
        for checkpoint in checkpoints
    )


def _receipt_hash(
    *,
    log_name: str,
    event_id: str,
    payload_source_hash: str,
    ledger_sequence: int,
    log_sequence: int,
    previous_receipt_hash: str | None,
    accepted_at: str,
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "log_name": log_name,
                "event_id": event_id,
                "payload_source_hash": payload_source_hash,
                "ledger_sequence": ledger_sequence,
                "log_sequence": log_sequence,
                "previous_receipt_hash": previous_receipt_hash,
                "accepted_at": accepted_at,
            }
        )
    )


def _entry_wire(entry: LogEntry) -> dict[str, Any]:
    return {
        "log_name": entry.entry_ref.log_name,
        "event_id": entry.event_id,
        "payload": entry.payload.hex(),
        "payload_source_hash": entry.payload_source_hash,
        "ledger_sequence": entry.ledger_sequence,
        "log_sequence": entry.log_sequence,
        "previous_receipt_hash": entry.previous_receipt_hash,
        "receipt_hash": entry.receipt_hash,
        "accepted_at": entry.accepted_at,
    }


def _entry_from_wire(raw: object, expected_log_name: str) -> LogEntry:
    if type(raw) is not dict:
        raise ValueError("registry record must be an object")

    required = {
        "log_name",
        "event_id",
        "payload",
        "payload_source_hash",
        "ledger_sequence",
        "log_sequence",
        "previous_receipt_hash",
        "receipt_hash",
        "accepted_at",
    }
    if set(raw) != required:
        raise ValueError("registry record fields are malformed")

    log_name = _validate_log_name(raw["log_name"])
    if log_name != expected_log_name:
        raise ValueError("registry record belongs to another log")
    event_id = _validate_event_id(raw["event_id"])
    payload = _decode_payload(raw["payload"])
    payload_source_hash = _validate_hash(raw["payload_source_hash"], "payload_source_hash")
    if _sha256(payload) != payload_source_hash:
        raise ValueError("payload_source_hash does not match payload")
    ledger_sequence = _positive_int(raw["ledger_sequence"], "ledger_sequence")
    log_sequence = _positive_int(raw["log_sequence"], "log_sequence")

    previous_receipt_hash = raw["previous_receipt_hash"]
    if previous_receipt_hash is not None:
        previous_receipt_hash = _validate_hash(
            previous_receipt_hash, "previous_receipt_hash"
        )
    receipt_hash = _validate_hash(raw["receipt_hash"], "receipt_hash")
    accepted_at, _ = _parse_timestamp(raw["accepted_at"])

    if receipt_hash != _receipt_hash(
        log_name=log_name,
        event_id=event_id,
        payload_source_hash=payload_source_hash,
        ledger_sequence=ledger_sequence,
        log_sequence=log_sequence,
        previous_receipt_hash=previous_receipt_hash,
        accepted_at=accepted_at,
    ):
        raise ValueError("receipt_hash does not match receipt fields")

    return LogEntry(
        entry_ref=LogEntryRef(log_name, log_sequence, receipt_hash),
        event_id=event_id,
        payload=payload,
        payload_source_hash=payload_source_hash,
        ledger_sequence=ledger_sequence,
        log_sequence=log_sequence,
        previous_receipt_hash=previous_receipt_hash,
        receipt_hash=receipt_hash,
        accepted_at=accepted_at,
    )


def _read_registry(path: Path, expected_log_name: str) -> tuple[LogEntry, ...]:
    try:
        source = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read registry {path}") from error

    if not source:
        raise ValueError("registry is empty")
    if not source.endswith(b"\n"):
        raise ValueError("registry is not newline terminated")

    entries: list[LogEntry] = []
    for line in source[:-1].split(b"\n"):
        if not line:
            raise ValueError("registry contains an empty line")
        try:
            raw = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("registry contains invalid JSON") from error
        if _canonical_json_bytes(raw) != line:
            raise ValueError("registry record is not canonical JSON")
        entries.append(_entry_from_wire(raw, expected_log_name))
    return tuple(entries)


def _validate_state(
    logs: dict[str, tuple[LogEntry, ...]],
) -> tuple[int, datetime | None]:
    by_ledger: dict[int, tuple[LogEntry, datetime]] = {}

    for log_name, entries in logs.items():
        _validate_log_name(log_name)
        previous_receipt_hash: str | None = None
        event_ids: set[str] = set()

        for expected_sequence, entry in enumerate(entries, start=1):
            if type(entry) is not LogEntry or type(entry.entry_ref) is not LogEntryRef:
                raise ValueError("registry entry has an invalid type")
            if entry.entry_ref.log_name != log_name:
                raise ValueError("entry ref belongs to another log")
            if entry.entry_ref.log_sequence != entry.log_sequence:
                raise ValueError("entry ref sequence does not match entry")
            if entry.entry_ref.receipt_hash != entry.receipt_hash:
                raise ValueError("entry ref hash does not match entry")
            if _validate_log_name(entry.entry_ref.log_name) != log_name:
                raise ValueError("entry log name is invalid")
            if _validate_event_id(entry.event_id) in event_ids:
                raise ValueError("event_id is duplicated in a log")
            event_ids.add(entry.event_id)
            if type(entry.payload) is not bytes:
                raise ValueError("payload is not bytes")
            _validate_hash(entry.payload_source_hash, "payload_source_hash")
            if _sha256(entry.payload) != entry.payload_source_hash:
                raise ValueError("payload_source_hash does not match payload")
            _positive_int(entry.ledger_sequence, "ledger_sequence")
            if entry.log_sequence != expected_sequence:
                raise ValueError("log_sequence is not contiguous")
            if previous_receipt_hash != entry.previous_receipt_hash:
                raise ValueError("previous_receipt_hash chain is broken")
            if entry.previous_receipt_hash is not None:
                _validate_hash(entry.previous_receipt_hash, "previous_receipt_hash")
            _validate_hash(entry.receipt_hash, "receipt_hash")
            accepted_at, accepted_time = _parse_timestamp(entry.accepted_at)
            if entry.receipt_hash != _receipt_hash(
                log_name=log_name,
                event_id=entry.event_id,
                payload_source_hash=entry.payload_source_hash,
                ledger_sequence=entry.ledger_sequence,
                log_sequence=entry.log_sequence,
                previous_receipt_hash=entry.previous_receipt_hash,
                accepted_at=accepted_at,
            ):
                raise ValueError("receipt_hash does not match receipt fields")
            if entry.ledger_sequence in by_ledger:
                raise ValueError("ledger_sequence is duplicated")

            by_ledger[entry.ledger_sequence] = (entry, accepted_time)
            previous_receipt_hash = entry.receipt_hash

    ordered = sorted(by_ledger.items())
    latest_accepted: datetime | None = None
    for expected_sequence, (ledger_sequence, (_, accepted_time)) in enumerate(
        ordered, start=1
    ):
        if ledger_sequence != expected_sequence:
            raise ValueError("ledger_sequence is not contiguous")
        if latest_accepted is not None and accepted_time < latest_accepted:
            raise ValueError("accepted_at moves backwards")
        latest_accepted = accepted_time
    return len(ordered), latest_accepted


def _receipt_from_entry(entry: LogEntry) -> AppendReceipt:
    return AppendReceipt(
        log_name=entry.entry_ref.log_name,
        event_id=entry.event_id,
        payload_source_hash=entry.payload_source_hash,
        ledger_sequence=entry.ledger_sequence,
        log_sequence=entry.log_sequence,
        previous_receipt_hash=entry.previous_receipt_hash,
        receipt_hash=entry.receipt_hash,
        accepted_at=entry.accepted_at,
    )


def _registry_bytes(entries: tuple[LogEntry, ...]) -> bytes:
    return b"".join(_canonical_json_bytes(_entry_wire(entry)) + b"\n" for entry in entries)


def _validate_entry_ref(value: object) -> LogEntryRef:
    if type(value) is not LogEntryRef:
        raise TypeError("through must be a LogEntryRef")
    _validate_log_name(value.log_name)
    _positive_int(value.log_sequence, "through.log_sequence")
    _validate_hash(value.receipt_hash, "through.receipt_hash")
    return value


def _validate_checkpoint(value: object) -> LogCheckpoint:
    if type(value) is not LogCheckpoint:
        raise TypeError("through must be a LogCheckpoint")
    _validate_log_name(value.log_name)
    _parse_timestamp(value.as_of)
    _nonnegative_int(value.upper_log_sequence, "checkpoint.upper_log_sequence")
    if value.upper_log_sequence == 0:
        if value.head_receipt_hash is not None:
            raise ValueError("empty checkpoint must not have a head hash")
    elif value.head_receipt_hash is None:
        raise ValueError("non-empty checkpoint must have a head hash")
    else:
        _validate_hash(value.head_receipt_hash, "checkpoint.head_receipt_hash")
    return value


class LocalFoundation:
    def __init__(self, root: str | Path, clock: Callable[[], str] = _system_clock) -> None:
        if not isinstance(root, (str, Path)):
            raise TypeError("root must be a str or Path")
        if type(root) is str and not root:
            raise ValueError("root must be non-empty")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._root = Path(root)
        self._clock = clock
        self._lock_path = self._root / ".foundation.write.lock"
        self._clock_path = self._root / ".foundation.clock"
        self._staging = self._root / ".staging"
        self._registries = self._root / "registries"
        self._artifacts = self._root / "artifacts" / "sha256"

    def put(self, *, envelope: ArtifactEnvelope) -> ArtifactRef:
        if type(envelope) is not ArtifactEnvelope:
            raise TypeError("envelope must be an ArtifactEnvelope")
        ref = ArtifactRef.from_envelope(envelope)
        source = canonical_bytes(envelope)

        self._ensure_layout()
        with self._locked():
            target = self._artifact_path(ref)
            self._ensure_artifact_bucket(target.parent)
            if target.exists() or target.is_symlink():
                try:
                    if target.is_symlink() or not target.is_file():
                        raise ValueError("artifact path is not a regular file")
                    existing = target.read_bytes()
                    _artifact_result(existing, ref)
                    if existing != source:
                        raise ValueError("occupied ref contains different bytes")
                except Exception as error:  # noqa: BLE001 - fail closed at CAS boundary
                    _fail("ARTIFACT_INTEGRITY", error)
                return ref

            staged: Path | None = None
            try:
                staged = self._stage(source, prefix="artifact-", suffix=".json")
                result = _artifact_result(staged.read_bytes(), ref)
                if result.source_bytes != source:
                    raise ValueError("staged artifact does not match source")
                os.replace(staged, target)
                staged = None
            except FoundationFailure:
                raise
            except Exception as error:  # noqa: BLE001 - atomic publication boundary
                _fail("ARTIFACT_PUBLICATION_FAILED", error)
            finally:
                if staged is not None:
                    with suppress(OSError):
                        staged.unlink()
        return ref

    def read(self, *, ref: ArtifactRef) -> ArtifactReadResult:
        ref = _validate_artifact_ref(ref)
        self._ensure_layout()
        target = self._artifact_path(ref)
        try:
            if target.is_symlink():
                raise ValueError("artifact path is a symlink")
            source = target.read_bytes()
            if not target.is_file():
                raise ValueError("artifact path is not a regular file")
        except FileNotFoundError as error:
            _fail("ARTIFACT_NOT_FOUND", error)
        except Exception as error:  # noqa: BLE001 - fail closed at CAS boundary
            _fail("ARTIFACT_INTEGRITY", error)
        try:
            return _artifact_result(source, ref)
        except Exception as error:  # noqa: BLE001 - fail closed on decoded source
            _fail("ARTIFACT_INTEGRITY", error)

    def append(self, log_name: str, event_id: str, payload: bytes) -> AppendReceipt:
        log_name = _validate_log_name(log_name)
        event_id = _validate_event_id(event_id)
        if type(payload) is not bytes:
            raise TypeError("payload must be bytes")

        self._ensure_layout()
        with self._locked():
            logs, ledger_sequence, latest_accepted = self._load_state()
            last_clock = self._load_clock(latest_accepted)
            prior_entries = logs.get(log_name, ())
            conflict = False
            for entry in prior_entries:
                if entry.event_id == event_id:
                    if entry.payload == payload:
                        return _receipt_from_entry(entry)
                    conflict = True
                    break

            accepted_at, accepted_time = self._clock_value()
            if last_clock is not None and accepted_time < last_clock:
                _fail("CLOCK_NOT_MONOTONIC")
            if conflict:
                _fail("LOG_CONFLICT")

            next_ledger_sequence = ledger_sequence + 1
            next_log_sequence = len(prior_entries) + 1
            previous_receipt_hash = (
                prior_entries[-1].receipt_hash if prior_entries else None
            )
            payload_source_hash = _sha256(payload)
            receipt_hash = _receipt_hash(
                log_name=log_name,
                event_id=event_id,
                payload_source_hash=payload_source_hash,
                ledger_sequence=next_ledger_sequence,
                log_sequence=next_log_sequence,
                previous_receipt_hash=previous_receipt_hash,
                accepted_at=accepted_at,
            )
            entry = LogEntry(
                entry_ref=LogEntryRef(log_name, next_log_sequence, receipt_hash),
                event_id=event_id,
                payload=payload,
                payload_source_hash=payload_source_hash,
                ledger_sequence=next_ledger_sequence,
                log_sequence=next_log_sequence,
                previous_receipt_hash=previous_receipt_hash,
                receipt_hash=receipt_hash,
                accepted_at=accepted_at,
            )

            staged: Path | None = None
            try:
                candidate = prior_entries + (entry,)
                staged = self._stage(_registry_bytes(candidate))
                if _read_registry(staged, log_name) != candidate:
                    raise ValueError("staged registry does not match candidate")
                candidate_logs = dict(logs)
                candidate_logs[log_name] = candidate
                _validate_state(candidate_logs)
                os.replace(staged, self._registry_path(log_name))
                staged = None
                # The registry durably records append time. Checkpoint state changes
                # only during checkpoint publication, avoiding a two-file append commit.
            except Exception as error:  # noqa: BLE001 - atomic publication boundary
                _fail("LOG_PUBLICATION_FAILED", error)
            finally:
                if staged is not None:
                    with suppress(OSError):
                        staged.unlink()

            return _receipt_from_entry(entry)

    def checkpoint(self, log_name: str) -> LogCheckpoint:
        log_name = _validate_log_name(log_name)

        self._ensure_layout()
        with self._locked():
            logs, _, latest_accepted = self._load_state()
            last_clock = self._load_clock(latest_accepted)
            as_of, accepted_time = self._clock_value()
            if last_clock is not None and accepted_time < last_clock:
                _fail("CLOCK_NOT_MONOTONIC")

            entries = logs.get(log_name, ())
            checkpoint = LogCheckpoint(
                log_name=log_name,
                as_of=as_of,
                upper_log_sequence=len(entries),
                head_receipt_hash=entries[-1].receipt_hash if entries else None,
            )
            self._record_clock(checkpoint, "SNAPSHOT_PUBLICATION_FAILED")
            return checkpoint

    def entries(
        self,
        log_name: str,
        through: LogCheckpoint | LogEntryRef | None = None,
    ) -> tuple[LogEntry, ...]:
        log_name = _validate_log_name(log_name)
        if through is None:
            cutoff: LogCheckpoint | LogEntryRef | None = None
        elif type(through) is LogCheckpoint:
            cutoff = _validate_checkpoint(through)
        elif type(through) is LogEntryRef:
            cutoff = _validate_entry_ref(through)
        else:
            raise TypeError("through must be a LogCheckpoint, LogEntryRef, or None")

        self._ensure_layout()
        with self._locked():
            logs, _, _ = self._load_state()
            entries = logs.get(log_name, ())
            if cutoff is None:
                return entries
            if cutoff.log_name != log_name:
                _fail("LOG_INTEGRITY")

            if type(cutoff) is LogEntryRef:
                if cutoff.log_sequence > len(entries):
                    _fail("LOG_INTEGRITY")
                if entries[cutoff.log_sequence - 1].entry_ref != cutoff:
                    _fail("LOG_INTEGRITY")
                return entries[: cutoff.log_sequence]

            if cutoff not in self._load_checkpoint_state():
                _fail("LOG_INTEGRITY")
            if cutoff.upper_log_sequence > len(entries):
                _fail("LOG_INTEGRITY")
            if (
                cutoff.upper_log_sequence
                and entries[cutoff.upper_log_sequence - 1].receipt_hash
                != cutoff.head_receipt_hash
            ):
                _fail("LOG_INTEGRITY")
            as_of = _parse_timestamp(cutoff.as_of)[1]
            for entry in entries[: cutoff.upper_log_sequence]:
                if _parse_timestamp(entry.accepted_at)[1] > as_of:
                    _fail("LOG_INTEGRITY")
            return entries[: cutoff.upper_log_sequence]

    def _ensure_layout(self) -> None:
        try:
            if self._root.is_symlink():
                raise OSError("root must not be a symlink")
            self._root.mkdir(parents=True, exist_ok=True)
            for directory in (self._registries, self._staging, self._artifacts):
                if directory.is_symlink():
                    raise OSError(f"{directory} must not be a symlink")
                directory.mkdir(parents=True, exist_ok=True)
                if not directory.is_dir():
                    raise OSError(f"{directory} is not a directory")
        except OSError as error:
            _fail("UNSUPPORTED_FILESYSTEM", error)

    def _artifact_path(self, ref: ArtifactRef) -> Path:
        digest = ref.content_hash.removeprefix("sha256:")
        return self._artifacts / digest[:2] / digest

    def _ensure_artifact_bucket(self, bucket: Path) -> None:
        try:
            if bucket.is_symlink():
                raise OSError("artifact bucket must not be a symlink")
            bucket.mkdir(exist_ok=True)
            if not bucket.is_dir():
                raise OSError("artifact bucket is not a directory")
        except OSError as error:
            _fail("UNSUPPORTED_FILESYSTEM", error)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            handle = self._lock_path.open("x", encoding="ascii")
        except FileExistsError as error:
            _fail("WRITE_LOCK_UNAVAILABLE", error)
        except OSError as error:
            _fail("UNSUPPORTED_FILESYSTEM", error)

        try:
            with handle:
                # ponytail: one global lock is the v1 contract; split only for measured contention.
                yield
        finally:
            with suppress(OSError):
                self._lock_path.unlink()

    def _load_state(
        self,
    ) -> tuple[dict[str, tuple[LogEntry, ...]], int, datetime | None]:
        try:
            logs: dict[str, tuple[LogEntry, ...]] = {}
            # ponytail: v1 verifies every prefix on every operation; add an index only
            # when measured registry volume makes the full scan too slow.
            for path in sorted(self._registries.iterdir(), key=lambda item: item.name):
                if path.is_symlink() or not path.is_file():
                    raise ValueError("registry directory contains a non-file")
                if not path.name.endswith(".jsonl"):
                    raise ValueError("registry directory contains a non-log file")
                log_name = path.name.removesuffix(".jsonl")
                _validate_log_name(log_name)
                logs[log_name] = _read_registry(path, log_name)
            ledger_sequence, latest_accepted = _validate_state(logs)
        except Exception as error:  # noqa: BLE001 - reject any malformed prefix
            _fail("LOG_INTEGRITY", error)
        return logs, ledger_sequence, latest_accepted

    def _load_clock(self, latest_accepted: datetime | None) -> datetime | None:
        checkpoints = self._load_checkpoint_state()
        if not checkpoints:
            return latest_accepted
        recorded = _parse_timestamp(checkpoints[-1].as_of)[1]
        return max(recorded, latest_accepted) if latest_accepted is not None else recorded

    def _load_checkpoint_state(self) -> tuple[LogCheckpoint, ...]:
        try:
            if self._clock_path.is_symlink():
                raise ValueError("clock state is a symlink")
            if not self._clock_path.exists():
                return ()
            if not self._clock_path.is_file():
                raise ValueError("clock state is not a regular file")
            return _read_checkpoint_state(self._clock_path.read_bytes())
        except (OSError, UnicodeDecodeError, ValueError) as error:
            _fail("LOG_INTEGRITY", error)

    def _record_clock(self, checkpoint: LogCheckpoint, failure_code: str) -> None:
        staged: Path | None = None
        try:
            source = _checkpoint_state_bytes(
                self._load_checkpoint_state() + (checkpoint,)
            )
            staged = self._stage(source, prefix="clock-", suffix=".state")
            if staged.read_bytes() != source:
                raise ValueError("staged clock state does not match")
            os.replace(staged, self._clock_path)
            staged = None
        except Exception as error:  # noqa: BLE001 - atomic checkpoint boundary
            _fail(failure_code, error)
        finally:
            if staged is not None:
                with suppress(OSError):
                    staged.unlink()

    def _clock_value(self) -> tuple[str, datetime]:
        try:
            return _parse_timestamp(self._clock())
        except Exception as error:  # noqa: BLE001 - injected clock is untrusted
            _fail("CLOCK_NOT_MONOTONIC", error)

    def _registry_path(self, log_name: str) -> Path:
        return self._registries / f"{log_name}.jsonl"

    def _stage(
        self,
        source: bytes,
        *,
        prefix: str = "registry-",
        suffix: str = ".jsonl",
    ) -> Path:
        # ponytail: whole-file replacement is the minimal atomic local design;
        # switch to an append journal only when measured volume requires it.
        descriptor, name = tempfile.mkstemp(
            prefix=prefix, suffix=suffix, dir=self._staging
        )
        path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(source)
        except BaseException:
            with suppress(OSError):
                path.unlink()
            raise
        return path
