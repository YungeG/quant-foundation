from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from crypto_quant_foundation import (
    FoundationFailure,
    LocalFoundation,
    LogCheckpoint,
    LogEntryRef,
    storage,
)

ZERO_HASH = "sha256:" + "0" * 64
EARLIER_TIME = "2030-01-02T03:04:04.000000Z"
FIRST_TIME = "2030-01-02T03:04:05.000000Z"
SECOND_TIME = "2030-01-02T03:04:06.000000Z"
THIRD_TIME = "2030-01-02T03:04:07.000000Z"


def _failure(code: str, call: Callable[[], object]) -> None:
    with pytest.raises(FoundationFailure) as raised:
        call()
    assert raised.value.code == code


def _records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_records(path: Path, records: list[dict[str, object]]) -> None:
    path.write_bytes(
        b"".join(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
            for record in records
        )
    )


def _receipt_hash(record: dict[str, object]) -> str:
    fields = (
        "log_name",
        "event_id",
        "payload_source_hash",
        "ledger_sequence",
        "log_sequence",
        "previous_receipt_hash",
        "accepted_at",
    )
    source = json.dumps(
        {field: record[field] for field in fields},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(source).hexdigest()}"


def test_append_preserves_exact_bytes_and_replays_the_original_receipt(
    tmp_path: Path,
) -> None:
    calls = 0

    def clock() -> str:
        nonlocal calls
        calls += 1
        return FIRST_TIME

    store = LocalFoundation(tmp_path, clock=clock)
    payload = b"\x00exact\xff\nbytes"
    receipt = store.append("events.v1", "event-1", payload)

    assert store.append("events.v1", "event-1", payload) == receipt
    assert calls == 1
    assert receipt.payload_source_hash == (
        "sha256:" + hashlib.sha256(payload).hexdigest()
    )
    assert receipt.entry_ref == LogEntryRef(
        "events.v1", receipt.log_sequence, receipt.receipt_hash
    )
    assert (tmp_path / ".staging").is_dir()
    assert (tmp_path / "artifacts/sha256").is_dir()

    registry = tmp_path / "registries/events.v1.jsonl"
    records = _records(registry)
    assert len(records) == 1
    assert records[0]["payload"] == payload.hex()
    assert records[0]["payload_source_hash"] == receipt.payload_source_hash
    assert records[0]["receipt_hash"] == _receipt_hash(records[0])
    assert store.entries("events.v1")[0].payload == payload

    _failure(
        "LOG_CONFLICT",
        lambda: store.append("events.v1", "event-1", b"different"),
    )


def test_sequences_are_global_per_log_and_order_equal_times(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    first = store.append("alpha.v1", "one", b"a")
    second = store.append("beta.v1", "two", b"b")
    third = store.append("alpha.v1", "three", b"c")

    assert [receipt.ledger_sequence for receipt in (first, second, third)] == [1, 2, 3]
    assert [receipt.log_sequence for receipt in (first, second, third)] == [1, 1, 2]
    assert [receipt.accepted_at for receipt in (first, second, third)] == [
        FIRST_TIME,
        FIRST_TIME,
        FIRST_TIME,
    ]
    alpha = store.entries("alpha.v1")
    assert [entry.ledger_sequence for entry in alpha] == [1, 3]
    assert alpha[1].previous_receipt_hash == alpha[0].receipt_hash


def test_backward_clock_fails_closed_without_a_new_entry(tmp_path: Path) -> None:
    values = iter((SECOND_TIME, SECOND_TIME, FIRST_TIME))
    store = LocalFoundation(tmp_path, clock=lambda: next(values))
    first = store.append("events.v1", "one", b"one")
    second = store.append("events.v1", "two", b"two")

    _failure(
        "CLOCK_NOT_MONOTONIC",
        lambda: store.append("events.v1", "three", b"three"),
    )
    assert [entry.entry_ref for entry in store.entries("events.v1")] == [
        first.entry_ref,
        second.entry_ref,
    ]


def test_checkpoint_clock_is_monotonic_across_store_instances(tmp_path: Path) -> None:
    values = iter((FIRST_TIME, SECOND_TIME))
    store = LocalFoundation(tmp_path, clock=lambda: next(values))
    first = store.append("events.v1", "one", b"one")
    checkpoint = store.checkpoint("events.v1")

    backward = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    _failure(
        "CLOCK_NOT_MONOTONIC",
        lambda: backward.append("events.v1", "two", b"two"),
    )
    _failure(
        "CLOCK_NOT_MONOTONIC",
        lambda: backward.checkpoint("events.v1"),
    )
    assert checkpoint.as_of == SECOND_TIME
    assert [entry.entry_ref for entry in store.entries("events.v1")] == [
        first.entry_ref
    ]


def test_append_uses_the_registry_as_its_atomic_clock_record(tmp_path: Path) -> None:
    values = iter((FIRST_TIME, SECOND_TIME, THIRD_TIME))
    store = LocalFoundation(tmp_path, clock=lambda: next(values))
    store.append("events.v1", "one", b"one")
    checkpoint = store.checkpoint("events.v1")
    second = store.append("events.v1", "two", b"two")

    assert checkpoint.as_of == SECOND_TIME
    assert second.accepted_at == THIRD_TIME
    assert json.loads((tmp_path / ".foundation.clock").read_text(encoding="ascii")) == {
        "as_of": SECOND_TIME,
        "head_receipt_hash": checkpoint.head_receipt_hash,
        "log_name": "events.v1",
        "upper_log_sequence": 1,
    }
    assert [entry.event_id for entry in store.entries("events.v1")] == ["one", "two"]


def test_checkpoints_and_entry_refs_reconstruct_immutable_prefixes(
    tmp_path: Path,
) -> None:
    values = iter((FIRST_TIME, SECOND_TIME, SECOND_TIME))
    store = LocalFoundation(tmp_path, clock=lambda: next(values))
    first = store.append("events.v1", "one", b"one")
    checkpoint = store.checkpoint("events.v1")
    second = store.append("events.v1", "two", b"two")

    assert checkpoint == LogCheckpoint(
        "events.v1", SECOND_TIME, 1, first.receipt_hash
    )
    assert [entry.event_id for entry in store.entries("events.v1", checkpoint)] == [
        "one"
    ]
    assert [entry.event_id for entry in store.entries("events.v1", first.entry_ref)] == [
        "one"
    ]
    assert [entry.event_id for entry in store.entries("events.v1")] == ["one", "two"]
    assert second.accepted_at == checkpoint.as_of

    empty = LocalFoundation(tmp_path / "empty", clock=lambda: FIRST_TIME).checkpoint(
        "events.v1"
    )
    assert empty == LogCheckpoint("events.v1", FIRST_TIME, 0, None)


def test_wrong_or_future_cutoffs_fail_closed(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    first = store.append("events.v1", "one", b"one")
    store.append("events.v1", "two", b"two")

    _failure(
        "LOG_INTEGRITY",
        lambda: store.entries("events.v1", LogEntryRef("other.v1", 1, first.receipt_hash)),
    )
    _failure(
        "LOG_INTEGRITY",
        lambda: store.entries("events.v1", LogEntryRef("events.v1", 3, ZERO_HASH)),
    )
    _failure(
        "LOG_INTEGRITY",
        lambda: store.entries(
            "events.v1", LogCheckpoint("events.v1", SECOND_TIME, 1, ZERO_HASH)
        ),
    )
    _failure(
        "LOG_INTEGRITY",
        lambda: store.entries(
            "events.v1", LogCheckpoint("events.v1", EARLIER_TIME, 1, first.receipt_hash)
        ),
    )


def test_entries_rejects_a_checkpoint_the_store_did_not_issue(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    store.append("events.v1", "one", b"one")

    _failure(
        "LOG_INTEGRITY",
        lambda: store.entries(
            "events.v1", LogCheckpoint("events.v1", FIRST_TIME, 0, None)
        ),
    )

    checkpoint = store.checkpoint("events.v1")
    reopened = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    assert [entry.event_id for entry in reopened.entries("events.v1", checkpoint)] == [
        "one"
    ]


def _corrupt_json(path: Path) -> None:
    path.write_bytes(b"{\n")


def _corrupt_source_hash(path: Path) -> None:
    records = _records(path)
    records[0]["payload_source_hash"] = ZERO_HASH
    records[0]["receipt_hash"] = _receipt_hash(records[0])
    _write_records(path, records)


def _corrupt_chain(path: Path) -> None:
    records = _records(path)
    records[1]["previous_receipt_hash"] = ZERO_HASH
    records[1]["receipt_hash"] = _receipt_hash(records[1])
    _write_records(path, records)


def _corrupt_time(path: Path) -> None:
    records = _records(path)
    records[0]["accepted_at"] = "2030-01-02T03:04:05Z"
    records[0]["receipt_hash"] = _receipt_hash(records[0])
    _write_records(path, records)


def _truncate(path: Path) -> None:
    path.write_bytes(path.read_bytes()[:-1])


def _empty(path: Path) -> None:
    path.write_bytes(b"")


@pytest.mark.parametrize(
    "mutate",
    (
        _corrupt_json,
        _corrupt_source_hash,
        _corrupt_chain,
        _corrupt_time,
        _truncate,
        _empty,
    ),
    ids=("json", "source-hash", "chain", "time", "truncation", "empty"),
)
def test_tampered_or_truncated_registries_fail_closed(
    tmp_path: Path, mutate: Callable[[Path], None]
) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    store.append("events.v1", "one", b"one")
    store.append("events.v1", "two", b"two")
    mutate(tmp_path / "registries/events.v1.jsonl")

    _failure("LOG_INTEGRITY", lambda: store.entries("events.v1"))


def test_malformed_persisted_clock_fails_closed(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    store.append("events.v1", "one", b"one")
    (tmp_path / ".foundation.clock").write_text("not-a-clock\n", encoding="ascii")

    _failure(
        "LOG_INTEGRITY",
        lambda: store.append("events.v1", "two", b"two"),
    )
    _failure("LOG_INTEGRITY", lambda: store.checkpoint("events.v1"))


def test_no_partial_prefix_is_returned_when_a_later_record_is_corrupt(
    tmp_path: Path,
) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    first = store.append("events.v1", "one", b"one")
    store.append("events.v1", "two", b"two")
    path = tmp_path / "registries/events.v1.jsonl"
    first_line = path.read_bytes().splitlines()[0]
    path.write_bytes(first_line + b"\n{\n")

    _failure("LOG_INTEGRITY", lambda: store.entries("events.v1", first.entry_ref))


def test_failed_finalization_has_no_published_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)
    replace = storage.os.replace

    def fail_registry_replace(source: object, target: object) -> None:
        if Path(target).suffix == ".jsonl":
            raise OSError("replace failed")
        replace(source, target)

    monkeypatch.setattr(storage.os, "replace", fail_registry_replace)
    _failure("LOG_PUBLICATION_FAILED", lambda: store.append("events.v1", "one", b"one"))

    assert store.entries("events.v1") == ()
    assert not (tmp_path / ".foundation.clock").exists()
    assert not list((tmp_path / ".staging").iterdir())


def test_failed_checkpoint_state_has_no_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)

    def fail_replace(source: object, target: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    _failure(
        "SNAPSHOT_PUBLICATION_FAILED",
        lambda: store.checkpoint("events.v1"),
    )
    assert not (tmp_path / ".foundation.clock").exists()
    assert not list((tmp_path / ".staging").iterdir())


def test_non_directory_root_is_an_unsupported_filesystem(tmp_path: Path) -> None:
    root = tmp_path / "root-file"
    root.write_bytes(b"not a directory")
    store = LocalFoundation(root, clock=lambda: FIRST_TIME)

    _failure("UNSUPPORTED_FILESYSTEM", lambda: store.checkpoint("events.v1"))


def test_preexisting_lock_is_not_deleted(tmp_path: Path) -> None:
    lock = tmp_path / ".foundation.write.lock"
    tmp_path.mkdir(exist_ok=True)
    lock.write_text("held", encoding="ascii")
    store = LocalFoundation(tmp_path, clock=lambda: FIRST_TIME)

    _failure("WRITE_LOCK_UNAVAILABLE", lambda: store.append("events.v1", "one", b"one"))
    assert lock.read_text(encoding="ascii") == "held"


def test_bad_public_input_does_not_touch_the_filesystem(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        LocalFoundation("")

    root = tmp_path / "not-created"
    store = LocalFoundation(root, clock=lambda: FIRST_TIME)
    with pytest.raises(TypeError):
        store.append("events.v1", "one", "not-bytes")  # type: ignore[arg-type]
    assert not root.exists()

    invalid_clock = LocalFoundation(tmp_path / "invalid-clock", clock=lambda: "bad")
    _failure(
        "CLOCK_NOT_MONOTONIC",
        lambda: invalid_clock.checkpoint("events.v1"),
    )


def test_storage_imports_only_the_domain_public_root() -> None:
    source = Path(storage.__file__).read_text(encoding="utf-8")
    assert "from crypto_quant_domain import" in source
    assert "crypto_quant_domain." not in source
    assert "crypto_quant_backtest" not in source


def test_storage_vocabulary_is_foundation_generic() -> None:
    source = Path(storage.__file__).read_text(encoding="utf-8")
    forbidden = ("research", "validation", "promotion", "backtest")
    for token in forbidden:
        assert token not in source.lower()
