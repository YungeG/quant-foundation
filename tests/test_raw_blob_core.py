from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

import pytest
from crypto_quant_domain import ArtifactEnvelope, ArtifactRef, RawBlobRef
from crypto_quant_foundation import FoundationFailure, LocalFoundation, storage
from crypto_quant_foundation import RawBlobRef as FoundationRawBlobRef


def _failure(code: str, call: Callable[[], object]) -> FoundationFailure:
    with pytest.raises(FoundationFailure) as raised:
        call()
    assert raised.value.code == code
    return raised.value


def _raw_path(root: Path, ref: RawBlobRef) -> Path:
    digest = ref.content_hash.removeprefix("sha256:")
    return root / "raw-blobs" / "sha256" / digest[:2] / digest


def test_raw_blob_ref_is_exact_and_canonically_reconstructable() -> None:
    ref = RawBlobRef.from_bytes(b"\x00raw\xff")

    assert FoundationRawBlobRef is RawBlobRef
    assert ref == RawBlobRef(
        "sha256:6af4f5e0c195b1ce5ee91b52060e6628cea782c3be2a5d167b0972439aa49495",
        5,
    )
    assert RawBlobRef.from_canonical_dict(ref.to_canonical_dict()) == ref
    with pytest.raises(ValueError, match="exactly"):
        RawBlobRef.from_canonical_dict({**ref.to_canonical_dict(), "extra": 1})
    with pytest.raises(TypeError, match="integer"):
        RawBlobRef(ref.content_hash, True)


def test_raw_blob_store_is_idempotent_isolated_and_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path)
    blob = b"\x00raw\xff"
    ref = RawBlobRef.from_bytes(blob)

    def no_network(*args: object, **kwargs: object) -> object:
        raise AssertionError("raw blob storage must not use the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    assert store.put_raw_blob(blob=blob) == ref
    assert store.put_raw_blob(blob=blob) == ref
    assert store.read_raw_blob(ref=ref) == blob
    assert store.raw_blob_path(ref=ref) == _raw_path(tmp_path, ref)
    assert _raw_path(tmp_path, ref).read_bytes() == blob

    artifact = ArtifactEnvelope.create("strategy_candidate", 1, {"raw": "blob"})
    artifact_ref = store.put(envelope=artifact)
    assert _raw_path(tmp_path, ref).is_file()
    artifact_path = (
        tmp_path
        / "artifacts"
        / "sha256"
        / ref.content_hash[7:9]
        / ref.content_hash[7:]
    )
    assert not artifact_path.exists()
    assert store.read(ref=artifact_ref).envelope == artifact
    assert isinstance(
        _failure(
            "ARTIFACT_NOT_FOUND",
            lambda: store.read(
                ref=ArtifactRef("strategy_candidate", 1, ref.content_hash)
            ),
        ),
        FoundationFailure,
    )


def test_raw_blob_reads_reject_missing_tampered_and_unsafe_paths(
    tmp_path: Path,
) -> None:
    store = LocalFoundation(tmp_path)
    blob = b"raw bytes"
    ref = store.put_raw_blob(blob=blob)
    target = _raw_path(tmp_path, ref)

    tampered = b"X" * len(blob)
    target.write_bytes(tampered)
    _failure("RAW_BLOB_INTEGRITY", lambda: store.read_raw_blob(ref=ref))
    _failure("RAW_BLOB_INTEGRITY", lambda: store.raw_blob_path(ref=ref))

    target.write_bytes(blob + b"!")
    _failure("RAW_BLOB_INTEGRITY", lambda: store.read_raw_blob(ref=ref))

    target.unlink()
    _failure("RAW_BLOB_NOT_FOUND", lambda: store.read_raw_blob(ref=ref))

    target.mkdir()
    _failure("RAW_BLOB_INTEGRITY", lambda: store.raw_blob_path(ref=ref))
    target.rmdir()
    matching = tmp_path / "matching-raw-blob"
    matching.write_bytes(blob)
    target.symlink_to(matching)
    _failure("RAW_BLOB_INTEGRITY", lambda: store.read_raw_blob(ref=ref))
    _failure("RAW_BLOB_INTEGRITY", lambda: store.raw_blob_path(ref=ref))


def test_raw_blob_reads_fail_closed_when_no_follow_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path)
    blob = b"raw bytes"
    ref = RawBlobRef.from_bytes(blob)
    target = _raw_path(tmp_path, ref)
    target.parent.mkdir(parents=True)
    target.write_bytes(blob)

    def opened_unexpectedly(*args: object, **kwargs: object) -> int:
        raise AssertionError("raw blob must not open without O_NOFOLLOW")

    monkeypatch.delattr(storage.os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(storage.os, "open", opened_unexpectedly)

    _failure(
        "RAW_BLOB_CAPABILITY_UNAVAILABLE", lambda: store.read_raw_blob(ref=ref)
    )
    _failure(
        "RAW_BLOB_CAPABILITY_UNAVAILABLE", lambda: store.raw_blob_path(ref=ref)
    )


def test_raw_blob_put_rejects_final_collision_and_unmanaged_state(
    tmp_path: Path,
) -> None:
    store = LocalFoundation(tmp_path)
    ref = RawBlobRef.from_bytes(b"expected")
    target = _raw_path(tmp_path, ref)
    target.parent.mkdir(parents=True)

    target.write_bytes(b"different")
    _failure("RAW_BLOB_FINAL_COLLISION", lambda: store.put_raw_blob(blob=b"expected"))

    target.unlink()
    target.mkdir()
    _failure("RAW_BLOB_UNMANAGED_STATE", lambda: store.put_raw_blob(blob=b"expected"))


def test_raw_blob_put_detects_an_unmanaged_final_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path)

    def corrupt_final(
        source: object, target: object, *, follow_symlinks: bool
    ) -> None:
        Path(target).write_bytes(b"unmanaged")

    monkeypatch.setattr(storage.os, "link", corrupt_final)
    _failure("RAW_BLOB_UNMANAGED_STATE", lambda: store.put_raw_blob(blob=b"expected"))


def test_raw_blob_arguments_do_not_touch_the_filesystem(tmp_path: Path) -> None:
    root = tmp_path / "not-created"
    store = LocalFoundation(root)

    with pytest.raises(TypeError, match="bytes"):
        store.put_raw_blob(blob=bytearray(b"raw"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="RawBlobRef"):
        store.read_raw_blob(ref={})  # type: ignore[arg-type]

    assert not root.exists()
