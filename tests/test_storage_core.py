from __future__ import annotations

import ast
import hashlib
from collections.abc import Callable
from inspect import Parameter, signature
from pathlib import Path
from typing import get_type_hints

import pytest
from crypto_quant_backtest import ArtifactEnvelopeReader
from crypto_quant_domain import (
    ArtifactEnvelope,
    ArtifactIntegrityError,
    ArtifactNotFoundError,
    ArtifactReadResult,
    ArtifactRef,
    canonical_bytes,
)
from crypto_quant_foundation import FoundationFailure, LocalFoundation, storage


def _failure(code: str, call: Callable[[], object]) -> FoundationFailure:
    with pytest.raises(FoundationFailure) as raised:
        call()
    assert raised.value.code == code
    return raised.value


def _envelope(artifact_type: str = "strategy_candidate") -> ArtifactEnvelope:
    return ArtifactEnvelope.create(
        artifact_type,
        1,
        {"candidate_id": "candidate-1", "score": -1},
    )


def _path(root: Path, ref: ArtifactRef) -> Path:
    digest = ref.content_hash.removeprefix("sha256:")
    return root / "artifacts" / "sha256" / digest[:2] / digest


def test_put_read_and_replay_preserve_exact_envelope_bytes(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path)
    envelope = _envelope()
    source = canonical_bytes(envelope)

    ref = store.put(envelope=envelope)
    result = store.read(ref=ref)

    assert ref == ArtifactRef.from_envelope(envelope)
    assert store.put(envelope=envelope) == ref
    assert type(result) is ArtifactReadResult
    assert result.envelope == envelope
    assert result.artifact == envelope.payload
    assert result.source_bytes == source
    assert result.source_hash == f"sha256:{hashlib.sha256(source).hexdigest()}"
    assert _path(tmp_path, ref).read_bytes() == source


def test_bad_artifact_arguments_do_not_touch_the_filesystem(tmp_path: Path) -> None:
    root = tmp_path / "not-created"
    store = LocalFoundation(root)

    with pytest.raises(TypeError, match="ArtifactEnvelope"):
        store.put(envelope={})  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ArtifactRef"):
        store.read(ref={})  # type: ignore[arg-type]

    assert not root.exists()


def test_missing_artifact_is_distinct_from_integrity_failure(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path)
    ref = ArtifactRef("strategy_candidate", 1, "sha256:" + "0" * 64)

    assert isinstance(
        _failure("ARTIFACT_NOT_FOUND", lambda: store.read(ref=ref)),
        ArtifactNotFoundError,
    )


def test_tampered_occupied_ref_fails_closed_for_read_and_put(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path)
    envelope = _envelope()
    ref = store.put(envelope=envelope)
    target = _path(tmp_path, ref)
    target.write_bytes(target.read_bytes() + b"\n")

    assert isinstance(
        _failure("ARTIFACT_INTEGRITY", lambda: store.read(ref=ref)),
        ArtifactIntegrityError,
    )
    assert isinstance(
        _failure("ARTIFACT_INTEGRITY", lambda: store.put(envelope=envelope)),
        ArtifactIntegrityError,
    )


def test_ref_path_type_and_version_disagreement_fails_closed(tmp_path: Path) -> None:
    store = LocalFoundation(tmp_path)
    requested = ArtifactRef.from_envelope(_envelope("validation_report"))
    wrong = ArtifactEnvelope.create("strategy_candidate", 2, {"value": "wrong"})
    target = _path(tmp_path, requested)
    target.parent.mkdir(parents=True)
    target.write_bytes(canonical_bytes(wrong))

    _failure("ARTIFACT_INTEGRITY", lambda: store.read(ref=requested))


def test_failed_staging_readback_leaves_no_published_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path)
    envelope = _envelope()
    ref = ArtifactRef.from_envelope(envelope)
    original = store._stage

    def corrupt_stage(source: bytes, **kwargs: str) -> Path:
        path = original(source, **kwargs)
        path.write_bytes(b"{}")
        return path

    monkeypatch.setattr(store, "_stage", corrupt_stage)
    _failure("ARTIFACT_PUBLICATION_FAILED", lambda: store.put(envelope=envelope))

    assert not _path(tmp_path, ref).exists()
    assert not list((tmp_path / ".staging").iterdir())


def test_failed_finalize_leaves_no_published_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFoundation(tmp_path)
    envelope = _envelope()
    ref = ArtifactRef.from_envelope(envelope)

    def fail_replace(source: object, target: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    _failure("ARTIFACT_PUBLICATION_FAILED", lambda: store.put(envelope=envelope))

    assert not _path(tmp_path, ref).exists()
    assert not list((tmp_path / ".staging").iterdir())


def test_owner_log_publication_preserves_envelope_source_and_hash(
    tmp_path: Path,
) -> None:
    store = LocalFoundation(tmp_path, clock=lambda: "2030-01-02T03:04:05.000000Z")
    envelope = _envelope()
    source = canonical_bytes(envelope)
    ref = store.put(envelope=envelope)
    event_id = "artifact-publication-test"

    receipt = store.append("research.artifacts.v1", event_id, source)
    entry = store.entries("research.artifacts.v1", receipt.entry_ref)[0]

    assert store.read(ref=ref).source_bytes == entry.payload == source
    assert entry.payload_source_hash == f"sha256:{hashlib.sha256(source).hexdigest()}"
    _failure(
        "LOG_CONFLICT",
        lambda: store.append("research.artifacts.v1", event_id, b"different"),
    )


def test_read_matches_the_accepted_backtest_structural_reader_signature() -> None:
    protocol = tuple(signature(ArtifactEnvelopeReader.read).parameters.values())
    implementation = tuple(signature(LocalFoundation.read).parameters.values())
    assert tuple((item.name, item.kind) for item in implementation) == (
        ("self", Parameter.POSITIONAL_OR_KEYWORD),
        ("ref", Parameter.KEYWORD_ONLY),
    )
    assert tuple((item.name, item.kind) for item in protocol) == (
        ("self", Parameter.POSITIONAL_OR_KEYWORD),
        ("ref", Parameter.KEYWORD_ONLY),
    )
    hints = get_type_hints(LocalFoundation.read)
    protocol_hints = get_type_hints(ArtifactEnvelopeReader.read)
    assert hints == protocol_hints == {
        "ref": ArtifactRef,
        "return": ArtifactReadResult,
    }


def test_foundation_import_boundary_stays_generic() -> None:
    source = Path(storage.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    domain_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "crypto_quant_domain"
    ]

    assert len(domain_imports) == 1
    assert {alias.name for alias in domain_imports[0].names} == {
        "ArtifactEnvelope",
        "ArtifactIntegrityError",
        "ArtifactNotFoundError",
        "ArtifactReadResult",
        "ArtifactRef",
        "canonical_bytes",
    }
    assert "crypto_quant_domain." not in source
    assert "crypto_quant_backtest" not in source
    for token in ("research", "validation", "promotion", "backtest"):
        assert token not in source.lower()
