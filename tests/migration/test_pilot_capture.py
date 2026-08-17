from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_PATH = ROOT / "fixtures/migration/pilot-v1/baseline.receipt.json"
MANIFEST_PATH = ROOT / "fixtures/migration/pilot-v1/baseline.manifest.json"
SOURCE_DIR = ROOT / "fixtures/migration/pilot-v1/source"
INPUT_DIR = ROOT / "fixtures/migration/pilot-v1/input"
OUTPUT_DIR = ROOT / "fixtures/migration/pilot-v1/output"
REQUIRED_OUTPUT = {
    "backtest.json",
    "hummingbot-controller.yml",
    "shadow-readiness.json",
}
REQUIRED_PACKAGES = {
    "PyYAML": "6.0.3",
    "numpy": "2.5.2",
    "pandas": "3.0.5",
}
HISTORICAL_CLASSIFICATION = "static_historical_evidence"
HERMETIC_REPLAY = "unavailable_not_claimed_without_separately_recorded_hermetic_environment"


def _sha256(path: Path) -> str:
    try:
        source = path.read_bytes()
    except OSError as error:
        raise AssertionError(f"cannot read fixture {path}: {error}") from error
    return f"sha256:{hashlib.sha256(source).hexdigest()}"


def _read_json(path: Path) -> dict:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError(f"invalid fixture {path}: {error}") from error
    assert isinstance(decoded, dict)
    return decoded


def _read_receipt() -> dict:
    return _read_json(RECEIPT_PATH)


def test_p00_legacy_historical_hashes_and_paths() -> None:
    receipt = _read_receipt()
    manifest = _read_json(MANIFEST_PATH)

    assert receipt["receipt_id"] == "p00-legacy-pilot-v1"
    assert receipt["schema_version"] == 1
    assert receipt["work_package"] == "P00-LEG-01"
    assert receipt["status"] == HISTORICAL_CLASSIFICATION
    assert receipt["classification"] == HISTORICAL_CLASSIFICATION
    assert manifest["status"] == HISTORICAL_CLASSIFICATION

    assert receipt["command"].startswith("PYTHONPATH=src:../crypto-quant-core/src")
    assert receipt["command"].endswith("tests/fixtures/migration/pilot-v1/output")

    for rel, expected in receipt["source_hashes"].items():
        assert _sha256(SOURCE_DIR / rel) == expected
    for rel, expected in receipt["input_hashes"].items():
        assert _sha256(INPUT_DIR / rel) == expected
    for name, expected in receipt["output_hashes"].items():
        assert _sha256(OUTPUT_DIR / name) == expected

    assert manifest["artifact_scope"]["source"] == receipt["source_hashes"]
    assert manifest["artifact_scope"]["input"] == receipt["input_hashes"]
    assert manifest["evidence_files"] == receipt["output_hashes"]
    assert set(receipt["output_hashes"]) == REQUIRED_OUTPUT


def test_p00_legacy_metadata_is_historical_observation() -> None:
    receipt = _read_receipt()
    manifest = _read_json(MANIFEST_PATH)

    assert receipt["hermetic_replay"] == HERMETIC_REPLAY
    assert manifest["historical_capture"]["hermetic_replay"] == HERMETIC_REPLAY
    assert receipt["observations"].endswith("historical observations only.")
    assert receipt["interpreter"]["path"].endswith("python")
    assert receipt["interpreter"]["version"] == "3.13.5"
    assert receipt["run_footprint"]["working_directory"] == "crypto-quant-platform"
    for package, expected in REQUIRED_PACKAGES.items():
        assert receipt["package_versions"][package] == expected


def test_p00_legacy_output_is_static_historical_evidence() -> None:
    receipt = _read_receipt()
    for filename in REQUIRED_OUTPUT:
        path = OUTPUT_DIR / filename
        assert path.exists(), f"missing {filename}"
        assert _sha256(path) == receipt["output_hashes"][filename]

    assert receipt["required_non_authority_labels"]["backtest.json"] == "legacy_backtest_json"
    assert receipt["required_non_authority_labels"]["shadow-readiness.json"] == (
        "legacy_shadow_readiness"
    )
